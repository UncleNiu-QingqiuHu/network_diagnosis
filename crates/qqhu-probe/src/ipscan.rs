//! IP 扫描：并发 ICMP 探活，可选 TCP 端口兜底。
//!
//! 关键取舍：
//!
//! 1. **共享一个 ICMP Client**。`surge-ping` 的回包按 `(host, ident, seq)` 路由，
//!    因此多个 Pinger 可安全共用同一 socket。逐个目标新建 Client 会为每个地址
//!    创建一次 raw socket，扫 /24 就是 254 次创建，在 Windows 上既慢又容易触限。
//! 2. **TCP 兜底**。不少企业网络出口禁 ICMP，ICMP 全丢不代表主机不在线。
//!    配置兜底端口后，ICMP 无响应的地址会再试一次 TCP 建连，命中即判存活。
//! 3. **滑动并发窗口**。不是一次性 spawn 全部任务，完成一个补一个，
//!    避免 /20 规模下瞬间堆积数千个 future。

use crate::{ProbeError};
use qqhu_core::{IpScanHost, IpScanParams, IpScanReport, ProbeMethod, ScanScope};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

#[derive(Debug, Clone)]
pub struct IpScanOptions {
    /// 每个地址的 ICMP 发包数（>1 可降低丢包误判）
    pub count: u32,
    /// 单包等待超时
    pub timeout: Duration,
    /// 相邻两包间隔
    pub interval: Duration,
    /// 并发探测的地址数上限
    pub concurrency: usize,
    /// ICMP 无响应时尝试的 TCP 端口（任一建连成功即判存活）
    pub tcp_fallback_ports: Vec<u16>,
    /// TCP 兜底的单次建连超时
    pub tcp_timeout: Duration,
}

impl Default for IpScanOptions {
    fn default() -> Self {
        Self {
            count: 1,
            timeout: Duration::from_millis(800),
            interval: Duration::from_millis(100),
            concurrency: 64,
            tcp_fallback_ports: Vec::new(),
            tcp_timeout: Duration::from_millis(800),
        }
    }
}

/// 扫描进度快照，用于向前端推送。
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub done: usize,
    pub total: usize,
    pub alive: usize,
    /// 刚完成的地址，便于界面显示「正在扫描 192.168.1.x」
    pub current: String,
}

/// 扫描过程中的一次性警告（如 ICMP 不可用、仅走 TCP）。
#[derive(Clone)]
struct ScanPlan {
    client: Option<Arc<Client>>,
    warnings: Vec<String>,
}

/// 扫描指定范围。
///
/// `cancel` 置位后不再派发新任务，已完成的结果照常返回，`report.cancelled = true`。
pub async fn scan_scope(
    input: &str,
    scope: &ScanScope,
    opts: &IpScanOptions,
    cancel: Arc<AtomicBool>,
    on_progress: impl Fn(ScanProgress) + Send + Sync + 'static,
) -> Result<IpScanReport, ProbeError> {
    let started_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let started = Instant::now();

    let plan = build_plan(opts)?;
    let total = scope.len();
    let opts = opts.clone();
    let on_progress = Arc::new(on_progress);

    let mut set: JoinSet<(usize, IpScanHost)> = JoinSet::new();
    let mut iter = scope.hosts().into_iter().enumerate();

    let concurrency = opts.concurrency.max(1);
    for _ in 0..concurrency {
        match iter.next() {
            Some((idx, ip)) => {
                spawn_probe(&mut set, idx, ip, &plan, &opts);
            }
            None => break,
        }
    }

    let mut results: Vec<(usize, IpScanHost)> = Vec::with_capacity(total);
    let mut alive = 0usize;
    let mut cancelled = false;
    // 进度节流：大范围扫描时每个地址都推事件会把 IPC 压爆
    let step = (total / 50).max(1);

    while let Some(joined) = set.join_next().await {
        if let Ok((idx, host)) = joined {
            if host.alive {
                alive += 1;
            }
            let current = host.ip.clone();
            results.push((idx, host));

            let done = results.len();
            if done % step == 0 || done == total {
                on_progress(ScanProgress {
                    done,
                    total,
                    alive,
                    current,
                });
            }
        }

        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            continue; // 不再派发新任务，让已在跑的收尾
        }
        if let Some((idx, ip)) = iter.next() {
            spawn_probe(&mut set, idx, ip, &plan, &opts);
        }
    }

    // 按原始地址顺序还原，保证结果稳定可比对
    results.sort_by_key(|(idx, _)| *idx);

    Ok(IpScanReport {
        input: input.to_string(),
        scope_desc: scope.desc.clone(),
        started_at,
        duration_ms: started.elapsed().as_millis() as u64,
        total,
        alive_count: alive,
        hosts: results.into_iter().map(|(_, h)| h).collect(),
        cancelled,
        params: IpScanParams {
            count: opts.count,
            timeout_ms: opts.timeout.as_millis() as u64,
            concurrency: opts.concurrency,
            tcp_fallback_ports: opts.tcp_fallback_ports.clone(),
        },
        warnings: plan.warnings.clone(),
    })
}

fn build_plan(opts: &IpScanOptions) -> Result<ScanPlan, ProbeError> {
    let mut warnings = Vec::new();

    let client = match Client::new(&Config::builder().kind(ICMP::V4).build()) {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            // ICMP 不可用但配了 TCP 兜底时仍能扫，只是慢一些、结论弱一些
            if opts.tcp_fallback_ports.is_empty() {
                return Err(ProbeError::IcmpClient(format!(
                    "{e}（Linux 可执行 sysctl -w net.ipv4.ping_group_range=\"0 2147483647\" 放开非特权 ICMP，\
                     或在下方填写 TCP 兜底端口改用端口探活）"
                )));
            }
            warnings.push(format!("ICMP 不可用，本次仅用 TCP 端口探活：{e}"));
            None
        }
    };

    if client.is_none() && opts.tcp_fallback_ports.is_empty() {
        return Err(ProbeError::IcmpClient("ICMP 与 TCP 兜底均不可用".into()));
    }

    Ok(ScanPlan { client, warnings })
}

fn spawn_probe(
    set: &mut JoinSet<(usize, IpScanHost)>,
    idx: usize,
    ip: Ipv4Addr,
    plan: &ScanPlan,
    opts: &IpScanOptions,
) {
    let client = plan.client.clone();
    let opts = opts.clone();
    set.spawn(async move {
        // ident 逐目标递增：虽然回包按 host 路由，但同一 Client 上复用 ident
        // 在部分平台会让内核侧匹配变得不必要地复杂，递增是最省心的做法。
        let ident = ((std::process::id() as u16).wrapping_add(idx as u16)) & 0x7fff;
        (idx, probe_one(ip, ident, client, &opts).await)
    });
}

async fn probe_one(
    ip: Ipv4Addr,
    ident: u16,
    client: Option<Arc<Client>>,
    opts: &IpScanOptions,
) -> IpScanHost {
    let mut rtts: Vec<f64> = Vec::new();

    if let Some(c) = client {
        let mut pinger = c.pinger(IpAddr::V4(ip), PingIdentifier(ident)).await;
        pinger.timeout(opts.timeout);
        let payload = vec![0u8; 32];
        for seq in 0..opts.count.max(1) {
            if seq > 0 {
                tokio::time::sleep(opts.interval).await;
            }
            if let Ok((_pkt, rtt)) = pinger.ping(PingSequence(seq as u16), &payload).await {
                rtts.push(rtt.as_secs_f64() * 1000.0);
            }
        }
    }

    let count = opts.count.max(1) as f64;
    let loss_percent = ((count - rtts.len() as f64) / count * 100.0).clamp(0.0, 100.0);

    if !rtts.is_empty() {
        return IpScanHost {
            ip: ip.to_string(),
            alive: true,
            method: ProbeMethod::Icmp,
            rtt_ms: rtts.iter().cloned().reduce(f64::min).map(round1),
            loss_percent: round1(loss_percent),
            open_port: None,
        };
    }

    // ICMP 无响应 —— 若配了兜底端口，再给它一次机会
    for &port in &opts.tcp_fallback_ports {
        let started = Instant::now();
        let ok = tokio::time::timeout(opts.tcp_timeout, TcpStream::connect((ip, port))).await;
        if let Ok(Ok(stream)) = ok {
            drop(stream);
            return IpScanHost {
                ip: ip.to_string(),
                alive: true,
                method: ProbeMethod::Tcp,
                rtt_ms: Some(round1(started.elapsed().as_secs_f64() * 1000.0)),
                loss_percent: 100.0,
                open_port: Some(port),
            };
        }
    }

    IpScanHost {
        ip: ip.to_string(),
        alive: false,
        method: ProbeMethod::None,
        rtt_ms: None,
        loss_percent: round1(loss_percent),
        open_port: None,
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqhu_core::parse_scan_scope;
    use std::sync::Mutex;

    fn opts_fast() -> IpScanOptions {
        IpScanOptions {
            count: 1,
            timeout: Duration::from_millis(300),
            interval: Duration::from_millis(20),
            concurrency: 16,
            tcp_fallback_ports: Vec::new(),
            tcp_timeout: Duration::from_millis(300),
        }
    }

    #[tokio::test]
    async fn loopback_is_alive() {
        let scope = parse_scan_scope("127.0.0.1", 4096).unwrap();
        let r = scan_scope(
            "127.0.0.1",
            &scope,
            &opts_fast(),
            Arc::new(AtomicBool::new(false)),
            |_| {},
        )
        .await
        .expect("扫描应成功");

        assert_eq!(r.total, 1);
        assert_eq!(r.alive_count, 1);
        assert_eq!(r.hosts[0].method, ProbeMethod::Icmp);
        assert!(r.hosts[0].rtt_ms.is_some());
    }

    /// 回环段 127.0.0.1-127.0.0.4：Linux/macOS 整个 127/8 都在本地，
    /// Windows 只保证 127.0.0.1。所以只断言「至少 1 个存活」，不绑定平台差异。
    #[tokio::test]
    async fn loopback_range_progress_and_order() {
        let scope = parse_scan_scope("127.0.0.1-127.0.0.4", 4096).unwrap();
        let seen = Arc::new(Mutex::new(Vec::<usize>::new()));
        let seen2 = seen.clone();

        let r = scan_scope(
            "127.0.0.1-127.0.0.4",
            &scope,
            &opts_fast(),
            Arc::new(AtomicBool::new(false)),
            move |p| seen2.lock().unwrap().push(p.done),
        )
        .await
        .unwrap();

        assert_eq!(r.total, 4);
        assert_eq!(r.hosts.len(), 4, "所有地址都要有结果（含无响应）");
        // 结果按地址升序
        let ips: Vec<&str> = r.hosts.iter().map(|h| h.ip.as_str()).collect();
        assert_eq!(ips, vec!["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]);
        assert!(r.alive_count >= 1);
        // 进度必须递增且不超过总数
        let done = seen.lock().unwrap().clone();
        assert!(!done.is_empty(), "应至少回调一次进度");
        assert!(done.windows(2).all(|w| w[0] < w[1]), "进度应严格递增");
        assert!(*done.last().unwrap() <= r.total);
    }

    #[tokio::test]
    async fn cancellation_stops_early() {
        // 用一个必然全部超时的网段，取消后应尽快返回
        let scope = parse_scan_scope("192.0.2.1-192.0.2.60", 4096).unwrap();
        let cancel = Arc::new(AtomicBool::new(true)); // 一开始就取消
        let started = Instant::now();

        let r = scan_scope(
            "192.0.2.1-192.0.2.60",
            &scope,
            &opts_fast(),
            cancel,
            |_| {},
        )
        .await
        .unwrap();

        assert!(r.cancelled, "应标记为已取消");
        assert!(r.hosts.len() < 60, "取消后不应扫完全部地址");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "取消应显著缩短耗时"
        );
    }

    /// 直接验证 TCP 兜底分支：`client = None` 模拟 ICMP 不可用，
    /// 此时只能靠端口探活。这是企业网络禁 ICMP 时的真实路径。
    #[tokio::test]
    async fn tcp_only_mode_marks_method_as_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let opts = IpScanOptions {
            count: 1,
            timeout: Duration::from_millis(200),
            interval: Duration::from_millis(20),
            concurrency: 1,
            tcp_fallback_ports: vec![port],
            tcp_timeout: Duration::from_millis(500),
        };

        let host = probe_one(Ipv4Addr::LOCALHOST, 1, None, &opts).await;
        assert!(host.alive, "端口开放应判为存活");
        assert_eq!(host.method, ProbeMethod::Tcp, "应标记为 TCP 判定");
        assert_eq!(host.open_port, Some(port));
        assert!(host.rtt_ms.is_some(), "TCP 命中也要记录建连耗时");
        assert_eq!(host.loss_percent, 100.0, "ICMP 全丢，丢包率应为 100%");
    }

    /// 同上但端口不通：应明确判为无响应，而不是误报存活。
    #[tokio::test]
    async fn tcp_only_mode_closed_port_is_dead() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = l.local_addr().unwrap().port();
        drop(l);

        let opts = IpScanOptions {
            count: 1,
            timeout: Duration::from_millis(150),
            interval: Duration::from_millis(20),
            concurrency: 1,
            tcp_fallback_ports: vec![closed],
            tcp_timeout: Duration::from_millis(300),
        };

        let host = probe_one(Ipv4Addr::LOCALHOST, 1, None, &opts).await;
        assert!(!host.alive);
        assert_eq!(host.method, ProbeMethod::None);
        assert!(host.open_port.is_none());
    }

    #[test]
    fn default_options_are_sane() {
        let o = IpScanOptions::default();
        assert_eq!(o.count, 1);
        assert!(o.concurrency >= 32, "并发过低会让 /24 扫描慢到不可用");
        assert!(o.tcp_fallback_ports.is_empty());
    }
}
