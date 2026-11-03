//! TCP 端口探测。
//!
//! 直接用 `TcpStream::connect` 建连并计时，取代旧版的 `tcping.exe`。
//! 好处：无外部依赖、三平台一致、可精确区分「拒绝」「超时」「不可达」。

use qqhu_core::{PortFailureClass, PortProbeResult, PortSample};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

#[derive(Debug, Clone)]
pub struct TcpProbeOptions {
    /// 每个端口重复次数（用于估算丢包与时延抖动）
    pub samples: u32,
    /// 单次建连超时
    pub timeout: Duration,
    /// 并发端口数上限
    pub concurrency: usize,
}

impl Default for TcpProbeOptions {
    fn default() -> Self {
        Self {
            samples: 3,
            timeout: Duration::from_secs(1),
            concurrency: 16,
        }
    }
}

/// 探测单个端口。
pub async fn probe_port(addr: IpAddr, port: u16, opts: &TcpProbeOptions) -> PortProbeResult {
    let target = SocketAddr::new(addr, port);
    let mut samples = Vec::with_capacity(opts.samples.max(1) as usize);
    let mut success = 0u32;
    let mut first_error: Option<PortFailureClass> = None;

    for _ in 0..opts.samples.max(1) {
        let started = Instant::now();
        match tokio::time::timeout(opts.timeout, TcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                drop(stream);
                success += 1;
                samples.push(PortSample {
                    success: true,
                    rtt_ms: Some(round2(started.elapsed().as_secs_f64() * 1000.0)),
                    failure: PortFailureClass::Ok,
                    detail: String::new(),
                });
            }
            Ok(Err(e)) => {
                let class = classify(&e);
                if first_error.is_none() {
                    first_error = Some(class);
                }
                samples.push(PortSample {
                    success: false,
                    rtt_ms: None,
                    failure: class,
                    detail: e.to_string(),
                });
            }
            Err(_) => {
                if first_error.is_none() {
                    first_error = Some(PortFailureClass::Timeout);
                }
                samples.push(PortSample {
                    success: false,
                    rtt_ms: None,
                    failure: PortFailureClass::Timeout,
                    detail: format!("建连超时（{} ms）", opts.timeout.as_millis()),
                });
            }
        }
    }

    let total = samples.len() as u32;
    let failure_class = if success > 0 {
        PortFailureClass::Ok
    } else {
        // 全失败时以「超时」优先展示，更符合排障直觉
        if samples.iter().any(|s| s.failure == PortFailureClass::Timeout) {
            PortFailureClass::Timeout
        } else {
            first_error.unwrap_or(PortFailureClass::Unknown)
        }
    };

    PortProbeResult {
        port,
        success_count: success,
        success_rate: if total == 0 { 0.0 } else { success as f64 / total as f64 },
        failure_class,
        samples,
    }
}

/// 并发探测多个端口，返回结果按端口号升序。
pub async fn probe_ports(addr: IpAddr, ports: &[u16], opts: &TcpProbeOptions) -> Vec<PortProbeResult> {
    let mut unique: Vec<u16> = ports.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.is_empty() {
        return Vec::new();
    }

    let concurrency = opts.concurrency.max(1);
    let mut set: JoinSet<(u16, PortProbeResult)> = JoinSet::new();
    let mut iter = unique.into_iter();
    let mut results: Vec<PortProbeResult> = Vec::new();

    // 先填满并发窗口，完成一个补一个，避免一次性 spawn 过多任务
    for _ in 0..concurrency {
        match iter.next() {
            Some(p) => {
                let o = opts.clone();
                set.spawn(async move { (p, probe_port(addr, p, &o).await) });
            }
            None => break,
        }
    }

    while let Some(joined) = set.join_next().await {
        if let Ok((_, r)) = joined {
            results.push(r);
        }
        if let Some(p) = iter.next() {
            let o = opts.clone();
            set.spawn(async move { (p, probe_port(addr, p, &o).await) });
        }
    }

    results.sort_by_key(|r| r.port);
    results
}

fn classify(e: &std::io::Error) -> PortFailureClass {
    match e.kind() {
        ErrorKind::ConnectionRefused => PortFailureClass::Refused,
        ErrorKind::TimedOut => PortFailureClass::Timeout,
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => PortFailureClass::Unreachable,
        _ => PortFailureClass::Error,
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn free_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    #[tokio::test]
    async fn open_port_is_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let opts = TcpProbeOptions {
            samples: 2,
            timeout: Duration::from_secs(2),
            concurrency: 4,
        };
        let r = probe_port(IpAddr::from([127, 0, 0, 1]), port, &opts).await;
        assert_eq!(r.failure_class, PortFailureClass::Ok);
        assert_eq!(r.success_count, 2);
        assert!((r.success_rate - 1.0).abs() < f64::EPSILON);
        assert!(r.samples.iter().all(|s| s.rtt_ms.is_some()));
    }

    #[tokio::test]
    async fn closed_port_is_not_ok() {
        let port = free_port().await;
        let opts = TcpProbeOptions {
            samples: 1,
            timeout: Duration::from_millis(500),
            concurrency: 1,
        };
        let r = probe_port(IpAddr::from([127, 0, 0, 1]), port, &opts).await;
        assert_ne!(r.failure_class, PortFailureClass::Ok);
        assert_eq!(r.success_count, 0);
    }

    #[tokio::test]
    async fn probe_ports_sorted_and_deduped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let closed = free_port().await;

        let opts = TcpProbeOptions {
            samples: 1,
            timeout: Duration::from_millis(300),
            concurrency: 2,
        };
        let rs = probe_ports(IpAddr::from([127, 0, 0, 1]), &[port, closed, port], &opts).await;
        assert_eq!(rs.len(), 2, "重复端口应去重");
        assert!(rs[0].port <= rs[1].port, "结果应按端口升序");
    }
}
