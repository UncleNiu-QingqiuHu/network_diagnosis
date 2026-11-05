//! 原始 ICMP socket 封装。
//!
//! `surge-ping` 只能拿 Echo Reply，看不到中间路由器的 Time Exceeded，
//! 因此路径追踪与 MTU 探测需要自己开 `SOCK_RAW + IPPROTO_ICMP`：
//! - 发送：手写 Echo Request 并计算校验和
//! - 接收：跳过 IP 首部后按 ICMP 类型分发，并从差错报文里取出原始探测包做匹配
//!
//! 平台差异：
//! - Windows 允许普通用户创建 raw ICMP socket（ICMP 是唯一例外协议）
//! - Linux / macOS 需要 root 或 `CAP_NET_RAW`
//! - 不分片标志的选项名三平台各不相同：`IP_DONTFRAGMENT` / `IP_MTU_DISCOVER` / `IP_DONTFRAG`

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use socket2::{Domain, Protocol, Socket, Type};

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// ICMP 首部长度。
pub const ICMP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    EchoReply,
    TimeExceeded,
    /// ICMP 3/4：需要分片但设置了 DF，说明包超出了路径 MTU
    FragmentationNeeded,
    Unreachable,
    Other,
}

#[derive(Debug, Clone)]
pub struct IcmpReply {
    pub kind: ReplyKind,
    /// 外层 IP 源地址（中间路由器或目标）
    pub source: Ipv4Addr,
    /// 差错报文里引用到的原始探测包序号
    pub seq: Option<u16>,
    /// ICMP 3/4 携带的下一跳 MTU
    pub next_hop_mtu: Option<u16>,
}

/// 一条 raw ICMP socket。
pub struct IcmpSocket {
    sock: tokio::net::UdpSocket,
    ident: u16,
    seq: u16,
}

impl IcmpSocket {
    /// 打开 IPv4 raw ICMP socket。
    ///
    /// `ttl` 用于路径追踪逐跳递增；`dont_fragment` 用于 MTU 探测。
    pub fn open(ttl: Option<u32>, dont_fragment: bool) -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        if let Some(ttl) = ttl {
            sock.set_ttl_v4(ttl)?;
        }
        if dont_fragment {
            set_dont_fragment(&sock)?;
        }
        sock.set_nonblocking(true)?;

        // 转成 tokio 的 UdpSocket：raw socket 同样是 recvfrom/sendto 语义
        #[cfg(windows)]
        let std_sock = unsafe {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};
            std::net::UdpSocket::from_raw_socket(sock.into_raw_socket())
        };
        #[cfg(unix)]
        let std_sock = unsafe {
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            std::net::UdpSocket::from_raw_fd(sock.into_raw_fd())
        };

        let sock = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(Self {
            sock,
            // 用进程号作标识，避免与其他 ping 工具的包串号
            ident: (std::process::id() & 0xffff) as u16,
            seq: 0,
        })
    }

    pub fn ident(&self) -> u16 {
        self.ident
    }

    /// 发一个 Echo Request，返回本次的序号。
    pub async fn send_echo(&mut self, dst: Ipv4Addr, payload_len: usize) -> io::Result<u16> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let packet = build_echo(self.ident, seq, payload_len);
        self.sock
            .send_to(&packet, SocketAddr::V4(SocketAddrV4::new(dst, 0)))
            .await?;
        Ok(seq)
    }

    /// 收一个包。raw socket 拿到的数据包含 IP 首部。
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.sock.recv_from(buf).await
    }
}

/// 构造 ICMP Echo Request 并填好校验和。
pub fn build_echo(ident: u16, seq: u16, payload_len: usize) -> Vec<u8> {
    let len = ICMP_HEADER_LEN + payload_len;
    let mut buf = vec![0u8; len];
    buf[0] = ICMP_ECHO_REQUEST;
    buf[1] = 0;
    buf[4..6].copy_from_slice(&ident.to_be_bytes());
    buf[6..8].copy_from_slice(&seq.to_be_bytes());
    // 填充可辨识的载荷；要求至少 8 字节的旧实现也能接受
    for (i, b) in buf.iter_mut().enumerate().skip(ICMP_HEADER_LEN) {
        *b = (i - ICMP_HEADER_LEN) as u8;
    }
    let ck = checksum(&buf);
    buf[2..4].copy_from_slice(&ck.to_be_bytes());
    buf
}

/// Internet checksum（RFC 1071）。
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 解析收到的 ICMP 包。
///
/// `from` 为 `recv_from` 给出的对端地址，`ident` 过滤其他进程的包，
/// `expect_dst` 是本轮探测的目标地址 —— **必须校验**：
/// raw socket 会收到本机所有 ICMP 报文，只比对 ident/seq 会把别人的 Echo Reply
/// 误判成「到达目标」（实测踩过：追踪公网时第 2 跳错报网关即目标）。
pub fn parse_reply(buf: &[u8], from: Ipv4Addr, ident: u16, expect_dst: Ipv4Addr) -> Option<IcmpReply> {
    let icmp = strip_ip_header(buf)?;
    if icmp.len() < ICMP_HEADER_LEN {
        return None;
    }

    let kind_byte = icmp[0];
    let code = icmp[1];

    match kind_byte {
        ICMP_ECHO_REPLY => {
            // Echo Reply 必须来自我们探测的目标，否则是别的进程的包
            if from != expect_dst {
                return None;
            }
            let rid = u16::from_be_bytes([icmp[4], icmp[5]]);
            if rid != ident {
                return None;
            }
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            Some(IcmpReply {
                kind: ReplyKind::EchoReply,
                source: from,
                seq: Some(seq),
                next_hop_mtu: None,
            })
        }
        ICMP_TIME_EXCEEDED => {
            let (idst, iid, seq) = inner_echo(&icmp[ICMP_HEADER_LEN..])?;
            if iid != ident || idst != expect_dst {
                return None;
            }
            Some(IcmpReply {
                kind: ReplyKind::TimeExceeded,
                source: from,
                seq: Some(seq),
                next_hop_mtu: None,
            })
        }
        ICMP_DEST_UNREACH => {
            let (iid, seq) = match inner_echo(&icmp[ICMP_HEADER_LEN..]) {
                Some((idst, iid, seq)) => {
                    if idst != expect_dst || iid != ident {
                        return None;
                    }
                    (iid, seq)
                }
                // 有的路由器不回原始包，这时只能按 ident 放行
                None => (ident, 0),
            };
            if iid != ident {
                return None;
            }
            if code == 4 {
                // 3/4：下一跳 MTU 在 ICMP 首部之后的第 6、7 字节
                let mtu = if icmp.len() >= ICMP_HEADER_LEN + 2 {
                    u16::from_be_bytes([icmp[6], icmp[7]])
                } else {
                    0
                };
                Some(IcmpReply {
                    kind: ReplyKind::FragmentationNeeded,
                    source: from,
                    seq: Some(seq),
                    next_hop_mtu: if mtu > 0 { Some(mtu) } else { None },
                })
            } else {
                Some(IcmpReply {
                    kind: ReplyKind::Unreachable,
                    source: from,
                    seq: Some(seq),
                    next_hop_mtu: None,
                })
            }
        }
        _ => None,
    }
}

/// 跳过 IPv4 首部。有的平台（如 Linux 的 SOCK_DGRAM ICMP）不返回 IP 首部，
/// 此时直接把整个缓冲当作 ICMP 报文。
fn strip_ip_header(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < ICMP_HEADER_LEN {
        return None;
    }
    if buf[0] >> 4 == 4 {
        let ihl = (buf[0] & 0x0f) as usize * 4;
        if ihl >= 20 && buf.len() > ihl {
            return Some(&buf[ihl..]);
        }
        return None;
    }
    Some(buf)
}

/// 从差错报文的载荷里取出原始探测包的目的地址、ident 与 seq。
fn inner_echo(payload: &[u8]) -> Option<(Ipv4Addr, u16, u16)> {
    if payload.len() < 20 {
        return None;
    }
    let ihl = (payload[0] & 0x0f) as usize * 4;
    if ihl < 20 || payload.len() < ihl + ICMP_HEADER_LEN {
        return None;
    }
    let dst = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    let ident = u16::from_be_bytes([payload[ihl + 4], payload[ihl + 5]]);
    let seq = u16::from_be_bytes([payload[ihl + 6], payload[ihl + 7]]);
    Some((dst, ident, seq))
}

/// 设置不分片标志（IP_DF）。
fn set_dont_fragment(sock: &Socket) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IP_DONTFRAGMENT, SOCKET,
        };

        let s = sock.as_raw_socket() as SOCKET;
        let on: u32 = 1;
        let rc = unsafe {
            setsockopt(
                s,
                IPPROTO_IP,
                IP_DONTFRAGMENT,
                &on as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let fd = sock.as_raw_fd();
        #[cfg(target_os = "linux")]
        let (opt, val): (i32, libc::c_int) = (libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DO);
        #[cfg(target_os = "macos")]
        let (opt, val): (i32, libc::c_int) = (libc::IP_DONTFRAG, 1);

        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                opt,
                &val as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_rfc_example() {
        // RFC 1071 示例数据
        let data = [
            0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x00, 0x00,
        ];
        assert_eq!(checksum(&data), 0x220d);
    }

    #[test]
    fn echo_packet_has_valid_checksum() {
        let pkt = build_echo(0x1234, 7, 32);
        assert_eq!(pkt[0], ICMP_ECHO_REQUEST);
        assert_eq!(pkt.len(), 40);
        assert_eq!(&pkt[4..6], &0x1234u16.to_be_bytes());
        // 重新计算整包校验和应为 0（含校验和字段本身）
        assert_eq!(checksum(&pkt), 0);
    }

    fn with_ip_header(icmp: &[u8]) -> Vec<u8> {
        with_ip_header_to(icmp, "0.0.0.0".parse().unwrap())
    }

    /// 构造带 IPv4 首部的包，并写入目的地址（供差错报文内层包校验使用）
    fn with_ip_header_to(icmp: &[u8], dst: Ipv4Addr) -> Vec<u8> {
        let mut v = vec![0x45u8];
        v.resize(20, 0);
        v[16..20].copy_from_slice(&dst.octets());
        v.extend_from_slice(icmp);
        v
    }

    #[test]
    fn parses_echo_reply_with_ip_header() {
        let mut icmp = vec![0u8; 8];
        icmp[0] = ICMP_ECHO_REPLY;
        icmp[4..6].copy_from_slice(&99u16.to_be_bytes());
        icmp[6..8].copy_from_slice(&3u16.to_be_bytes());
        let buf = with_ip_header(&icmp);

        let r = parse_reply(&buf, "192.168.1.1".parse().unwrap(), 99, "192.168.1.1".parse().unwrap())
            .unwrap();
        assert_eq!(r.kind, ReplyKind::EchoReply);
        assert_eq!(r.seq, Some(3));
        assert_eq!(r.source.to_string(), "192.168.1.1");

        // 来源与探测目标不一致的 Echo Reply 必须丢弃：
        // raw socket 能收到本机所有 ICMP，只比 ident/seq 会误判「到达目标」
        assert!(parse_reply(&buf, "192.168.1.1".parse().unwrap(), 99, "8.8.8.8".parse().unwrap())
            .is_none());
    }

    #[test]
    fn parses_time_exceeded_and_matches_ident() {
        // 构造：ICMP 11 报文 + 内层 IP 头 + 内层 ICMP Echo
        let mut inner_echo_pkt = vec![0u8; 8];
        inner_echo_pkt[0] = ICMP_ECHO_REQUEST;
        inner_echo_pkt[4..6].copy_from_slice(&42u16.to_be_bytes());
        inner_echo_pkt[6..8].copy_from_slice(&5u16.to_be_bytes());
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let inner_ip = with_ip_header_to(&inner_echo_pkt, target);

        let mut icmp = vec![0u8; 8];
        icmp[0] = ICMP_TIME_EXCEEDED;
        icmp[1] = 0;
        icmp.extend_from_slice(&inner_ip);
        let buf = with_ip_header(&icmp);

        let r = parse_reply(&buf, "10.0.0.1".parse().unwrap(), 42, target).unwrap();
        assert_eq!(r.kind, ReplyKind::TimeExceeded);
        assert_eq!(r.seq, Some(5));

        // 标识不匹配、或内层目的地址不是本轮目标的包，都应丢弃
        assert!(parse_reply(&buf, "10.0.0.1".parse().unwrap(), 43, target).is_none());
        assert!(parse_reply(
            &buf,
            "10.0.0.1".parse().unwrap(),
            42,
            "198.51.100.7".parse().unwrap()
        )
        .is_none());
    }

    #[test]
    fn parses_fragmentation_needed_mtu() {
        let mut inner_echo_pkt = vec![0u8; 8];
        inner_echo_pkt[0] = ICMP_ECHO_REQUEST;
        inner_echo_pkt[4..6].copy_from_slice(&7u16.to_be_bytes());
        inner_echo_pkt[6..8].copy_from_slice(&9u16.to_be_bytes());
        let target: Ipv4Addr = "203.0.113.9".parse().unwrap();
        let inner_ip = with_ip_header_to(&inner_echo_pkt, target);

        let mut icmp = vec![0u8; 8];
        icmp[0] = ICMP_DEST_UNREACH;
        icmp[1] = 4;
        icmp[6..8].copy_from_slice(&1400u16.to_be_bytes());
        icmp.extend_from_slice(&inner_ip);
        let buf = with_ip_header(&icmp);

        let r = parse_reply(&buf, "10.0.0.1".parse().unwrap(), 7, target).unwrap();
        assert_eq!(r.kind, ReplyKind::FragmentationNeeded);
        assert_eq!(r.next_hop_mtu, Some(1400));
    }

    #[test]
    fn tolerates_packet_without_ip_header() {
        let mut icmp = vec![0u8; 8];
        icmp[0] = ICMP_ECHO_REPLY;
        icmp[4..6].copy_from_slice(&1u16.to_be_bytes());
        let r = parse_reply(&icmp, "1.1.1.1".parse().unwrap(), 1, "1.1.1.1".parse().unwrap())
            .unwrap();
        assert_eq!(r.kind, ReplyKind::EchoReply);
    }

    #[test]
    fn rejects_too_short_and_irrelevant() {
        let dst: Ipv4Addr = "1.1.1.1".parse().unwrap();
        assert!(parse_reply(&[0u8; 4], dst, 1, dst).is_none());
        let mut icmp = vec![0u8; 8];
        icmp[0] = 13; // Timestamp 之类，与我们无关
        assert!(parse_reply(&with_ip_header(&icmp), dst, 1, dst).is_none());
    }
}
