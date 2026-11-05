//! 青丘湖网络工作台 —— 核心领域层。
//!
//! 本 crate **不依赖任何平台 API、不依赖 Tauri、不做 IO**，
//! 只承载数据模型与纯计算，因此可以单元测试、可以在任何目标上编译。

pub mod error;
pub mod ipscan;
pub mod macscan;
pub mod model;
pub mod mtu;
pub mod quality;
pub mod subnet;
pub mod summary;
pub mod traceroute;
pub mod sslcert;

pub use error::{CoreError, CoreResult};
pub use ipscan::{
    parse_scan_scope, IpScanHost, IpScanParams, IpScanReport, ProbeMethod, ScanScope,
    ScanScopeKind, MAX_SCAN_HOSTS,
};
pub use macscan::{
    is_arp_displayable, is_broadcast, is_locally_administered, is_zero, normalize_mac, ArpEntry,
    ArpState, MacScanReport, OuiDb,
};
pub use model::*;
pub use mtu::{MtuProbe, MtuReport, DEFAULT_MTU, IPV4_ICMP_OVERHEAD, MAX_MTU, MIN_MTU};
pub use quality::compute_network_quality;
pub use subnet::{calc_from_cidr_combo, calc_subnet, subdivide_ipv4_equal_children, SubnetCalcResult};
pub use sslcert::{
    build_warnings, hostname_matches, CertInfo, CertStatus, SslCheckReport, EXPIRING_SOON_DAYS,
};
pub use summary::build_summary;
pub use traceroute::{TraceHop, TraceReport};

/// 应用版本（唯一来源；Tauri 侧通过 build script 注入）。
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
