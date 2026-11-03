//! 青丘湖网络工作台 —— 核心领域层。
//!
//! 本 crate **不依赖任何平台 API、不依赖 Tauri、不做 IO**，
//! 只承载数据模型与纯计算，因此可以单元测试、可以在任何目标上编译。

pub mod error;
pub mod model;
pub mod quality;
pub mod subnet;

pub use error::{CoreError, CoreResult};
pub use model::*;
pub use quality::compute_network_quality;
pub use subnet::{calc_from_cidr_combo, calc_subnet, subdivide_ipv4_equal_children, SubnetCalcResult};

/// 应用版本（唯一来源；Tauri 侧通过 build script 注入）。
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
