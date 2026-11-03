//! 平台抽象层。
//!
//! 跨平台重写的核心约定：**业务层只依赖 [`HostPlatform`] trait**，
//! 各平台实现放在 `cfg` 子模块里。模块可用性不是散落各处的 `cfg!`，
//! 而是由 [`CapabilitySet`] 一次性给出，前端据此决定显示/灰化/隐藏。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlatformKind {
    Windows,
    MacOs,
    Linux,
}

impl PlatformKind {
    pub fn display(self) -> &'static str {
        match self {
            PlatformKind::Windows => "Windows",
            PlatformKind::MacOs => "macOS",
            PlatformKind::Linux => "Linux",
        }
    }
}

/// 单模块能力等级。前端映射：`Full` 正常、`Partial` 显示但标注限制、`Unavailable` 灰化。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityLevel {
    Full,
    Partial,
    Unavailable,
}

impl CapabilityLevel {
    pub fn is_usable(self) -> bool {
        !matches!(self, CapabilityLevel::Unavailable)
    }
}

/// 一次导出全部模块可用性，避免前端逐模块判断平台。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitySet {
    pub platform: PlatformKind,
    pub network_probe: CapabilityLevel,
    pub subnet: CapabilityLevel,
    pub ip_scan: CapabilityLevel,
    pub mac_scan: CapabilityLevel,
    pub dhcp: CapabilityLevel,
    pub switch_console: CapabilityLevel,
    pub database: CapabilityLevel,
    pub packet_capture: CapabilityLevel,
    pub arp_monitor: CapabilityLevel,
    pub security_baseline: CapabilityLevel,
    pub domain: CapabilityLevel,
    pub code_signing: CapabilityLevel,
    pub ssl_cert: CapabilityLevel,
    pub ai_assistant: CapabilityLevel,
    /// 各模块不可用时的说明，键为模块 key。
    #[serde(default)]
    pub notes: Vec<ModuleNote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleNote {
    pub module: String,
    pub reason: String,
}

/// 平台能力探测契约。
pub trait HostPlatform: Send + Sync {
    fn kind(&self) -> PlatformKind;

    /// 计算机名；取不到时返回 "unknown"，不 panic。
    fn hostname(&self) -> String;

    /// 形如 `Windows 11 (10.0.22631) x86_64` 的一行摘要，写入报告元信息。
    fn os_summary(&self) -> String;

    /// 当前进程是否具备管理员/root 权限。
    fn is_elevated(&self) -> bool;

    /// 默认网关；无默认路由时返回 `None`。
    fn default_gateway(&self) -> Option<std::net::IpAddr>;

    /// 模块可用性矩阵。
    fn capabilities(&self) -> CapabilitySet;
}

/// 当前平台实现。
pub fn host() -> &'static dyn HostPlatform {
    #[cfg(windows)]
    {
        &imp::PLATFORM
    }
    #[cfg(target_os = "macos")]
    {
        &imp::PLATFORM
    }
    #[cfg(target_os = "linux")]
    {
        &imp::PLATFORM
    }
}

pub fn platform_kind() -> PlatformKind {
    host().kind()
}

// ---------------------------------------------------------------- 公共工具

/// 读环境变量并回退到默认值，供各平台共享。
pub(crate) fn env_or(keys: &[&str], default: &str) -> String {
    for k in keys {
        if let Ok(v) = std::env::var(k) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return v;
            }
        }
    }
    default.to_string()
}

#[cfg(windows)]
mod imp {
    use super::*;

    pub static PLATFORM: WindowsPlatform = WindowsPlatform;

    pub struct WindowsPlatform;

    impl HostPlatform for WindowsPlatform {
        fn kind(&self) -> PlatformKind {
            PlatformKind::Windows
        }

        fn hostname(&self) -> String {
            env_or(&["COMPUTERNAME"], "unknown")
        }

        fn os_summary(&self) -> String {
            // P1 将改用 RtlGetVersion 取真实 build 号；P0 只保证不失败。
            format!("Windows {}", std::env::consts::ARCH)
        }

        fn is_elevated(&self) -> bool {
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            unsafe {
                let mut token: HANDLE = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return false;
                }
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut ret_len: u32 = 0;
                let ok = GetTokenInformation(
                    token,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut core::ffi::c_void,
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut ret_len,
                );
                CloseHandle(token);
                ok != 0 && elevation.TokenIsElevated != 0
            }
        }

        fn default_gateway(&self) -> Option<std::net::IpAddr> {
            // P1 由 netdev / IP Helper API 实现；P0 返回 None 由上层降级。
            None
        }

        fn capabilities(&self) -> CapabilitySet {
            use CapabilityLevel::*;
            CapabilitySet {
                platform: PlatformKind::Windows,
                network_probe: Full,
                subnet: Full,
                ip_scan: Full,
                mac_scan: Full,
                dhcp: Full,
                switch_console: Full,
                database: Full,
                packet_capture: Full,
                arp_monitor: Full,
                security_baseline: Full,
                domain: Full,
                code_signing: Full,
                ssl_cert: Full,
                ai_assistant: Full,
                notes: vec![],
            }
        }
    }

}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub static PLATFORM: MacPlatform = MacPlatform;

    pub struct MacPlatform;

    impl HostPlatform for MacPlatform {
        fn kind(&self) -> PlatformKind {
            PlatformKind::MacOs
        }

        fn hostname(&self) -> String {
            env_or(&["HOSTNAME"], "unknown")
        }

        fn os_summary(&self) -> String {
            format!("macOS {} {}", os_version(), std::env::consts::ARCH)
        }

        fn is_elevated(&self) -> bool {
            unsafe { libc::geteuid() == 0 }
        }

        fn default_gateway(&self) -> Option<std::net::IpAddr> {
            None
        }

        fn capabilities(&self) -> CapabilitySet {
            use CapabilityLevel::*;
            CapabilitySet {
                platform: PlatformKind::MacOs,
                network_probe: Full,
                subnet: Full,
                ip_scan: Full,
                mac_scan: Full,
                dhcp: Full,
                switch_console: Full,
                database: Full,
                // 需要 libpcap（系统自带），chmod-bpf 或 root 才能实时抓包
                packet_capture: Partial,
                arp_monitor: Partial,
                security_baseline: Partial,
                // 无原生 AD 域加入；仅可只读探测
                domain: Unavailable,
                code_signing: Full,
                ssl_cert: Full,
                ai_assistant: Full,
                notes: vec![
                    ModuleNote {
                        module: "domain".into(),
                        reason: "macOS 不支持 Active Directory 加域与组策略，模块不可用。".into(),
                    },
                    ModuleNote {
                        module: "packet_capture".into(),
                        reason: "实时抓包需要 libpcap 权限，首次使用需授权或提权。".into(),
                    },
                    ModuleNote {
                        module: "security_baseline".into(),
                        reason: "本机基线检查按 macOS 实现，部分 Windows 专有项（防火墙策略、本地用户策略）不可用。".into(),
                    },
                ],
            }
        }
    }

    fn os_version() -> String {
        std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into())
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    pub static PLATFORM: LinuxPlatform = LinuxPlatform;

    pub struct LinuxPlatform;

    impl HostPlatform for LinuxPlatform {
        fn kind(&self) -> PlatformKind {
            PlatformKind::Linux
        }

        fn hostname(&self) -> String {
            if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
                let s = s.trim().to_string();
                if !s.is_empty() {
                    return s;
                }
            }
            env_or(&["HOSTNAME"], "unknown")
        }

        fn os_summary(&self) -> String {
            format!("{} {}", distro_pretty_name(), std::env::consts::ARCH)
        }

        fn is_elevated(&self) -> bool {
            unsafe { libc::geteuid() == 0 }
        }

        fn default_gateway(&self) -> Option<std::net::IpAddr> {
            None
        }

        fn capabilities(&self) -> CapabilitySet {
            use CapabilityLevel::*;
            CapabilitySet {
                platform: PlatformKind::Linux,
                network_probe: Full,
                subnet: Full,
                ip_scan: Full,
                mac_scan: Full,
                dhcp: Full,
                switch_console: Full,
                database: Full,
                packet_capture: Partial,
                arp_monitor: Partial,
                security_baseline: Partial,
                // 仅有 realm/sssd 的只读探测，不提供加退域
                domain: Partial,
                code_signing: Partial,
                ssl_cert: Full,
                ai_assistant: Full,
                notes: vec![
                    ModuleNote {
                        module: "domain".into(),
                        reason: "Linux 仅支持 realm/sssd 只读探测，不提供加域、退域与组策略刷新。".into(),
                    },
                    ModuleNote {
                        module: "packet_capture".into(),
                        reason: "实时抓包需要 libpcap 与 CAP_NET_RAW 权限。".into(),
                    },
                    ModuleNote {
                        module: "code_signing".into(),
                        reason: "Linux 无 Authenticode 等价机制，仅提供 GPG 分离签名。".into(),
                    },
                ],
            }
        }
    }

    fn distro_pretty_name() -> String {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
            })
            .unwrap_or_else(|| "Linux".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_probe_is_infallible() {
        let h = host();
        assert!(!h.hostname().is_empty());
        assert!(!h.os_summary().is_empty());
        // 能力矩阵必须自洽：不可用的模块应带说明
        let caps = h.capabilities();
        for note in &caps.notes {
            assert!(!note.reason.is_empty(), "模块 {} 缺少不可用原因", note.module);
        }
    }

    #[test]
    fn capability_serializes_to_camel_case() {
        let json = serde_json::to_string(&host().capabilities()).unwrap();
        assert!(json.contains("\"networkProbe\""));
        assert!(!json.contains("network_probe"));
    }
}
