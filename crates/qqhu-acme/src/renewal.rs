//! 续期判定（纯逻辑）。
//!
//! 定时器只负责「按时问一次」，要不要续、能不能续都在这层决定，
//! 这样判定规则可以直接单测，不必等真实时间流逝。

use crate::model::AcmeCertMeta;
use chrono::{DateTime, Duration, Utc};

/// 到期前多少天开始续期。Let's Encrypt 证书 90 天，30 天足够覆盖几次重试。
pub const LEAD_DAYS: i64 = 30;

/// 失败后的退避时间：同一张证书 12 小时内不重复尝试，避免把 CA 的频率额度打满。
pub const RETRY_AFTER_HOURS: i64 = 12;

/// 后台检查间隔（秒）。
pub const CHECK_INTERVAL_SECS: u64 = 6 * 3600;

/// 是否满足「该续期了」。
///
/// 三个条件：开了自动续期、剩余天数进入窗口、不在失败退避期。
pub fn is_due(meta: &AcmeCertMeta, now: DateTime<Utc>, lead_days: i64) -> bool {
    if !meta.auto_renew {
        return false;
    }
    if (meta.not_after - now).num_days() > lead_days {
        return false;
    }
    retry_allowed(meta, now)
}

/// 是否已过失败退避期。
///
/// 只看上次尝试时间，不区分成败：成功后续期会把有效期推后，自然不再 due；
/// 失败则必须等够退避时间，否则每次心跳都会重试。
pub fn retry_allowed(meta: &AcmeCertMeta, now: DateTime<Utc>) -> bool {
    match meta.last_attempt_at {
        Some(t) => now - t >= Duration::hours(RETRY_AFTER_HOURS),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(days: i64, auto: bool) -> AcmeCertMeta {
        let now = Utc::now();
        AcmeCertMeta {
            id: "x".into(),
            primary_domain: "example.com".into(),
            domains: vec!["example.com".into()],
            directory: "d".into(),
            staging: false,
            provider: "测试".into(),
            provider_key: "aliyun".into(),
            serial: "01".into(),
            fingerprint: "AA".into(),
            created_at: now,
            not_before: now,
            not_after: now + Duration::days(days),
            days_remaining: days,
            auto_renew: auto,
            renew_count: 0,
            last_attempt_at: None,
            last_error: None,
            renewed_at: None,
        }
    }

    #[test]
    fn due_only_inside_window() {
        let now = Utc::now();
        assert!(!is_due(&meta(31, true), now, LEAD_DAYS));
        assert!(is_due(&meta(30, true), now, LEAD_DAYS));
        assert!(is_due(&meta(5, true), now, LEAD_DAYS));
        // 已过期也仍然要续
        assert!(is_due(&meta(-3, true), now, LEAD_DAYS));
    }

    #[test]
    fn disabled_never_due() {
        assert!(!is_due(&meta(1, false), Utc::now(), LEAD_DAYS));
    }

    #[test]
    fn failed_attempt_backs_off() {
        let now = Utc::now();
        let mut m = meta(10, true);
        m.last_attempt_at = Some(now - Duration::hours(1));
        m.last_error = Some("boom".into());
        assert!(!is_due(&m, now, LEAD_DAYS), "1 小时前刚失败，不该立刻重试");

        m.last_attempt_at = Some(now - Duration::hours(13));
        assert!(is_due(&m, now, LEAD_DAYS), "超过退避时间应重试");
    }

    #[test]
    fn lead_days_is_configurable() {
        let now = Utc::now();
        assert!(is_due(&meta(20, true), now, 30));
        assert!(!is_due(&meta(20, true), now, 10));
    }
}
