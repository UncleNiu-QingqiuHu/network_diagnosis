//! 应用入口：注册命令、初始化日志。

pub mod agent;
pub mod commands;
pub mod paths;
pub mod renewal;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(commands::ScanState::default())
        .manage(renewal::RenewalState::default())
        .manage(agent::AgentState::default())
        .setup(|app| {
            // 数据目录必须先就绪：报告、证书库、Agent 配置全都挂在它下面。
            // 失败就直接拦在这里 —— 放过去只会在第一次写文件时抛出无关的错。
            let data = paths::init().map_err(|e| {
                eprintln!("[启动失败] {e}");
                e.to_string()
            })?;
            if !data.migrated.is_empty() {
                eprintln!(
                    "[数据迁移] 已从 {} 迁移：{}",
                    data.migrated_from
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    data.migrated.join("、")
                );
            }
            // 后台续期：启动即检查一次，之后每 6 小时一轮
            renewal::spawn(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::local_network,
            commands::ssl_check,
            commands::trace_route,
            commands::probe_mtu,
            commands::pki_overview,
            commands::pki_create_ca,
            commands::pki_delete_ca,
            commands::pki_issue,
            commands::pki_delete_cert,
            commands::pki_export_pfx,
            commands::pki_cert_text,
            commands::pki_dir_of,
            commands::acme_overview,
            commands::acme_issue,
            commands::acme_delete_cert,
            commands::acme_cert_text,
            commands::acme_export_pfx,
            commands::acme_dir_of,
            commands::acme_set_auto_renew,
            commands::acme_renewal_status,
            commands::acme_check_renewals,
            commands::acme_renew_now,
            commands::about_info,
            commands::license_text,
            commands::subnet_calc,
            commands::subnet_from_cidr,
            commands::subnet_subdivide,
            commands::run_diagnosis,
            commands::ip_scan_start,
            commands::ip_scan_cancel,
            commands::ip_scan_export_csv,
            commands::mac_scan_run,
            commands::mac_scan_export_csv,
            agent::agent_config,
            agent::agent_save_model,
            agent::agent_delete_model,
            agent::agent_set_key,
            agent::agent_set_active_model,
            agent::agent_set_options,
            agent::agent_skills,
            agent::agent_scan_skills,
            agent::agent_import_skill,
            agent::agent_set_skill_enabled,
            agent::agent_delete_skill,
            agent::agent_chat,
            agent::agent_cancel,
            agent::agent_confirm,
            agent::agent_status,
            agent::agent_sessions,
            agent::agent_session_get,
            agent::agent_session_new,
            agent::agent_session_save,
            agent::agent_session_rename,
            agent::agent_session_delete,
            agent::agent_session_append,
            agent::agent_session_export,
        ])
        .run(tauri::generate_context!())
        .expect("应用启动失败");
}
