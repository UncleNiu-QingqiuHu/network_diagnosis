//! 应用入口：注册命令、初始化日志。

pub mod commands;
pub mod paths;
pub mod renewal;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(commands::ScanState::default())
        .manage(renewal::RenewalState::default())
        .setup(|app| {
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
            commands::ai_chat,
        ])
        .run(tauri::generate_context!())
        .expect("应用启动失败");
}
