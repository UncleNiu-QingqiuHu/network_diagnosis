//! 应用入口：注册命令、初始化日志。

pub mod commands;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::about_info,
            commands::license_text,
            commands::subnet_calc,
            commands::subnet_from_cidr,
            commands::subnet_subdivide,
            commands::ai_chat,
        ])
        .run(tauri::generate_context!())
        .expect("应用启动失败");
}
