use serde::{Deserialize, Serialize};
use std::process::Command;
use std::thread;
use std::time::Duration;

// Структура для результатов сканирования
#[derive(Serialize, Deserialize, Debug)]
struct ScanResult {
    asset_id: String,
    software_list: Vec<String>,
}

fn main() {
    println!("Shapoclyack Endpoint Agent started...");
    
    // 1. Цикл работы агента
    loop {
        // 2. Имитация получения JWT-токена (здесь будет вызов API Gateway)
        let token = "eyJhbGciOiJIUzI1Ni..."; 
        
        // 3. Сбор данных в зависимости от ОС
        let software = collect_software();
        
        let result = ScanResult {
            asset_id: "node-001".to_string(),
            software_list: software,
        };

        // 4. Отправка данных на API Gateway (реализация через reqwest)
        send_to_gateway(result, token);

        // Пауза перед следующим циклом (например, 1 час)
        thread::sleep(Duration::from_secs(3600));
    }
}

/// Кроссплатформенный сборщик софта
fn collect_software() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        // Пример вызова PowerShell для списка программ
        let output = Command::new("powershell")
            .args(["Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"])
            .output().expect("Failed to execute command");
        vec![String::from_utf8_lossy(&output.stdout).to_string()]
    }

    #[cfg(target_os = "linux")]
    {
        // Пример для Debian/Ubuntu
        let output = Command::new("dpkg-query")
            .args(["-f", "${binary:Package}\n", "-W"])
            .output().expect("Failed to execute command");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect()
    }
    
    #[cfg(target_os = "macos")]
    {
        // Сканирование папки /Applications
        let output = Command::new("ls").args(["/Applications"]).output().unwrap();
        vec![String::from_utf8_lossy(&output.stdout).to_string()]
    }
}

fn send_to_gateway(data: ScanResult, token: &str) {
    println!("Sending data to gateway with token: {}", token);
    // Здесь будет reqwest::Client::post().json(&data)...
}
