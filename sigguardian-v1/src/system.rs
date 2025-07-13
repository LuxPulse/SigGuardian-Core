use sysinfo::{System, SystemExt, NetworkExt, NetworksExt, CpuExt, ComponentExt};
use crate::advanced_threat_detection::ThreatDetector;
use crate::geolocation::get_geolocation;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct SystemInfo {
    pub mac_addresses: Vec<String>,
    pub uuid: String,
    pub ssid: Option<String>,
    pub hostname: String,
    pub os_version: String,
    pub cpu: String,
    pub memory: u64,
    pub geo_data: Option<crate::geolocation::GeoData>,
    pub threat_report: crate::advanced_threat_detection::ThreatReport,
    pub processes: Vec<String>,
    pub network_connections: Vec<String>,
    pub timestamp: u64,
}

pub fn get_system_info() -> SystemInfo {
    let sys = System::new_all();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let mut processes = Vec::new();
    for (_, process) in sys.processes() {
        let status = match process.status() {
            ProcessStatus::Run => "Running",
            ProcessStatus::Sleep => "Sleeping",
            ProcessStatus::Idle => "Idle",
            _ => "Other",
        };
        processes.push(format!(
            "{} (PID: {}, CPU: {}%, MEM: {}MB, STATUS: {})",
            process.name(),
            process.pid(),
            process.cpu_usage(),
            process.memory() / 1024 / 1024,
            status
        ));
    }
    
    let mut network_connections = Vec::new();
    for conn in sys.networks().iter().flat_map(|(_, data)| data) {
        network_connections.push(format!(
            "{}: {} ⇄ {} (Up: {}, Down: {})",
            conn.interface_name(),
            conn.mac_address(),
            conn.addresses().iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            conn.total_packets_transmitted(),
            conn.total_packets_received()
        ));
    }
    
    SystemInfo {
        mac_addresses: get_mac_addresses(),
        uuid: get_system_uuid().unwrap_or_else(|_| "UNKNOWN".to_string()),
        ssid: get_current_ssid(),
        hostname: sys.host_name().unwrap_or_else(|| "UNKNOWN".to_string()),
        os_version: sys.long_os_version().unwrap_or_else(|| "UNKNOWN".to_string()),
        cpu: sys.cpus().first()
            .map(|c| format!("{} {}MHz", c.brand(), c.frequency()))
            .unwrap_or_else(|| "UNKNOWN".to_string()),
        memory: sys.total_memory(),
        geo_data: get_geolocation(),
        threat_report: ThreatDetector::full_scan(),
        processes,
        network_connections,
        timestamp,
    }
}

pub fn format_system_info(info: &SystemInfo) -> String {
    let mut output = String::new();
    
    writeln!(output, "🛡️ SigGuardian-X System Report").unwrap();
    writeln!(output, "⏰ Timestamp: {}", info.timestamp).unwrap();
    writeln!(output, "🆔 Hostname: {}", info.hostname).unwrap();
    writeln!(output, "💻 OS: {}", info.os_version).unwrap();
    writeln!(output, "🧠 CPU: {}", info.cpu).unwrap();
    writeln!(output, "💾 Memory: {:.2} GB", info.memory as f64 / 1024.0 / 1024.0 / 1024.0).unwrap();
    
    writeln!(output, "\n🌐 Network:").unwrap();
    writeln!(output, "  MAC Addresses: {}", info.mac_addresses.join(", ")).unwrap();
    if let Some(ssid) = &info.ssid {
        writeln!(output, "  SSID: {}", ssid).unwrap();
    }
    
    if let Some(geo) = &info.geo_data {
        writeln!(output, "\n📍 Geolocation:").unwrap();
        writeln!(output, "  IP: {}", geo.ip).unwrap();
        writeln!(output, "  Location: {}, {}, {}", geo.city, geo.region, geo.country_name).unwrap();
        writeln!(output, "  Coordinates: {:.4}, {:.4}", geo.latitude, geo.longitude).unwrap();
        writeln!(output, "  ASN: {}", geo.asn).unwrap();
        writeln!(output, "  Org: {}", geo.org).unwrap();
    }
    
    writeln!(output, "\n⚠️ Threat Report:").unwrap();
    writeln!(output, "  Risk Score: {:.1}/10.0", info.threat_report.risk_score).unwrap();
    writeln!(output, "  VPN Detected: {}", info.threat_report.vpn_detected).unwrap();
    writeln!(output, "  RDP Active: {}", info.threat_report.rdp_active).unwrap();
    writeln!(output, "  Sandbox Detected: {}", info.threat_report.sandbox_detected).unwrap();
    writeln!(output, "  VPS Detected: {}", info.threat_report.vps_detected).unwrap();
    writeln!(output, "  Proxy Detected: {}", info.threat_report.is_proxy).unwrap();
    writeln!(output, "  TOR Detected: {}", info.threat_report.is_tor).unwrap();
    writeln!(output, "  Hosting Provider: {}", info.threat_report.is_hosting).unwrap();
    
    writeln!(output, "\n🔍 Processes ({} running):", info.processes.len()).unwrap();
    for process in info.processes.iter().take(10) {
        writeln!(output, "  - {}", process).unwrap();
    }
    
    writeln!(output, "\n🌐 Network Connections:").unwrap();
    for conn in info.network_connections.iter().take(5) {
        writeln!(output, "  - {}", conn).unwrap();
    }
    
    output
}

// Existing functions (get_mac_addresses, get_system_uuid, get_current_ssid) 
// remain the same as previous implementation