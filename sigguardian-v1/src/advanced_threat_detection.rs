use serde::Deserialize;
use sysinfo::{System, SystemExt, ProcessExt, ProcessStatus};
use std::net::UdpSocket;
use std::time::Duration;
use reqwest::blocking::Client;
use crate::constants::THREAT_API;

#[derive(Debug, Deserialize)]
struct ThreatResponse {
    risk_score: f32,
    is_vpn: bool,
    is_proxy: bool,
    is_tor: bool,
    is_hosting: bool,
    is_rdp: bool,
    is_sandbox: bool,
}

pub struct ThreatDetector;

impl ThreatDetector {
    pub fn full_scan() -> ThreatReport {
        let mut report = ThreatReport::new();
        
        // Network-based detection
        report.vpn_detected = Self::detect_vpn();
        report.rdp_active = Self::detect_rdp();
        
        // System environment checks
        report.sandbox_detected = Self::detect_sandbox();
        report.vps_detected = Self::detect_vps();
        
        // External threat intelligence
        if let Ok(threat_data) = Self::query_threat_intel() {
            report.risk_score = threat_data.risk_score;
            report.is_proxy = threat_data.is_proxy;
            report.is_tor = threat_data.is_tor;
            report.is_hosting = threat_data.is_hosting;
        }
        
        report
    }

    fn detect_vpn() -> bool {
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("powershell")
                .args(&["Get-VpnConnection", "|", "Where", "{$_.ConnectionStatus", "-eq", "'Connected'}"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("Connected"))
                .unwrap_or(false);
            return output;
        }
        
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let ifconfig = std::process::Command::new("ifconfig")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            
            ifconfig.contains("tun") || 
            ifconfig.contains("ppp") || 
            ifconfig.contains("vpn")
        }
    }

    fn detect_rdp() -> bool {
        let sys = System::new_all();
        let rdp_processes = ["msrdc", "rdesktop", "xrdp", "vnc", "teamviewer"];
        
        sys.processes().values().any(|process| {
            let name = process.name().to_lowercase();
            rdp_processes.iter().any(|&p| name.contains(p))
        })
    }

    fn detect_sandbox() -> bool {
        // Check for low system resources (common in sandboxes)
        let sys = System::new_all();
        if sys.total_memory() < 2_147_483_648 || // < 2GB RAM
           sys.cpus().len() < 2 ||               // < 2 CPUs
           sys.uptime() < 300                    // < 5 min uptime
        {
            return true;
        }
        
        // Check for known sandbox processes
        let sandbox_processes = ["procmon", "wireshark", "processhacker", "sandboxie"];
        sys.processes().values().any(|process| {
            let name = process.name().to_lowercase();
            sandbox_processes.iter().any(|&p| name.contains(p))
        })
    }

    fn detect_vps() -> bool {
        let sys = System::new_all();
        
        // Check for hypervisor in CPU info
        if let Some(vendor) = sys.cpus().first().map(|c| c.vendor_id().to_lowercase()) {
            if vendor.contains("kvm") || 
               vendor.contains("vmware") || 
               vendor.contains("virtualbox") || 
               vendor.contains("xen") || 
               vendor.contains("qemu") 
            {
                return true;
            }
        }
        
        // Check for cloud-init (common in VPS)
        sys.processes().values().any(|process| 
            process.name().to_lowercase().contains("cloud-init")
        )
    }

    fn query_threat_intel() -> Result<ThreatResponse, reqwest::Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
            
        let response = client.get(THREAT_API)
            .header("X-API-Key", "mindofluxx-secure-key")
            .send()?;
            
        response.json()
    }
}

#[derive(Debug, Default)]
pub struct ThreatReport {
    pub risk_score: f32,
    pub vpn_detected: bool,
    pub rdp_active: bool,
    pub sandbox_detected: bool,
    pub vps_detected: bool,
    pub is_proxy: bool,
    pub is_tor: bool,
    pub is_hosting: bool,
}

impl ThreatReport {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn is_high_risk(&self) -> bool {
        self.risk_score > 7.0 ||
        self.vpn_detected ||
        self.rdp_active ||
        self.sandbox_detected ||
        self.is_proxy ||
        self.is_tor
    }
}