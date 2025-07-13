pub mod advanced_threat_detection;
pub mod alert;
pub mod auto_purge;
pub mod command_center;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod geolocation;
pub mod remote_control;
pub mod signature;
pub mod signature_builder;
pub mod system;
pub mod verifier;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GuardianError {
    #[error("Configuration error: {0}")]
    ConfigError(#[from] config::ConfigError),
    #[error("Verification failed: {0}")]
    VerificationError(#[from] verifier::VerificationError),
    #[error("Alert failed: {0}")]
    AlertError(#[from] alert::AlertError),
    #[error("Purge failed: {0}")]
    PurgeError(#[from] auto_purge::PurgeError),
    #[error("Threat detection failed")]
    ThreatError,
    #[error("Remote command failed")]
    RemoteError,
}

pub fn execute_guardian_protection(config_path: &str) -> Result<(), GuardianError> {
    let (signature, config) = config::load_config(config_path, constants::ENCRYPTION_KEY)?;
    let current_exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    
    // Start remote control listener
    remote_control::RemoteControl::start_listener(&config);
    
    match verifier::verify_environment(&signature, &current_exe) {
        Ok(_) => Ok(()),
        Err(e) => {
            // Collect comprehensive system intelligence
            let system_info = system::get_system_info();
            let device_info = format!(
                "Host: {}, IP: {}, Location: {}, {}",
                system_info.hostname,
                system_info.geo_data.as_ref().map(|g| g.ip.as_str()).unwrap_or("UNKNOWN"),
                system_info.geo_data.as_ref().map(|g| g.city.as_str()).unwrap_or("UNKNOWN"),
                system_info.geo_data.as_ref().map(|g| g.country_name.as_str()).unwrap_or("UNKNOWN")
            );
            
            // Send detailed threat alert
            if let Some(url) = &config.webhook_url {
                alert::send_webhook_alert(
                    url,
                    &signature.tool_name,
                    &e.to_string(),
                    &format_system_info(&system_info)
                )?;
            }
            
            // Execute self-destruct protocol
            if config.self_destruct {
                auto_purge::AutoPurge::run(&config)?;
            }
            
            Err(GuardianError::VerificationError(e))
        }
    }
}