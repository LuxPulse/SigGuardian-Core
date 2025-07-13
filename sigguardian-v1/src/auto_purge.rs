use std::{
    fs, path::{Path, PathBuf},
    process, env,
    io::{self, Write},
    time::{SystemTime, Duration},
    thread,
};
use crate::constants::SELF_DESTRUCT_DELAY_MS;

pub struct AutoPurge;

impl AutoPurge {
    pub fn run(config: &crate::config::GuardianConfig) {
        // Delay before starting purge to allow alert to send
        thread::sleep(Duration::from_millis(SELF_DESTRUCT_DELAY_MS));
        
        // Self-destruct sequence
        let _ = Self::delete_current_exe();
        
        if let Some(paths) = &config.purge_paths {
            for pattern in paths {
                let _ = Self::delete_by_pattern(pattern);
            }
        }
        
        let _ = Self::write_log_entry();
        
        // Final termination
        process::exit(0);
    }
    
    fn delete_current_exe() -> Result<(), io::Error> {
        let exe_path = env::current_exe()?;
        Self::secure_delete(&exe_path)?;
        
        #[cfg(windows)]
        Self::schedule_file_deletion(&exe_path);
        
        Ok(())
    }
    
    fn secure_delete(path: &Path) -> io::Result<()> {
        // Overwrite with random data before deletion
        if path.is_file() {
            let size = fs::metadata(path)?.len() as usize;
            let random_data: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
            fs::write(path, random_data)?;
        }
        fs::remove_file(path)?;
        Ok(())
    }
    
    #[cfg(windows)]
    fn schedule_file_deletion(path: &Path) {
        use std::os::windows::ffi::OsStrExt;
        use winapi::um::winbase::MoveFileExW;
        use winapi::um::winbase::MOVEFILE_DELAY_UNTIL_REBOOT;
        
        let wide_path: Vec<u16> = path.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
            
        unsafe {
            MoveFileExW(wide_path.as_ptr(), std::ptr::null_mut(), MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }
    
    fn delete_by_pattern(pattern: &str) -> io::Result<()> {
        let current_dir = env::current_dir()?;
        let pattern_path = current_dir.join(pattern);
        
        if pattern_path.is_dir() {
            Self::delete_dir_contents(&pattern_path)?;
            fs::remove_dir(&pattern_path)?;
        } else if pattern_path.exists() {
            Self::secure_delete(&pattern_path)?;
        } else {
            // Handle glob patterns
            for entry in glob::glob(pattern_path.to_str().unwrap())
                .unwrap()
                .filter_map(Result::ok) 
            {
                if entry.is_dir() {
                    let _ = Self::delete_dir_contents(&entry);
                    let _ = fs::remove_dir_all(&entry);
                } else {
                    let _ = Self::secure_delete(&entry);
                }
            }
        }
        Ok(())
    }
    
    fn delete_dir_contents(path: &Path) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                Self::delete_dir_contents(&path)?;
                fs::remove_dir(path)?;
            } else {
                Self::secure_delete(&path)?;
            }
        }
        Ok(())
    }
    
    fn write_log_entry() -> io::Result<()> {
        let log_msg = format!(
            "[{}] SigGuardian-X: Tool auto-purged due to unauthorized execution",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        
        // System log
        #[cfg(windows)]
        {
            use winapi::um::debugapi::OutputDebugStringA;
            let msg = std::ffi::CString::new(log_msg.clone()).unwrap();
            unsafe { OutputDebugStringA(msg.as_ptr()); }
        }
        
        #[cfg(unix)]
        {
            let _ = syslog::init(
                syslog::Facility::LOG_AUTH,
                log::LevelFilter::Info,
                Some("SigGuardian-X")
            ).map(|_| syslog::error!("{}", log_msg));
        }
        
        // File log
        let temp_path = env::temp_dir().join("sig_purge.log");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(temp_path)?;
            
        writeln!(file, "{}", log_msg)
    }
}