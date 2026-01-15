use clap::{Parser, Subcommand};
use log::info;
use std::path::Path;
use zthfs::{
    VERSION,
    config::{FilesystemConfigBuilder, LogConfig},
    fs_impl::Zthfs,
    health_check, init,
};

#[derive(Parser)]
#[command(name = "zthfs")]
#[command(version = VERSION)]
#[command(about = "A transparent encryption filesystem for medical data protection")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, default_value = "/etc/zthfs/config.json")]
    config: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount the filesystem
    Mount {
        /// Mount point directory
        mount_point: String,

        /// Data directory
        data_dir: String,

        /// Configuration file path
        #[arg(short, long, default_value = "/etc/zthfs/config.json")]
        config: String,
    },

    /// Unmount the filesystem
    Unmount {
        /// Mount point directory
        mount_point: String,
    },

    /// Initialize a new ZTHFS configuration
    Init {
        /// Configuration file path
        config_path: String,
    },

    /// Validate configuration
    Validate {
        /// Configuration file path
        config_path: String,
    },

    /// Run diagnostics and health check
    Health,

    /// Demonstrate ZTHFS functionality
    Demo,

    /// Show system information
    Info,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.verbose {
        unsafe { std::env::set_var("RUST_LOG", "debug") };
    } else {
        unsafe { std::env::set_var("RUST_LOG", "info") };
    }

    init()?;

    match cli.command {
        Commands::Mount {
            mount_point,
            data_dir,
            config,
        } => {
            mount_filesystem(&mount_point, &data_dir, &config)?;
        }

        Commands::Unmount { mount_point } => {
            unmount_filesystem(&mount_point)?;
        }

        Commands::Init { config_path } => {
            initialize_config(&config_path)?;
        }

        Commands::Validate { config_path } => {
            validate_config(&config_path)?;
        }

        Commands::Health => {
            run_health_check()?;
        }

        Commands::Demo => {
            run_demo()?;
        }

        Commands::Info => {
            show_system_info()?;
        }
    }

    Ok(())
}

fn mount_filesystem(
    mount_point: &str,
    data_dir: &str,
    config_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Mounting ZTHFS at {mount_point} with data directory {data_dir}");

    // Load configuration
    let config = if Path::new(config_path).exists() {
        zthfs::config::FilesystemConfig::from_file(config_path)?
    } else {
        // Create default configuration
        FilesystemConfigBuilder::new()
            .data_dir(data_dir.to_string())
            .mount_point(mount_point.to_string())
            .build()?
    };

    // Validate mount point exists and is a directory
    let mount_path = Path::new(mount_point);
    if !mount_path.exists() {
        return Err(format!("Mount point {} does not exist", mount_point).into());
    }
    if !mount_path.is_dir() {
        return Err(format!("Mount point {} is not a directory", mount_point).into());
    }

    // Create filesystem instance
    let fs = Zthfs::new(&config)?;

    // Mount with FUSE - this will block until the filesystem is unmounted
    info!("Starting FUSE mount at {mount_point}");
    fuser::mount2(
        fs,
        mount_point,
        &[
            fuser::MountOption::FSName("zthfs".to_string()),
            fuser::MountOption::Subtype("zthfs".to_string()),
            fuser::MountOption::AllowOther,
            fuser::MountOption::AutoUnmount,
            fuser::MountOption::DefaultPermissions,
        ],
    )?;

    info!("Filesystem unmounted successfully from {mount_point}");
    Ok(())
}

fn unmount_filesystem(mount_point: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Unmounting ZTHFS at {mount_point}");

    // Validate mount point
    let mount_path = Path::new(mount_point);
    if !mount_path.exists() {
        return Err(format!("Mount point {} does not exist", mount_point).into());
    }

    // Try to unmount using fusermount (Linux/macOS)
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        match Command::new("fusermount")
            .args(["-u", mount_point])
            .status()
        {
            Ok(status) if status.success() => {
                info!("Filesystem unmounted successfully from {mount_point} using fusermount");
                Ok(())
            }
            Ok(_) => {
                // fusermount failed, try umount
                match Command::new("umount").arg(mount_point).status() {
                    Ok(status) if status.success() => {
                        info!("Filesystem unmounted successfully from {mount_point} using umount");
                        Ok(())
                    }
                    Ok(_) => Err(format!(
                        "Failed to unmount {}: umount command failed",
                        mount_point
                    )
                    .into()),
                    Err(e) => Err(format!("Failed to execute umount command: {}", e).into()),
                }
            }
            Err(_) => {
                // fusermount not available, try umount directly
                match Command::new("umount").arg(mount_point).status() {
                    Ok(status) if status.success() => {
                        info!("Filesystem unmounted successfully from {mount_point} using umount");
                        Ok(())
                    }
                    Ok(_) => Err(format!(
                        "Failed to unmount {}: umount command failed",
                        mount_point
                    )
                    .into()),
                    Err(e) => Err(format!("Failed to execute umount command: {}", e).into()),
                }
            }
        }
    }

    // For macOS, use diskutil
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        match Command::new("diskutil")
            .args(&["unmount", "force", mount_point])
            .status()
        {
            Ok(status) if status.success() => {
                info!("Filesystem unmounted successfully from {mount_point} using diskutil");
                Ok(())
            }
            Ok(_) => {
                Err(format!("Failed to unmount {}: diskutil command failed", mount_point).into())
            }
            Err(e) => Err(format!("Failed to execute diskutil command: {}", e).into()),
        }
    }

    // For other platforms or as fallback
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err("Automatic unmounting not supported on this platform. Please unmount manually.".into())
    }
}

fn initialize_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing ZTHFS configuration at {config_path}");

    let config = FilesystemConfigBuilder::new()
        .data_dir("/var/lib/zthfs/data".to_string())
        .mount_point("/mnt/zthfs".to_string())
        .build()?;

    config.save_to_file(config_path)?;
    info!("Configuration saved to {config_path}");
    Ok(())
}

fn validate_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Validating configuration at {config_path}");

    let config = zthfs::config::FilesystemConfig::from_file(config_path)?;

    // First do basic validation
    match config.validate() {
        Ok(_) => {
            info!("✓ Basic configuration is valid");
            info!("Data directory: {}", config.data_dir);
            info!("Mount point: {}", config.mount_point);
            info!(
                "Logging: {}",
                if config.logging.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            info!(
                "Integrity: {}",
                if config.integrity.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
        }
        Err(e) => {
            info!("✗ Configuration is invalid: {e}");
            return Err(e.to_string().into());
        }
    }

    // Then do production validation
    info!("");
    info!("Running production safety checks...");
    match config.validate_with_production_checks() {
        Ok(_) => {
            info!("✓ Configuration is safe for production use");
        }
        Err(e) => {
            info!("⚠ Configuration is NOT safe for production: {e}");
            info!(
                "Please use EncryptionConfig::generate_key() or EncryptionConfig::with_random_keys()"
            );
            info!("to generate secure keys for production use.");
            return Err(e.to_string().into());
        }
    }

    Ok(())
}

fn run_health_check() -> Result<(), Box<dyn std::error::Error>> {
    info!("Running ZTHFS health check");

    match health_check() {
        Ok(report) => {
            println!("ZTHFS Health Check Report:");
            println!("{report}");
        }
        Err(e) => {
            println!("Health check failed: {e}");
            return Err(Box::new(e));
        }
    }

    Ok(())
}

fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use zthfs::config::FilesystemConfigBuilder;

    info!("Running ZTHFS demonstration");

    // Use fixed demo paths for testing
    let data_dir = Path::new("/tmp/zthfs_data");
    let mount_point = Path::new("/tmp/zthfs_mount");
    let log_file = Path::new("/tmp/zthfs_demo.log");

    // Create directories
    fs::create_dir_all(data_dir)?;
    fs::create_dir_all(mount_point)?;

    // Ensure log file directory exists
    if let Some(parent) = log_file.parent() {
        fs::create_dir_all(parent)?;
    }

    let config = FilesystemConfigBuilder::new()
        .data_dir(data_dir.to_string_lossy().to_string())
        .mount_point(mount_point.to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: true,
            file_path: log_file.to_string_lossy().to_string(),
            level: "info".to_string(),
            max_size: 1024 * 1024, // 1MB for demo
            rotation_count: 2,
        })
        .build()?;

    // Create filesystem instance
    let fs = Zthfs::new(&config)?;

    println!("🎉 ZTHFS Medical Data Filesystem Demo");
    println!("====================================");

    // Test file operations
    let test_file = Path::new("/patient_record.txt");
    let medical_data = b"Patient ID: 12345\nDiagnosis: Hypertension\nTreatment: Medication";

    println!("📝 Writing medical data to file...");
    zthfs::fs_impl::file_write::write_file(&fs, test_file, medical_data)?;

    println!("📖 Reading medical data from file...");
    let read_data = zthfs::fs_impl::file_read::read_file(&fs, test_file)?;
    println!("✓ Data integrity verified");

    assert_eq!(medical_data, read_data.as_slice());
    println!("✅ Encryption/Decryption test passed!");

    // Test directory operations
    let test_dir = Path::new("/medical_records");
    zthfs::fs_impl::dir_modify::create_directory(&fs, test_dir, 0o755)?;

    println!("📁 Created directory: {}", test_dir.display());

    // Test file copy
    let dest_file = Path::new("/medical_records/copied_record.txt");
    zthfs::fs_impl::file_copy::copy_file(&fs, test_file, dest_file)?;
    println!("📋 Copied file to: {}", dest_file.display());

    println!("\n🎉 Demo completed successfully!");

    Ok(())
}

fn show_system_info() -> Result<(), Box<dyn std::error::Error>> {
    println!("ZTHFS - Zero-Trust Healthcare File System");
    println!("Version: {VERSION}");
    println!("Build Info: {}", zthfs::BUILD_INFO);

    println!("\nUsage:");
    println!("  zthfs init <config_path>     - Initialize configuration");
    println!("  zthfs mount <mount> <data>   - Mount filesystem");
    println!("  zthfs unmount <mount>        - Unmount filesystem");
    println!("  zthfs validate <config>      - Validate configuration");
    println!("  zthfs health                 - Run health check");
    println!("  zthfs demo                   - Run demonstration");
    println!("  zthfs info                   - Show this information");

    Ok(())
}
