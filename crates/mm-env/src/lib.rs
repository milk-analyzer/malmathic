pub mod capture;
pub mod image;
pub mod reader;
pub mod readonly;
pub mod snapshots;
pub mod vdi;
pub mod vmdk;

#[cfg(windows)]
pub mod win;

use mm_core::{Error, Result};
use mm_raw::{Volume, VolumeKind};

pub use image::{find_ntfs_partitions, open_partition, ImageFile, ImageVolume, Partition};
pub use reader::{BlockDevice, BlockReader, CacheCounters, CacheStats};
pub use readonly::ReadOnlyFile;
pub use snapshots::{Moment, NamedLink, Snapshot, SnapshotView, VmMetadata};
pub use vdi::Vdi;
pub use vmdk::{CacheCost, ChainLink, Provenance, Vmdk, VmdkInfo};

#[cfg(windows)]
pub fn console_process_count() -> Option<u32> {
    win::console_process_count()
}

#[cfg(not(windows))]
pub fn console_process_count() -> Option<u32> {
    None
}

#[cfg(windows)]
pub type OpenVolume = Volume<BlockReader<win::VolumeDevice>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Live,
    Recovery,
    Image,
}

impl Environment {
    #[cfg(windows)]
    pub fn detect() -> Self {
        if win::is_preinstallation_environment() {
            Environment::Recovery
        } else {
            Environment::Live
        }
    }

    #[cfg(windows)]
    pub fn can_read_raw_volumes(&self) -> bool {
        matches!(self, Environment::Recovery | Environment::Image) || win::is_elevated()
    }

    #[cfg(not(windows))]
    pub fn can_read_raw_volumes(&self) -> bool {
        true
    }

    #[cfg(not(windows))]
    pub fn detect() -> Self {
        Environment::Live
    }

    pub fn has_live_processes(&self) -> bool {
        matches!(self, Environment::Live)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Environment::Live => "live Windows",
            Environment::Recovery => "recovery environment (WinRE/WinPE)",
            Environment::Image => "disk image, read offline",
        }
    }

    pub fn no_processes_reason(&self) -> Option<&'static str> {
        match self {
            Environment::Live => None,
            Environment::Recovery => {
                Some("running from the recovery environment; no processes exist")
            }
            Environment::Image => {
                Some("reading a disk image; the system it came from is not running here")
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum VolumeStatus {
    WindowsInstall { serial: u64, cluster_size: u64 },
    NtfsNoWindows { serial: u64, reason: String },
    Locked,
    NotNtfs(VolumeKind),
    Inaccessible(String),
}

impl VolumeStatus {
    pub fn holds_windows(&self) -> bool {
        matches!(self, VolumeStatus::WindowsInstall { .. })
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveredVolume {
    pub device_path: String,
    pub mount_points: Vec<String>,
    pub status: VolumeStatus,
}

impl DiscoveredVolume {
    pub fn display_name(&self) -> String {
        match self.mount_points.first() {
            Some(m) => m.trim_end_matches('\\').to_string(),
            None => {
                let short: String = self.device_path.chars().skip(10).take(12).collect();
                format!("volume {short}…")
            }
        }
    }
}

#[cfg(windows)]
pub fn discover_volumes() -> Result<Vec<DiscoveredVolume>> {
    let paths = win::enumerate_volume_paths().map_err(|e| Error::io("enumerating volumes", e))?;

    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let device_path = path.trim_end_matches('\\').to_string();
        let mount_points = win::mount_points_for(&path);
        let status = classify_volume(&device_path);
        out.push(DiscoveredVolume { device_path, mount_points, status });
    }
    Ok(out)
}

#[cfg(windows)]
fn classify_volume(device_path: &str) -> VolumeStatus {
    use std::io::{Read, Seek, SeekFrom};

    let device = match win::VolumeDevice::open(device_path) {
        Ok(d) => d,
        Err(e) => return VolumeStatus::Inaccessible(e.to_string()),
    };
    let mut reader = BlockReader::new(device);

    let mut sector = [0u8; 512];
    if let Err(e) = reader.read_exact(&mut sector) {
        return VolumeStatus::Inaccessible(e.to_string());
    }
    match mm_raw::classify(&sector) {
        VolumeKind::Ntfs => {}
        VolumeKind::BitLocker => return VolumeStatus::Locked,
        other => return VolumeStatus::NotNtfs(other),
    }

    if reader.seek(SeekFrom::Start(0)).is_err() {
        return VolumeStatus::Inaccessible("could not rewind volume".into());
    }

    match Volume::open(reader, device_path) {
        Ok(volume) => {
            let serial = volume.serial();
            if volume.is_windows_install() {
                VolumeStatus::WindowsInstall { serial, cluster_size: volume.cluster_size() }
            } else {
                VolumeStatus::NtfsNoWindows { serial, reason: volume.why_not_windows() }
            }
        }
        Err(Error::VolumeLocked(_)) => VolumeStatus::Locked,
        Err(e) => VolumeStatus::Inaccessible(e.to_string()),
    }
}

#[cfg(windows)]
pub fn open_volume(device_path: &str) -> Result<OpenVolume> {
    let device = win::VolumeDevice::open(device_path)
        .map_err(|e| Error::io(format!("opening {device_path}"), e))?;
    Volume::open(BlockReader::new(device), device_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_environment_has_no_live_processes() {
        assert!(!Environment::Recovery.has_live_processes());
        assert!(Environment::Live.has_live_processes());
    }

    #[test]
    fn only_a_windows_install_is_a_target() {
        assert!(VolumeStatus::WindowsInstall { serial: 1, cluster_size: 4096 }.holds_windows());
        assert!(!VolumeStatus::NtfsNoWindows { serial: 1, reason: String::new() }.holds_windows());
        assert!(!VolumeStatus::Locked.holds_windows());
        assert!(!VolumeStatus::NotNtfs(VolumeKind::ExFat).holds_windows());
    }

    #[test]
    fn display_name_falls_back_when_there_is_no_drive_letter() {
        let with_letter = DiscoveredVolume {
            device_path: "\\\\?\\Volume{aaaaaaaa-0000-0000-0000-000000000000}".into(),
            mount_points: vec!["D:\\".into()],
            status: VolumeStatus::Locked,
        };
        assert_eq!(with_letter.display_name(), "D:");

        let without = DiscoveredVolume { mount_points: vec![], ..with_letter };
        let name = without.display_name();
        assert!(name.starts_with("volume "), "got {name}");
        assert!(name.contains("aaaaaaaa"), "got {name}");
    }
}
