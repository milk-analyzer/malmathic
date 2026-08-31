use std::io;
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_FILES, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetLogicalDrives,
    GetVolumePathNamesForVolumeNameW, ReadFile, SetFilePointerEx, FILE_ATTRIBUTE_NORMAL,
    FILE_BEGIN, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::GetConsoleProcessList;
use windows::Win32::System::Ioctl::{GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::IO::DeviceIoControl;

use crate::reader::BlockDevice;

pub struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

unsafe impl Send for OwnedHandle {}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

pub fn open_device(path: &str) -> io::Result<OwnedHandle> {
    let name = wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("{path}: {e}")))?;

    Ok(OwnedHandle(handle))
}

pub struct VolumeDevice {
    handle: OwnedHandle,
    length: u64,
}

impl VolumeDevice {
    pub fn open(device_path: &str) -> io::Result<Self> {
        let handle = open_device(device_path)?;
        let length = volume_length(&handle)?;
        Ok(VolumeDevice { handle, length })
    }
}

impl BlockDevice for VolumeDevice {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            SetFilePointerEx(self.handle.0, offset as i64, None, FILE_BEGIN)
                .map_err(|e| io::Error::other(format!("seek to {offset}: {e}")))?;
        }
        let mut read = 0u32;
        unsafe {
            ReadFile(self.handle.0, Some(buf), Some(&mut read), None).map_err(|e| {
                io::Error::other(format!("read {} bytes at {offset}: {e}", buf.len()))
            })?;
        }
        Ok(read as usize)
    }

    fn length(&self) -> u64 {
        self.length
    }
}

fn volume_length(handle: &OwnedHandle) -> io::Result<u64> {
    let mut info = GET_LENGTH_INFORMATION::default();
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            handle.0,
            IOCTL_DISK_GET_LENGTH_INFO,
            None,
            0,
            Some(&mut info as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<GET_LENGTH_INFORMATION>() as u32,
            Some(&mut returned),
            None,
        )
        .map_err(|e| io::Error::other(format!("querying volume length: {e}")))?;
    }
    Ok(info.Length as u64)
}

pub fn enumerate_volume_paths() -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buf = [0u16; 260];

    let find = unsafe { FindFirstVolumeW(&mut buf) }
        .map_err(|e| io::Error::other(format!("enumerating volumes: {e}")))?;

    loop {
        out.push(from_wide(&buf));
        buf = [0u16; 260];
        if unsafe { FindNextVolumeW(find, &mut buf) }.is_err() {
            break;
        }
    }
    let _ = unsafe { FindVolumeClose(find) };
    let _ = ERROR_NO_MORE_FILES;

    Ok(out)
}

pub fn mount_points_for(volume_path_with_slash: &str) -> Vec<String> {
    let name = wide(volume_path_with_slash);
    let mut needed = 0u32;

    let _ = unsafe { GetVolumePathNamesForVolumeNameW(PCWSTR(name.as_ptr()), None, &mut needed) };
    if needed == 0 {
        return Vec::new();
    }

    let mut buf = vec![0u16; needed as usize];
    if unsafe {
        GetVolumePathNamesForVolumeNameW(PCWSTR(name.as_ptr()), Some(&mut buf), &mut needed)
    }
    .is_err()
    {
        return Vec::new();
    }

    buf.split(|&c| c == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect()
}

pub fn logical_drive_letters() -> Vec<String> {
    let mask = unsafe { GetLogicalDrives() };
    (0..26u32)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:", (b'A' + i as u8) as char))
        .collect()
}

pub fn is_elevated() -> bool {
    let mut raw = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }.is_err() {
        return false;
    }
    let token = OwnedHandle(raw);

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    }
    .is_ok();

    ok && elevation.TokenIsElevated != 0
}

pub fn console_process_count() -> Option<u32> {
    let mut one = [0u32; 1];
    match unsafe { GetConsoleProcessList(&mut one) } {
        0 => None,
        count => Some(count),
    }
}

pub fn is_preinstallation_environment() -> bool {
    let key = wide("SYSTEM\\CurrentControlSet\\Control\\MiniNT");
    let mut handle = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(key.as_ptr()), None, KEY_READ, &mut handle)
    };
    if status.is_ok() {
        let _ = unsafe { RegCloseKey(handle) };
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_strings_round_trip() {
        let w = wide("C:\\Windows");
        assert_eq!(*w.last().unwrap(), 0, "must be NUL-terminated for Win32");
        assert_eq!(from_wide(&w), "C:\\Windows");
    }

    #[test]
    fn from_wide_stops_at_the_nul() {
        let buf = [0x43u16, 0x3a, 0x00, 0x58, 0x58];
        assert_eq!(from_wide(&buf), "C:");
    }

    #[test]
    fn from_wide_handles_an_unterminated_buffer() {
        assert_eq!(from_wide(&[0x41u16, 0x42]), "AB");
        assert_eq!(from_wide(&[]), "");
    }

    #[test]
    fn volumes_can_be_enumerated() {
        let vols = enumerate_volume_paths().expect("volume enumeration failed");
        assert!(!vols.is_empty(), "no volumes found");
        for v in &vols {
            assert!(v.starts_with("\\\\?\\Volume{"), "unexpected volume path: {v}");
            assert!(v.ends_with('\\'), "volume path should end with a separator: {v}");
        }
    }

    #[test]
    fn logical_drives_include_a_system_drive() {
        let drives = logical_drive_letters();
        assert!(!drives.is_empty(), "no drive letters at all");
        for d in &drives {
            assert_eq!(d.len(), 2);
            assert!(d.ends_with(':'));
        }
    }

    #[test]
    fn full_windows_is_not_detected_as_winpe() {
        assert!(!is_preinstallation_environment());
    }
}
