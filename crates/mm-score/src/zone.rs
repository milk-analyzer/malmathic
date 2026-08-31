use mm_core::NormalizedPath;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Zone {
    SystemDir,
    WindowsOther,
    WindowsTemp,
    WinSxs,
    ProgramFiles,
    ProgramData,
    UserTemp,
    UserAppData,
    UserDownloads,
    UserProfile,
    RecycleBin,
    VolumeRoot,
    Other,
    Unlocated,
}

impl Zone {
    pub fn label(&self) -> &'static str {
        match self {
            Zone::SystemDir => "system directory",
            Zone::WindowsOther => "Windows directory",
            Zone::WindowsTemp => "Windows temp",
            Zone::WinSxs => "component store",
            Zone::ProgramFiles => "Program Files",
            Zone::ProgramData => "ProgramData",
            Zone::UserTemp => "user temp",
            Zone::UserAppData => "user AppData",
            Zone::UserDownloads => "user Downloads",
            Zone::UserProfile => "user profile",
            Zone::RecycleBin => "recycle bin",
            Zone::VolumeRoot => "volume root",
            Zone::Other => "elsewhere",
            Zone::Unlocated => "no location recorded",
        }
    }

    pub fn is_conventional_for_executables(&self) -> bool {
        matches!(self, Zone::SystemDir | Zone::WindowsOther | Zone::WinSxs | Zone::ProgramFiles)
    }
}

pub fn classify(path: &NormalizedPath) -> Zone {
    if !path.is_located() {
        return Zone::Unlocated;
    }
    let key = path.key();
    let segments: Vec<&str> = key.split('\\').filter(|s| !s.is_empty()).collect();

    match segments.as_slice() {
        [_only] => Zone::VolumeRoot,
        [] => Zone::VolumeRoot,

        ["windows", rest @ ..] => classify_windows(rest),
        ["users", _user, rest @ ..] => classify_user(rest),
        ["program files", ..] | ["program files (x86)", ..] => Zone::ProgramFiles,
        ["programdata", ..] => Zone::ProgramData,
        [dir, ..] if dir.starts_with("$recycle.bin") => Zone::RecycleBin,
        ["documents and settings", _user, rest @ ..] => classify_user(rest),
        _ => Zone::Other,
    }
}

pub fn is_immediately_in_a_scratch_root(path: &NormalizedPath) -> bool {
    let segments: Vec<&str> = path.key().split('\\').filter(|s| !s.is_empty()).collect();
    matches!(
        segments.as_slice(),
        [_] | ["windows", "temp", _] | ["windows", "systemtemp", _] | ["windows", "cbstemp", _]
    ) || matches!(
        segments.as_slice(),
        ["windows", "serviceprofiles", account, "appdata", "local", "temp", _]
            if matches!(*account, "localservice" | "networkservice")
    )
}

fn classify_windows(rest: &[&str]) -> Zone {
    match rest {
        ["system32", ..] | ["syswow64", ..] => Zone::SystemDir,
        ["winsxs", ..] => Zone::WinSxs,
        ["temp", ..] | ["systemtemp", ..] | ["cbstemp", ..] => Zone::WindowsTemp,
        ["serviceprofiles", account, "appdata", "local", "temp", ..]
            if matches!(*account, "localservice" | "networkservice") =>
        {
            Zone::WindowsTemp
        }
        _ => Zone::WindowsOther,
    }
}

fn classify_user(rest: &[&str]) -> Zone {
    match rest {
        ["appdata", "local", "temp", ..] => Zone::UserTemp,
        ["appdata", ..] => Zone::UserAppData,
        ["local settings", "temp", ..] => Zone::UserTemp,
        ["local settings", ..] => Zone::UserAppData,
        ["downloads", ..] => Zone::UserDownloads,
        _ => Zone::UserProfile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone_of(p: &str) -> Zone {
        classify(&NormalizedPath::parse(p).unwrap())
    }

    #[test]
    fn a_scratch_root_is_told_apart_from_a_scratch_subdirectory() {
        let at_root =
            |p: &str| is_immediately_in_a_scratch_root(&NormalizedPath::parse(p).unwrap());

        assert!(at_root("C:\\Windows\\Temp\\server.exe"));
        assert!(at_root("C:\\Windows\\SystemTemp\\payload.exe"));
        assert!(at_root("C:\\Windows\\CbsTemp\\x.exe"));
        assert!(at_root("C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp\\x.exe"));
        assert!(at_root("C:\\setup.exe"));

        assert!(!at_root(
            "C:\\Windows\\Temp\\{54106D84-F4CC-40B5-9660-909117B8066E}\\.be\\VC_redist.x64.exe"
        ));
        assert!(!at_root(
            "C:\\Windows\\Temp\\69B4930B-E838-49BC-8624-11A2CA3DF8D5\\MpRecovery.exe"
        ));
        assert!(!at_root(
            "C:\\Windows\\SystemTemp\\GoogleUpdater_chrome_Unpacker_BeginUnzipping3236_915766021\\UpdaterSetup.exe"
        ));
        assert!(!at_root(
            "C:\\Windows\\TEMP\\DBF1C200-28DD-47F3-B17F-9713A73A8B60MpCommU\\UpdatePlatform.exe"
        ));
        assert!(!at_root("C:\\Windows\\SystemTemp\\Google7860_403476743\\bin\\updater.exe"));

        assert!(!at_root("C:\\Windows\\System32\\svchost.exe"));
        assert!(!at_root("C:\\Users\\bob\\AppData\\Local\\Temp\\setup.exe"));
        assert!(!at_root("C:\\Windows\\ServiceProfiles\\Someone\\AppData\\Local\\Temp\\x.exe"));
    }

    #[test]
    fn system_directories_are_recognized() {
        assert_eq!(zone_of("C:\\Windows\\System32\\svchost.exe"), Zone::SystemDir);
        assert_eq!(zone_of("C:\\Windows\\SysWOW64\\svchost.exe"), Zone::SystemDir);
        assert_eq!(zone_of("C:\\Windows\\System32\\drivers\\etc\\hosts"), Zone::SystemDir);
    }

    #[test]
    fn windows_subregions_are_separated() {
        assert_eq!(zone_of("C:\\Windows\\WinSxS\\amd64_x\\a.dll"), Zone::WinSxs);
        assert_eq!(zone_of("C:\\Windows\\Temp\\a.exe"), Zone::WindowsTemp);
        assert_eq!(zone_of("C:\\Windows\\notepad.exe"), Zone::WindowsOther);
        assert_eq!(zone_of("C:\\Windows\\Tasks\\x"), Zone::WindowsOther);
    }

    #[test]
    fn every_system_scratch_directory_is_windows_temp() {
        for p in [
            "C:\\Windows\\Temp\\a.exe",
            "C:\\Windows\\SystemTemp\\a.exe",
            "C:\\Windows\\SystemTemp\\GoogleUpdater_chrome_Unpacker_x\\cr_1.tmp\\setup.exe",
            "C:\\Windows\\CbsTemp\\a.exe",
            "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp\\a.exe",
            "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\deep\\a.exe",
            "%SystemRoot%\\SystemTemp\\a.exe",
            "C:\\WINDOWS\\SYSTEMTEMP\\A.EXE",
        ] {
            assert_eq!(zone_of(p), Zone::WindowsTemp, "{p}");
        }
    }

    #[test]
    fn near_misses_for_the_scratch_directories_stay_ordinary() {
        for p in [
            "C:\\Windows\\SystemTemporary\\a.exe",
            "C:\\Windows\\Tempest\\a.exe",
            "C:\\Windows\\CbsTempo\\a.exe",
            "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\a.exe",
            "C:\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT",
            "C:\\Windows\\ServiceProfiles\\Impostor\\AppData\\Local\\Temp\\a.exe",
            "C:\\Windows\\ServiceProfiles\\LocalService\\Local\\Temp\\a.exe",
        ] {
            assert_eq!(zone_of(p), Zone::WindowsOther, "{p}");
        }
        assert_eq!(zone_of("C:\\Users\\LocalService\\AppData\\Local\\Temp\\a.exe"), Zone::UserTemp);
    }

    #[test]
    fn scratch_space_is_not_a_conventional_place_to_ship_software() {
        assert!(!Zone::WindowsTemp.is_conventional_for_executables());
        assert!(Zone::WindowsOther.is_conventional_for_executables());
    }

    #[test]
    fn user_temp_is_distinguished_from_other_appdata() {
        assert_eq!(zone_of("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"), Zone::UserTemp);
        assert_eq!(zone_of("C:\\Users\\bob\\AppData\\Roaming\\x.exe"), Zone::UserAppData);
        assert_eq!(zone_of("C:\\Users\\bob\\AppData\\Local\\Programs\\x.exe"), Zone::UserAppData);
        assert_eq!(zone_of("C:\\Users\\bob\\Downloads\\x.exe"), Zone::UserDownloads);
        assert_eq!(zone_of("C:\\Users\\bob\\Desktop\\x.exe"), Zone::UserProfile);
    }

    #[test]
    fn user_zones_work_for_any_profile_name() {
        for user in ["bob", "Администратор", "a.b-c_d", "Default"] {
            let p = format!("C:\\Users\\{user}\\AppData\\Local\\Temp\\x.exe");
            assert_eq!(zone_of(&p), Zone::UserTemp, "user {user}");
        }
    }

    #[test]
    fn lookalike_directories_do_not_impersonate_system_paths() {
        assert_eq!(zone_of("C:\\Users\\bob\\system32\\svchost.exe"), Zone::UserProfile);
        assert_eq!(zone_of("C:\\Users\\bob\\Windows\\System32\\x.exe"), Zone::UserProfile);
        assert_eq!(zone_of("C:\\temp\\windows\\system32\\x.exe"), Zone::Other);
        assert_eq!(zone_of("C:\\Windows\\system32_old\\x.exe"), Zone::WindowsOther);
    }

    #[test]
    fn program_directories_and_programdata() {
        assert_eq!(zone_of("C:\\Program Files\\App\\a.exe"), Zone::ProgramFiles);
        assert_eq!(zone_of("C:\\Program Files (x86)\\App\\a.exe"), Zone::ProgramFiles);
        assert_eq!(zone_of("C:\\ProgramData\\App\\a.exe"), Zone::ProgramData);
    }

    #[test]
    fn recycle_bin_and_volume_root() {
        assert_eq!(zone_of("C:\\$Recycle.Bin\\S-1-5-21-1\\$RABCDEF.exe"), Zone::RecycleBin);
        assert_eq!(zone_of("C:\\payload.exe"), Zone::VolumeRoot);
    }

    #[test]
    fn legacy_profile_paths_are_handled() {
        assert_eq!(
            zone_of("C:\\Documents and Settings\\bob\\Local Settings\\Temp\\x.exe"),
            Zone::UserTemp
        );
    }

    #[test]
    fn secondary_volumes_fall_through_to_other() {
        assert_eq!(zone_of("D:\\tools\\a.exe"), Zone::Other);
    }

    #[test]
    fn conventional_zones_are_the_ones_that_ship_software() {
        assert!(Zone::SystemDir.is_conventional_for_executables());
        assert!(Zone::ProgramFiles.is_conventional_for_executables());
        assert!(Zone::WinSxs.is_conventional_for_executables());
        assert!(!Zone::UserTemp.is_conventional_for_executables());
        assert!(!Zone::UserDownloads.is_conventional_for_executables());
        assert!(!Zone::VolumeRoot.is_conventional_for_executables());
        assert!(!Zone::WindowsTemp.is_conventional_for_executables());
    }
}
