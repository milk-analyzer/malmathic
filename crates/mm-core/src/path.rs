use std::fmt;

use crate::volume::VolumeRef;

const EXEC_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
    ".hta", ".cpl", ".ocx",
];

#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NormalizedPath {
    raw: String,
    key: String,
    located: bool,
    #[serde(default, skip_serializing_if = "is_unstated")]
    volume: VolumeRef,
}

fn is_unstated(v: &VolumeRef) -> bool {
    matches!(v, VolumeRef::Unstated)
}

impl NormalizedPath {
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim().trim_matches('"');
        if raw.is_empty() {
            return None;
        }
        let key = normalize(raw)?;
        let located = is_rooted(raw);
        let volume = volume_ref(raw);
        Some(NormalizedPath { raw: raw.to_string(), key, located, volume })
    }

    pub fn unlocated(file_name: &str) -> Option<Self> {
        let name = file_name.trim().trim_matches('"');
        if name.is_empty() || name.contains(['\\', '/']) {
            return None;
        }
        let key = normalize(name)?;
        Some(NormalizedPath {
            raw: name.to_string(),
            key,
            located: false,
            volume: VolumeRef::Unstated,
        })
    }

    #[must_use]
    pub fn rebased(&self, key: &str) -> Option<Self> {
        let mut out = Self::parse(key)?;
        out.located = self.located;
        out.volume = self.volume.clone();
        Some(out)
    }

    pub fn is_located(&self) -> bool {
        self.located
    }

    pub fn from_command_line(cmd: &str) -> Option<Self> {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return None;
        }

        let program = if let Some(rest) = cmd.strip_prefix('"') {
            rest.split('"').next()?
        } else {
            split_unquoted_program(cmd)
        };

        if !is_plausible_program(program) {
            return None;
        }
        Self::parse(program)
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn volume(&self) -> &VolumeRef {
        &self.volume
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn display_path(&self) -> &str {
        let lower = self.raw.to_ascii_lowercase();
        let bytes = self.raw.as_bytes();

        let drive_letter = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
        let plain_rooted = bytes.first() == Some(&b'\\')
            && !lower.starts_with("\\volume{")
            && !lower.starts_with("\\device\\")
            && !lower.starts_with("\\??\\")
            && !lower.starts_with("\\\\?\\");

        if drive_letter || plain_rooted {
            &self.raw
        } else {
            &self.key
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        self.key.rsplit('\\').next().filter(|s| !s.is_empty())
    }

    pub fn parent(&self) -> Option<&str> {
        let idx = self.key.rfind('\\')?;
        if idx == 0 {
            Some("\\")
        } else {
            Some(&self.key[..idx])
        }
    }

    pub fn extension(&self) -> Option<&str> {
        let name = self.file_name()?;
        let idx = name.rfind('.')?;
        Some(&name[idx..]).filter(|e| e.len() > 1)
    }

    pub fn is_executable_extension(&self) -> bool {
        self.extension().is_some_and(|e| EXEC_EXTENSIONS.contains(&e))
    }
}

pub fn name_is_executable_extension(name: &str) -> bool {
    let Some(idx) = name.rfind('.') else { return false };
    let ext = name[idx..].to_ascii_lowercase();
    ext.len() > 1 && EXEC_EXTENSIONS.contains(&ext.as_str())
}

impl fmt::Debug for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.key)
    }
}

impl fmt::Display for NormalizedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

fn split_unquoted_program(cmd: &str) -> &str {
    let rooted = is_rooted(cmd);

    if let Some(end) = earliest_executable_boundary(cmd) {
        let prefix = &cmd[..end];
        return if rooted { prefix } else { last_token(prefix) };
    }

    if rooted {
        match first_switch_gap(cmd) {
            Some(end) => &cmd[..end],
            None => cmd,
        }
    } else {
        first_token(cmd)
    }
}

fn earliest_executable_boundary(cmd: &str) -> Option<usize> {
    let lower = cmd.to_ascii_lowercase();
    let mut best: Option<usize> = None;
    for ext in EXEC_EXTENSIONS {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(ext) {
            let end = from + rel + ext.len();
            let boundary =
                lower[end..].chars().next().is_none_or(|c| c == ' ' || c == ',' || c == '\t');
            if boundary {
                best = Some(best.map_or(end, |b: usize| b.min(end)));
                break;
            }
            from = end;
        }
    }
    best
}

fn first_switch_gap(cmd: &str) -> Option<usize> {
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' || bytes[i] == b'\t' {
            let gap_start = i;
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
            if matches!(bytes.get(i), Some(b'-') | Some(b'/')) {
                return Some(gap_start);
            }
            continue;
        }
        i += 1;
    }
    None
}

fn first_token(s: &str) -> &str {
    s.split([' ', '\t']).next().unwrap_or(s)
}

fn last_token(s: &str) -> &str {
    s.rsplit([' ', '\t']).next().unwrap_or(s)
}

fn strip_namespace_prefix(s: &str) -> &str {
    for prefix in ["\\??\\", "\\\\?\\", "\\\\.\\"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest;
        }
    }
    s
}

fn is_rooted(s: &str) -> bool {
    let s = s.trim_start_matches('"');
    let bytes = s.as_bytes();
    if bytes.first() == Some(&b'\\') || bytes.first() == Some(&b'/') {
        return true;
    }
    if bytes.first() == Some(&b'%') && s[1..].contains('%') {
        return true;
    }
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_plausible_program(program: &str) -> bool {
    let program = program.trim().trim_matches('"');
    if program.is_empty() {
        return false;
    }

    let body = strip_namespace_prefix(program);
    if body.contains(['"', '|', '<', '>', '*', '?']) {
        return false;
    }

    is_rooted(program) || !program.contains([' ', '\t'])
}

fn volume_ref(raw: &str) -> VolumeRef {
    let trimmed = raw.trim().trim_matches('"');
    let s = trimmed.replace('/', "\\").to_lowercase();
    let s = strip_namespace_prefix(&s).to_string();

    let body = s.strip_prefix("globalroot\\").unwrap_or(&s);
    let body = body.strip_prefix('\\').unwrap_or(body);

    if let Some(rest) = body.strip_prefix("device\\") {
        let name = rest.split('\\').next().unwrap_or(rest);
        if !name.is_empty() {
            return VolumeRef::Device(name.to_string());
        }
        return VolumeRef::Unstated;
    }
    if let Some(rest) = body.strip_prefix("volume{") {
        if let Some(idx) = rest.find('}') {
            let token = &rest[..idx];
            if !token.is_empty() {
                return VolumeRef::Token(token.to_string());
            }
        }
        return VolumeRef::Unstated;
    }

    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return VolumeRef::Letter(bytes[0] as char);
    }

    VolumeRef::Unstated
}

fn normalize(raw: &str) -> Option<String> {
    let mut s = raw.replace('/', "\\").to_lowercase();

    for prefix in ["\\??\\", "\\\\?\\", "\\\\.\\"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
            break;
        }
    }

    s = strip_volume_prefix(&s);

    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        s = s[2..].to_string();
    }

    s = expand_known_env(&s);

    let mut out = String::with_capacity(s.len() + 1);
    for segment in s.split('\\') {
        match canonical_segment(segment) {
            Segment::Skip => {}
            Segment::Up => {
                if let Some(idx) = out.rfind('\\') {
                    out.truncate(idx);
                }
            }
            Segment::Name(name) => {
                out.push('\\');
                out.push_str(name);
            }
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

enum Segment<'a> {
    Skip,
    Up,
    Name(&'a str),
}

fn canonical_segment(segment: &str) -> Segment<'_> {
    if segment.is_empty() || segment == "." {
        return Segment::Skip;
    }
    if segment == ".." {
        return Segment::Up;
    }
    let trimmed = segment.trim_end_matches([' ', '.']);
    Segment::Name(if trimmed.is_empty() { segment } else { trimmed })
}

fn strip_volume_prefix(s: &str) -> String {
    let body = s.strip_prefix("globalroot\\").unwrap_or(s);
    let body = body.strip_prefix('\\').unwrap_or(body);

    if let Some(rest) = body.strip_prefix("device\\") {
        if let Some(idx) = rest.find('\\') {
            return rest[idx..].to_string();
        }
        return "\\".to_string();
    }
    if let Some(rest) = body.strip_prefix("volume{") {
        if let Some(idx) = rest.find('}') {
            return rest[idx + 1..].to_string();
        }
        return "\\".to_string();
    }
    s.to_string()
}

fn expand_known_env(s: &str) -> String {
    const FIXED: &[(&str, &str)] = &[
        ("%systemroot%", "\\windows"),
        ("%windir%", "\\windows"),
        ("%systemdrive%", ""),
        ("%programfiles%", "\\program files"),
        ("%programfiles(x86)%", "\\program files (x86)"),
        ("%commonprogramfiles%", "\\program files\\common files"),
        ("%commonprogramfiles(x86)%", "\\program files (x86)\\common files"),
        ("%programdata%", "\\programdata"),
        ("%allusersprofile%", "\\programdata"),
    ];
    let mut out = s.to_string();
    for (token, replacement) in FIXED {
        if out.contains(token) {
            out = out.replace(token, replacement);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_path_states_no_location() {
        for raw in [
            "Microsoft\\Windows\\IECompatUaCache",
            "bin\\tool.exe",
            "..\\..\\up.exe",
            "sub/dir/x.exe",
        ] {
            let p = NormalizedPath::parse(raw).expect(raw);
            assert!(!p.is_located(), "relative, so it states no location: {raw}");
        }
    }

    #[test]
    fn every_rooted_spelling_is_still_located() {
        for raw in [
            "C:\\Windows\\System32\\svchost.exe",
            "\\Users\\bob\\x.exe",
            "\\??\\C:\\Users\\bob\\x.exe",
            "\\\\?\\C:\\Users\\bob\\x.exe",
            "\\Device\\HarddiskVolume3\\Users\\bob\\x.exe",
            "\\VOLUME{01d7a1b2c3d4e5f6}\\WINDOWS\\X.EXE",
            "%SystemRoot%\\System32\\svchost.exe",
            "%ProgramFiles%\\App\\x.exe",
            "/users/bob/x.exe",
            "\"C:\\Program Files\\App\\a b.exe\"",
        ] {
            let p = NormalizedPath::parse(raw).expect(raw);
            assert!(p.is_located(), "rooted, so it states a location: {raw}");
        }
        assert!(!NormalizedPath::parse("explorer.exe").unwrap().is_located());
    }

    #[test]
    fn a_drive_letter_survives_as_an_identity() {
        let p = NormalizedPath::parse("W:\\TRASH\\Downloads\\x.exe").unwrap();
        assert_eq!(p.key(), "\\trash\\downloads\\x.exe");
        assert_eq!(p.volume(), &VolumeRef::Letter('w'));
    }

    #[test]
    fn every_namespace_spelling_of_a_letter_is_recognised() {
        for raw in ["W:\\x.exe", "\\??\\W:\\x.exe", "\\\\?\\w:\\x.exe", "w:/x.exe", "\"W:\\x.exe\""]
        {
            let p = NormalizedPath::parse(raw).expect(raw);
            assert_eq!(p.volume(), &VolumeRef::Letter('w'), "input: {raw}");
        }
    }

    #[test]
    fn device_and_volume_tokens_keep_their_names() {
        let p = NormalizedPath::parse("\\Device\\HarddiskVolume3\\Users\\bob\\x.exe").unwrap();
        assert_eq!(p.volume(), &VolumeRef::Device("harddiskvolume3".into()));

        let p = NormalizedPath::parse("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume7\\x.exe").unwrap();
        assert_eq!(p.volume(), &VolumeRef::Device("harddiskvolume7".into()));

        let p = NormalizedPath::parse("\\VOLUME{01d7a1b2c3d4e5f6}\\WINDOWS\\X.EXE").unwrap();
        assert_eq!(p.volume(), &VolumeRef::Token("01d7a1b2c3d4e5f6".into()));

        let p = NormalizedPath::parse("\\\\?\\Volume{0b1c2d3e-4f50-6172}\\x.exe").unwrap();
        assert_eq!(p.volume(), &VolumeRef::Token("0b1c2d3e-4f50-6172".into()));
    }

    #[test]
    fn the_common_spellings_state_no_volume() {
        for raw in [
            "\\Users\\bob\\AppData\\Roaming\\x.exe",
            "%SystemRoot%\\System32\\svchost.exe",
            "%SystemDrive%\\Temp\\x.exe",
            "%ProgramFiles%\\App\\x.exe",
            "explorer.exe",
        ] {
            let p = NormalizedPath::parse(raw).expect(raw);
            assert_eq!(p.volume(), &VolumeRef::Unstated, "input: {raw}");
        }
        assert_eq!(NormalizedPath::unlocated("STEAM.EXE").unwrap().volume(), &VolumeRef::Unstated);
    }

    #[test]
    fn a_command_line_carries_its_programs_volume() {
        let p = NormalizedPath::from_command_line("\"E:\\tools\\a b.exe\" --silent").unwrap();
        assert_eq!(p.volume(), &VolumeRef::Letter('e'));
        let p = NormalizedPath::from_command_line("C:\\Windows\\System32\\cmd.exe /c x").unwrap();
        assert_eq!(p.volume(), &VolumeRef::Letter('c'));
    }

    #[test]
    fn rebasing_through_a_junction_keeps_the_volume() {
        let p = NormalizedPath::parse("W:\\javapath\\java.exe").unwrap();
        let r = p.rebased("\\javapath_target_2175890\\java.exe").unwrap();
        assert_eq!(r.key(), "\\javapath_target_2175890\\java.exe");
        assert_eq!(r.volume(), &VolumeRef::Letter('w'));
    }

    #[test]
    fn an_older_report_deserializes_as_stating_no_volume() {
        let json = r#"{"raw":"C:\\x.exe","key":"\\x.exe","located":true}"#;
        let p: NormalizedPath = serde_json::from_str(json).unwrap();
        assert_eq!(p.key(), "\\x.exe");
        assert_eq!(p.volume(), &VolumeRef::Unstated);
    }

    #[test]
    fn all_artifact_spellings_agree() {
        let expected = "\\users\\bob\\appdata\\roaming\\x.exe";
        let inputs = [
            "\\Users\\bob\\AppData\\Roaming\\x.exe",
            "c:\\users\\bob\\appdata\\roaming\\x.exe",
            "\\??\\C:\\Users\\bob\\AppData\\Roaming\\x.exe",
            "\\VOLUME{01d7a1b2c3d4e5f6}\\USERS\\BOB\\APPDATA\\ROAMING\\X.EXE",
            "\\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Roaming\\x.exe",
            "\\\\?\\C:\\Users\\bob\\AppData\\Roaming\\x.exe",
        ];
        for input in inputs {
            let p = NormalizedPath::parse(input).expect(input);
            assert_eq!(p.key(), expected, "input: {input}");
        }
    }

    #[test]
    fn command_lines_lose_their_arguments() {
        let expected = "\\users\\bob\\appdata\\roaming\\x.exe";
        let inputs = [
            "\"C:\\Users\\bob\\AppData\\Roaming\\x.exe\" --silent",
            "C:\\Users\\bob\\AppData\\Roaming\\x.exe --silent",
            "C:\\Users\\bob\\AppData\\Roaming\\x.exe -k netsvcs",
            "C:\\Users\\bob\\AppData\\Roaming\\x.exe /S",
            "\"C:\\Users\\bob\\AppData\\Roaming\\x.exe\"",
            "C:\\Users\\bob\\AppData\\Roaming\\x.exe",
        ];
        for input in inputs {
            let p = NormalizedPath::from_command_line(input).expect(input);
            assert_eq!(p.key(), expected, "input: {input}");
        }
    }

    #[test]
    fn quoted_paths_with_spaces_survive() {
        let p =
            NormalizedPath::from_command_line("\"C:\\Program Files\\Thing\\a b.exe\" -q").unwrap();
        assert_eq!(p.key(), "\\program files\\thing\\a b.exe");
    }

    #[test]
    fn unquoted_path_with_spaces_uses_extension_boundary() {
        let p = NormalizedPath::from_command_line("C:\\Program Files\\Thing\\a b.exe -q").unwrap();
        assert_eq!(p.key(), "\\program files\\thing\\a b.exe");
    }

    #[test]
    fn dll_before_comma_is_the_program() {
        let p = NormalizedPath::from_command_line("C:\\Windows\\System32\\rundll32.exe").unwrap();
        assert_eq!(p.key(), "\\windows\\system32\\rundll32.exe");

        let p = NormalizedPath::from_command_line("c:\\temp\\evil.dll,DllMain").unwrap();
        assert_eq!(p.key(), "\\temp\\evil.dll");
    }

    #[test]
    fn a_stock_runonce_command_line_yields_its_program_and_nothing_else() {
        let stock = r#"REG ADD "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f"#;
        let got = NormalizedPath::from_command_line(stock).unwrap();
        assert_eq!(got.key(), "\\reg");
    }

    #[test]
    fn an_unrooted_command_line_never_fabricates_a_multi_word_path() {
        for cmd in [
            r#"REG ADD "HKCU\Software\X" /v Y /f"#,
            "cmd /c del somefile",
            "powershell -enc AAAA",
            "schtasks /create /tn x /tr something",
            "wscript //B //Nologo script.vbs",
            "rundll32 shell32.dll,Control_RunDLL desk.cpl",
        ] {
            if let Some(path) = NormalizedPath::from_command_line(cmd) {
                assert!(
                    !path.key().contains(' '),
                    "fabricated a multi-word path {:?} from: {cmd}",
                    path.key()
                );
            }
        }
    }

    #[test]
    fn values_that_cannot_be_paths_are_refused() {
        for cmd in [r#""C:\a\b.exe" | more"#, "C:\\a\\b* /x", "<redirect"] {
            let got = NormalizedPath::from_command_line(cmd);
            if let Some(p) = got {
                assert!(
                    !p.key().contains(['|', '*', '<']),
                    "kept an impossible path: {:?}",
                    p.key()
                );
            }
        }
    }

    #[test]
    fn real_persistence_values_still_yield_their_path() {
        let cases = [
            (
                r#""C:\Program Files\Vendor\App\updater.exe" /silent"#,
                "\\program files\\vendor\\app\\updater.exe",
            ),
            ("C:\\Windows\\System32\\svchost.exe -k netsvcs", "\\windows\\system32\\svchost.exe"),
            (
                "%SystemRoot%\\System32\\rundll32.exe shell32.dll,Control_RunDLL",
                "\\windows\\system32\\rundll32.exe",
            ),
            ("\\??\\C:\\Windows\\System32\\drivers\\x.sys", "\\windows\\system32\\drivers\\x.sys"),
            ("notepad.exe", "\\notepad.exe"),
        ];
        for (cmd, expected) in cases {
            let got = NormalizedPath::from_command_line(cmd).unwrap_or_else(|| panic!("{cmd}"));
            assert_eq!(got.key(), expected, "input: {cmd}");
        }
    }

    #[test]
    fn an_unrooted_command_line_yields_only_its_program_token() {
        let p = NormalizedPath::from_command_line("rundll32 evil.dll,Start").unwrap();
        assert_eq!(p.key(), "\\evil.dll");
    }

    #[test]
    fn a_long_whitespace_run_does_not_take_quadratic_time() {
        let hostile = format!("REG{}ADD something", " ".repeat(262_144));
        let start = std::time::Instant::now();
        let _ = NormalizedPath::from_command_line(&hostile);
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 500, "took {elapsed:?}; the scan is not linear");
    }

    #[test]
    fn rootedness_is_recognized_in_every_spelling() {
        for rooted in ["C:\\x", "\\x", "\\??\\C:\\x", "\\\\?\\C:\\x", "%SystemRoot%\\x", "/x"] {
            assert!(is_rooted(rooted), "{rooted} should be rooted");
        }
        for bare in ["x", "notepad.exe", "REG", "%incomplete", ""] {
            assert!(!is_rooted(bare), "{bare} should not be rooted");
        }
    }

    #[test]
    fn fixed_environment_tokens_expand() {
        let p = NormalizedPath::parse("%SystemRoot%\\System32\\svchost.exe").unwrap();
        assert_eq!(p.key(), "\\windows\\system32\\svchost.exe");
        let p = NormalizedPath::parse("%SystemDrive%\\Users\\bob\\x.exe").unwrap();
        assert_eq!(p.key(), "\\users\\bob\\x.exe");

        let p = NormalizedPath::parse("%CommonProgramFiles%\\Microsoft Shared\\Ink\\InkObj.dll")
            .unwrap();
        assert_eq!(p.key(), "\\program files\\common files\\microsoft shared\\ink\\inkobj.dll");
        let p =
            NormalizedPath::parse("%CommonProgramFiles(x86)%\\System\\ado\\msadrh15.dll").unwrap();
        assert_eq!(p.key(), "\\program files (x86)\\common files\\system\\ado\\msadrh15.dll");

        let p = NormalizedPath::parse("%ProgramFiles%\\Vendor\\app.exe").unwrap();
        assert_eq!(p.key(), "\\program files\\vendor\\app.exe");
        let p = NormalizedPath::parse("%ProgramFiles(x86)%\\Vendor\\app.exe").unwrap();
        assert_eq!(p.key(), "\\program files (x86)\\vendor\\app.exe");
    }

    #[test]
    fn per_user_tokens_are_left_unexpanded() {
        let p = NormalizedPath::parse("%APPDATA%\\x.exe").unwrap();
        assert_eq!(p.key(), "\\%appdata%\\x.exe");
    }

    #[test]
    fn separators_collapse_and_normalize() {
        let p = NormalizedPath::parse("C:\\\\Users//bob\\\\x.exe").unwrap();
        assert_eq!(p.key(), "\\users\\bob\\x.exe");
        let p = NormalizedPath::parse("C:\\Users\\bob\\").unwrap();
        assert_eq!(p.key(), "\\users\\bob");
    }

    #[test]
    fn a_relative_segment_is_collapsed_out_of_the_key() {
        let seen =
            NormalizedPath::parse("C:\\Program Files\\Git\\bin\\..\\usr\\bin\\bash.exe").unwrap();
        let walked = NormalizedPath::parse("\\Program Files\\Git\\usr\\bin\\bash.exe").unwrap();
        assert_eq!(seen.key(), walked.key());
        assert_eq!(seen.key(), "\\program files\\git\\usr\\bin\\bash.exe");
    }

    #[test]
    fn dot_and_dotdot_and_trailing_noise_all_canonicalise() {
        let expected = "\\users\\bob\\x.exe";
        for input in [
            "C:\\Users\\bob\\.\\x.exe",
            "C:\\Users\\bob\\sub\\..\\x.exe",
            "C:\\Users\\.\\bob\\sub\\subsub\\..\\..\\x.exe",
            "C:\\Users \\bob.\\x.exe",
            "C:\\Users\\bob\\x.exe.",
            "C:\\Users\\bob\\x.exe ",
            "C:\\\\Users\\\\bob\\\\x.exe",
        ] {
            let p = NormalizedPath::parse(input).unwrap_or_else(|| panic!("{input}"));
            assert_eq!(p.key(), expected, "input: {input}");
        }
    }

    #[test]
    fn a_relative_segment_cannot_escape_the_volume_root() {
        let p = NormalizedPath::parse("C:\\..\\..\\windows\\x.exe").unwrap();
        assert_eq!(p.key(), "\\windows\\x.exe");
        assert!(NormalizedPath::parse("C:\\..").is_none());
        assert!(NormalizedPath::parse("C:\\users\\..").is_none());
    }

    #[test]
    fn a_segment_of_pure_dots_is_kept_rather_than_deleted() {
        let p = NormalizedPath::parse("C:\\users\\...\\x.exe").unwrap();
        assert_eq!(p.key(), "\\users\\...\\x.exe");
    }

    #[test]
    fn volume_names_behind_a_namespace_prefix_are_stripped() {
        let expected = "\\windows\\system32\\x.exe";
        for input in [
            "\\\\?\\Volume{01d7a1b2-c3d4-e5f6-0708-090a0b0c0d0e}\\Windows\\System32\\x.exe",
            "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\Windows\\System32\\x.exe",
            "\\Device\\HarddiskVolume3\\Windows\\System32\\x.exe",
            "\\??\\C:\\Windows\\System32\\x.exe",
        ] {
            let p = NormalizedPath::parse(input).unwrap_or_else(|| panic!("{input}"));
            assert_eq!(p.key(), expected, "input: {input}");
        }
    }

    #[test]
    fn components_split_correctly() {
        let p = NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\x.exe").unwrap();
        assert_eq!(p.file_name(), Some("x.exe"));
        assert_eq!(p.parent(), Some("\\users\\bob\\appdata\\roaming"));
        assert_eq!(p.extension(), Some(".exe"));
        assert!(p.is_executable_extension());

        let p = NormalizedPath::parse("C:\\notes.txt").unwrap();
        assert_eq!(p.parent(), Some("\\"));
        assert!(!p.is_executable_extension());
    }

    #[test]
    fn empty_and_root_only_inputs_are_rejected() {
        assert!(NormalizedPath::parse("").is_none());
        assert!(NormalizedPath::parse("   ").is_none());
        assert!(NormalizedPath::parse("\\??\\").is_none());
        assert!(NormalizedPath::parse("C:\\").is_none());
        assert!(NormalizedPath::from_command_line("").is_none());
    }

    #[test]
    fn raw_is_preserved_for_display() {
        let p = NormalizedPath::parse("\\??\\C:\\Users\\Bob\\X.exe").unwrap();
        assert_eq!(p.raw(), "\\??\\C:\\Users\\Bob\\X.exe");
        assert_eq!(p.key(), "\\users\\bob\\x.exe");
    }
}
