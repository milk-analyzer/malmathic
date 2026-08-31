use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind, PersistenceKind};

use crate::Harvested;

pub const MAX_LINK_BYTES: usize = 1 << 20;

const MAX_STRING_CHARS: usize = 1 << 16;

const MAX_EXTRA_BLOCKS: usize = 64;

const MAX_LINKINFO_STRING: usize = 4096;

const HEADER_SIZE: usize = 0x4C;

const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

mod flag {
    pub const HAS_TARGET_ID_LIST: u32 = 0x0000_0001;
    pub const HAS_LINK_INFO: u32 = 0x0000_0002;
    pub const HAS_NAME: u32 = 0x0000_0004;
    pub const HAS_RELATIVE_PATH: u32 = 0x0000_0008;
    pub const HAS_WORKING_DIR: u32 = 0x0000_0010;
    pub const HAS_ARGUMENTS: u32 = 0x0000_0020;
    pub const HAS_ICON_LOCATION: u32 = 0x0000_0040;
    pub const IS_UNICODE: u32 = 0x0000_0080;
    pub const FORCE_NO_LINK_INFO: u32 = 0x0000_0100;
}

mod link_info {
    pub const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x0000_0001;
    pub const COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX: u32 = 0x0000_0002;
}

const ENVIRONMENT_VARIABLE_BLOCK: u32 = 0xA000_0001;
const ENV_BLOCK_SIZE: u32 = 0x0000_0314;
const ENV_ANSI_LEN: usize = 260;
const ENV_UNICODE_BYTES: usize = 520;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    pub directory: String,
    pub name: String,
    pub profile: Option<String>,
}

impl Location {
    pub fn full_path(&self) -> String {
        format!("{}\\{}", self.directory.trim_end_matches('\\'), self.name)
    }

    pub fn scope(&self) -> String {
        match &self.profile {
            Some(profile) => {
                let user = profile.rsplit('\\').next().unwrap_or(profile.as_str());
                format!("Startup folder ({user})")
            }
            None => "Startup folder (all users)".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Entry {
    Link {
        observation: Observation,
        target: NormalizedPath,
        arguments: Option<String>,
        origin: TargetOrigin,
    },
    UnreadableLink {
        reason: &'static str,
    },
    File {
        observation: Observation,
        path: NormalizedPath,
    },
    Ignored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetOrigin {
    LocalBasePath,
    RelativePath,
    EnvironmentBlock,
}

impl TargetOrigin {
    pub fn label(&self) -> &'static str {
        match self {
            TargetOrigin::LocalBasePath => "LinkInfo local path",
            TargetOrigin::RelativePath => "relative path",
            TargetOrigin::EnvironmentBlock => "environment block",
        }
    }
}

pub fn harvest(at: &Location, bytes: &[u8]) -> Entry {
    if is_folder_metadata(&at.name) {
        return Entry::Ignored;
    }

    if at.name.to_ascii_lowercase().ends_with(".lnk") {
        return harvest_link(at, bytes);
    }

    let full = at.full_path();
    match NormalizedPath::parse(&full) {
        Some(path) => Entry::File { observation: observation_for(at, path.clone(), &full), path },
        None => Entry::Ignored,
    }
}

pub fn observations(entries: &[Entry]) -> Harvested {
    entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Link { observation, .. } | Entry::File { observation, .. } => {
                Some(observation.clone())
            }
            _ => None,
        })
        .collect()
}

fn harvest_link(at: &Location, bytes: &[u8]) -> Entry {
    let link = match parse(bytes) {
        Ok(link) => link,
        Err(reason) => return Entry::UnreadableLink { reason },
    };

    let Some((raw_target, origin)) = link.resolve(at) else {
        return Entry::UnreadableLink { reason: "the link names no local path we can resolve" };
    };

    let Some(target) = NormalizedPath::parse(&raw_target) else {
        return Entry::UnreadableLink { reason: "the link's target does not normalize to a path" };
    };

    let mut raw_value = format!("{} -> {raw_target}", at.name);
    if let Some(arguments) = &link.arguments {
        raw_value.push(' ');
        raw_value.push_str(arguments);
    }

    Entry::Link {
        observation: observation_for(at, target.clone(), &raw_value),
        target,
        arguments: link.arguments.clone(),
        origin,
    }
}

fn observation_for(at: &Location, path: NormalizedPath, raw_value: &str) -> Observation {
    Observation::about_path(
        ArtifactSource::StartupFolder { file: at.full_path() },
        path,
        ObservationKind::Persistence {
            kind: PersistenceKind::StartupFolder,
            raw_value: sanitize(raw_value),
        },
    )
}

fn is_folder_metadata(name: &str) -> bool {
    name.eq_ignore_ascii_case("desktop.ini") || name.eq_ignore_ascii_case("thumbs.db")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub local_base_path: Option<String>,
    pub relative_path: Option<String>,
    pub working_dir: Option<String>,
    pub arguments: Option<String>,
    pub environment_target: Option<String>,
    pub network_only: bool,
}

impl Link {
    pub fn resolve(&self, at: &Location) -> Option<(String, TargetOrigin)> {
        if let Some(local) = &self.local_base_path {
            return Some((local.clone(), TargetOrigin::LocalBasePath));
        }
        if let Some(relative) = &self.relative_path {
            if let Some(joined) = join_relative(&at.directory, relative) {
                return Some((joined, TargetOrigin::RelativePath));
            }
        }
        if let Some(env) = &self.environment_target {
            if let Some(expanded) = expand_profile_tokens(env, at.profile.as_deref()) {
                return Some((expanded, TargetOrigin::EnvironmentBlock));
            }
        }
        None
    }
}

pub fn parse(bytes: &[u8]) -> Result<Link, &'static str> {
    if bytes.len() > MAX_LINK_BYTES {
        return Err("larger than any shell link");
    }
    if bytes.len() < HEADER_SIZE {
        return Err("shorter than a shell link header");
    }
    if u32_at(bytes, 0) != Some(HEADER_SIZE as u32) {
        return Err("header size is not 0x4C");
    }
    if bytes.get(4..20) != Some(&LINK_CLSID[..]) {
        return Err("not a shell link (class id mismatch)");
    }

    let flags = u32_at(bytes, 0x14).ok_or("truncated header")?;
    let unicode = flags & flag::IS_UNICODE != 0;

    let mut at = HEADER_SIZE;
    let mut link = Link::default();

    if flags & flag::HAS_TARGET_ID_LIST != 0 {
        let size = u16_at(bytes, at).ok_or("truncated LinkTargetIDList size")? as usize;
        at = at.checked_add(2).and_then(|a| a.checked_add(size)).ok_or("IDList size overflows")?;
        if at > bytes.len() {
            return Err("LinkTargetIDList runs past the end of the link");
        }
    }

    if flags & flag::HAS_LINK_INFO != 0 {
        let size = u32_at(bytes, at).ok_or("truncated LinkInfo size")? as usize;
        if size < 0x1C {
            return Err("LinkInfo is shorter than its own header");
        }
        let end = at.checked_add(size).ok_or("LinkInfo size overflows")?;
        if end > bytes.len() {
            return Err("LinkInfo runs past the end of the link");
        }
        if flags & flag::FORCE_NO_LINK_INFO == 0 {
            let (local, network_only) = parse_link_info(&bytes[at..end]);
            link.local_base_path = local;
            link.network_only = network_only;
        }
        at = end;
    }

    for (bit, slot) in [
        (flag::HAS_NAME, 9usize),
        (flag::HAS_RELATIVE_PATH, 0),
        (flag::HAS_WORKING_DIR, 1),
        (flag::HAS_ARGUMENTS, 2),
        (flag::HAS_ICON_LOCATION, 9),
    ] {
        if flags & bit == 0 {
            continue;
        }
        let (text, next) = read_string_data(bytes, at, unicode)?;
        at = next;
        match slot {
            0 => link.relative_path = non_empty(text),
            1 => link.working_dir = non_empty(text),
            2 => link.arguments = non_empty(text),
            _ => {}
        }
    }

    link.environment_target = parse_extra_data(bytes, at);

    Ok(link)
}

fn parse_link_info(data: &[u8]) -> (Option<String>, bool) {
    let Some(header_size) = u32_at(data, 0x04) else { return (None, false) };
    let Some(info_flags) = u32_at(data, 0x08) else { return (None, false) };

    let has_local = info_flags & link_info::VOLUME_ID_AND_LOCAL_BASE_PATH != 0;
    let has_network = info_flags & link_info::COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX != 0;

    if !has_local {
        return (None, has_network);
    }

    let wide = header_size >= 0x24;

    let string_at = |wide_offset: usize, ansi_offset: usize| -> Option<String> {
        if wide {
            if let Some(o) = u32_at(data, wide_offset).filter(|o| *o != 0) {
                return unicode_string(data, o as usize);
            }
        }
        u32_at(data, ansi_offset).filter(|o| *o != 0).and_then(|o| ansi_string(data, o as usize))
    };

    let base = string_at(0x1C, 0x10);
    let suffix = string_at(0x20, 0x18);

    let mut path = match base {
        Some(base) if !base.is_empty() => base,
        _ => return (None, has_network),
    };
    if let Some(suffix) = suffix {
        if !suffix.is_empty() {
            if !path.ends_with('\\') && !suffix.starts_with('\\') {
                path.push('\\');
            }
            path.push_str(&suffix);
        }
    }
    (Some(path), has_network)
}

fn read_string_data(
    bytes: &[u8],
    at: usize,
    unicode: bool,
) -> Result<(String, usize), &'static str> {
    let count = u16_at(bytes, at).ok_or("truncated StringData count")? as usize;
    let start = at.checked_add(2).ok_or("StringData offset overflows")?;
    let width = if unicode { 2 } else { 1 };
    let len = count.min(MAX_STRING_CHARS).checked_mul(width).ok_or("StringData overflows")?;
    let end = start.checked_add(len).ok_or("StringData overflows")?;
    if end > bytes.len() {
        return Err("StringData runs past the end of the link");
    }
    let raw = &bytes[start..end];
    let text = if unicode { Some(decode_utf16(raw)) } else { decode_ansi(raw) };
    Ok((text.unwrap_or_default(), end))
}

fn parse_extra_data(bytes: &[u8], mut at: usize) -> Option<String> {
    for _ in 0..MAX_EXTRA_BLOCKS {
        let size = u32_at(bytes, at)?;
        if size < 4 {
            return None;
        }
        let end = at.checked_add(size as usize)?;
        if end > bytes.len() || end <= at {
            return None;
        }
        let block = &bytes[at..end];
        if u32_at(block, 4) == Some(ENVIRONMENT_VARIABLE_BLOCK) && size == ENV_BLOCK_SIZE {
            let wide = block
                .get(8 + ENV_ANSI_LEN..8 + ENV_ANSI_LEN + ENV_UNICODE_BYTES)
                .map(nul_terminated_utf16);
            let narrow = block.get(8..8 + ENV_ANSI_LEN).and_then(nul_terminated_ansi);
            let found = wide.filter(|s| !s.is_empty()).or(narrow).filter(|s| !s.is_empty());
            if found.is_some() {
                return found;
            }
        }
        at = end;
    }
    None
}

fn join_relative(directory: &str, relative: &str) -> Option<String> {
    let relative = relative.trim();
    if relative.is_empty() {
        return None;
    }
    if relative.starts_with('\\') || relative.starts_with('%') {
        return Some(relative.to_string());
    }
    if relative.len() >= 2 && relative.as_bytes()[1] == b':' {
        return Some(relative.to_string());
    }

    let mut parts: Vec<&str> =
        directory.split('\\').filter(|segment| !segment.is_empty()).collect();
    for segment in relative.split(['\\', '/']) {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("\\{}", parts.join("\\")))
}

fn expand_profile_tokens(value: &str, profile: Option<&str>) -> Option<String> {
    let mut out = value.to_string();
    if let Some(profile) = profile {
        let profile = profile.trim_end_matches('\\');
        for (token, replacement) in [
            ("%userprofile%", profile.to_string()),
            ("%appdata%", format!("{profile}\\AppData\\Roaming")),
            ("%localappdata%", format!("{profile}\\AppData\\Local")),
        ] {
            out = replace_ignore_ascii_case(&out, token, &replacement);
        }
    }
    const KNOWN: &[&str] = &[
        "%systemroot%",
        "%windir%",
        "%systemdrive%",
        "%programfiles(x86)%",
        "%programfiles%",
        "%commonprogramfiles(x86)%",
        "%commonprogramfiles%",
        "%programdata%",
        "%allusersprofile%",
    ];
    let mut stripped = out.to_ascii_lowercase();
    for token in KNOWN {
        stripped = stripped.replace(token, "");
    }
    if stripped.contains('%') {
        return None;
    }
    Some(out)
}

pub fn resolve_directory(raw: &str, profile: Option<&str>) -> Option<String> {
    let raw = raw.trim().trim_matches('"');
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("\\\\") {
        return None;
    }
    let expanded = expand_profile_tokens(raw, profile)?;
    let path = NormalizedPath::parse(&expanded)?;
    if !path.is_located() {
        return None;
    }
    Some(path.key().to_string())
}

fn replace_ignore_ascii_case(haystack: &str, needle_lower: &str, replacement: &str) -> String {
    let lower = haystack.to_ascii_lowercase();
    if !lower.contains(needle_lower) {
        return haystack.to_string();
    }
    let mut out = String::with_capacity(haystack.len());
    let mut at = 0;
    while let Some(found) = lower[at..].find(needle_lower) {
        let start = at + found;
        out.push_str(&haystack[at..start]);
        out.push_str(replacement);
        at = start + needle_lower.len();
    }
    out.push_str(&haystack[at..]);
    out
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_le_bytes(b.get(at..end)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(b.get(at..end)?.try_into().ok()?))
}

fn unicode_string(data: &[u8], offset: usize) -> Option<String> {
    Some(nul_terminated_utf16(data.get(offset..)?))
}

fn nul_terminated_utf16(rest: &[u8]) -> String {
    let mut units = Vec::new();
    for &chunk in rest.as_chunks::<2>().0.iter().take(MAX_LINKINFO_STRING) {
        let unit = u16::from_le_bytes(chunk);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    decode_units(&units)
}

fn decode_units(units: &[u16]) -> String {
    let text: String = char::decode_utf16(units.iter().copied())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    sanitize(&text)
}

fn decode_utf16(raw: &[u8]) -> String {
    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes).collect();
    decode_units(&units)
}

fn ansi_string(data: &[u8], offset: usize) -> Option<String> {
    nul_terminated_ansi(data.get(offset..)?)
}

fn nul_terminated_ansi(rest: &[u8]) -> Option<String> {
    let end = rest.iter().take(MAX_LINKINFO_STRING).position(|&b| b == 0).unwrap_or(rest.len());
    decode_ansi(&rest[..end])
}

fn decode_ansi(raw: &[u8]) -> Option<String> {
    if raw.iter().any(|&b| b >= 0x80) {
        return None;
    }
    Some(sanitize(&String::from_utf8_lossy(raw)))
}

fn non_empty(text: String) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn sanitize(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const STARTUP_DIR: &str =
        "\\Users\\analyst\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";

    const DEEPL: &[u8] = include_bytes!("../testdata/startup/startup-deepl.lnk");
    const IDLE: &[u8] = include_bytes!("../testdata/startup/args-idle.lnk");
    const CMD: &[u8] = include_bytes!("../testdata/startup/envblock-cmd.lnk");
    const CONTROL_PANEL: &[u8] = include_bytes!("../testdata/startup/pidl-only-controlpanel.lnk");

    fn at(name: &str) -> Location {
        Location {
            directory: STARTUP_DIR.to_string(),
            name: name.to_string(),
            profile: Some("\\Users\\analyst".to_string()),
        }
    }

    fn target_of(entry: &Entry) -> String {
        match entry {
            Entry::Link { target, .. } | Entry::File { path: target, .. } => {
                target.key().to_string()
            }
            other => panic!("expected a resolved entry, got {other:?}"),
        }
    }

    fn raw_value_of(entry: &Entry) -> String {
        match entry {
            Entry::Link { observation, .. } | Entry::File { observation, .. } => {
                match &observation.kind {
                    ObservationKind::Persistence { raw_value, .. } => raw_value.clone(),
                    other => panic!("expected persistence, got {other:?}"),
                }
            }
            other => panic!("expected a resolved entry, got {other:?}"),
        }
    }

    #[test]
    fn a_startup_shortcut_is_persistence_for_its_target() {
        let entry = harvest(&at("DeepL auto-start.lnk"), DEEPL);
        assert_eq!(
            target_of(&entry),
            "\\users\\analyst\\appdata\\roaming\\0install.net\\desktop-integration\\stubs\\
             1eae01f3cdb5ff0ecf683b15a60a1489573c1188cb34abc205fcf7a924b4e54d\\auto-start.exe"
                .replace(['\n', ' '], "")
        );
        let Entry::Link { observation, origin, .. } = &entry else {
            panic!("expected a link");
        };
        assert_eq!(*origin, TargetOrigin::LocalBasePath);
        assert!(matches!(
            observation.kind,
            ObservationKind::Persistence { kind: PersistenceKind::StartupFolder, .. }
        ));
        assert_eq!(
            observation.source,
            ArtifactSource::StartupFolder { file: format!("{STARTUP_DIR}\\DeepL auto-start.lnk") }
        );
    }

    #[test]
    fn an_executable_in_the_folder_is_persistence_for_itself() {
        let entry = harvest(&at("svcupdate.exe"), &[]);
        assert_eq!(target_of(&entry), format!("{STARTUP_DIR}\\svcupdate.exe").to_ascii_lowercase());
        assert!(matches!(entry, Entry::File { .. }));
    }

    #[test]
    fn a_link_to_a_missing_file_still_claims_the_persistence() {
        let entry = harvest(&at("DeepL auto-start.lnk"), DEEPL);
        assert!(matches!(entry, Entry::Link { .. }));
        assert_eq!(observations(&[entry]).len(), 1);
    }

    #[test]
    fn no_stray_character_is_appended_to_a_resolved_target() {
        for (name, bytes) in [("DeepL auto-start.lnk", DEEPL), ("IDLE.lnk", IDLE)] {
            let key = target_of(&harvest(&at(name), bytes));
            assert!(
                key.ends_with(".exe"),
                "{name} resolved to {key}, which does not end at the executable"
            );
        }
    }

    #[test]
    fn command_line_arguments_are_captured_and_reported() {
        let entry = harvest(&at("IDLE.lnk"), IDLE);
        let Entry::Link { arguments, .. } = &entry else { panic!("expected a link") };
        let arguments = arguments.as_deref().expect("IDLE passes idle.pyw as an argument");
        assert!(arguments.to_ascii_lowercase().contains("idle.pyw"), "{arguments}");
        assert!(raw_value_of(&entry).to_ascii_lowercase().contains("idle.pyw"));
    }

    #[test]
    fn the_environment_block_resolves_a_link_with_no_link_info() {
        let entry = harvest(&at("Command Prompt.lnk"), CMD);
        let Entry::Link { origin, .. } = &entry else { panic!("expected a link") };
        assert_eq!(*origin, TargetOrigin::EnvironmentBlock);
        assert_eq!(target_of(&entry), "\\windows\\system32\\cmd.exe");
    }

    #[test]
    fn a_link_that_names_no_file_is_unknown() {
        let entry = harvest(&at("Control Panel.lnk"), CONTROL_PANEL);
        assert!(matches!(entry, Entry::UnreadableLink { .. }), "{entry:?}");
        assert!(observations(&[entry]).is_empty());
    }

    #[test]
    fn folder_metadata_is_not_a_startup_entry() {
        assert!(matches!(harvest(&at("desktop.ini"), &[]), Entry::Ignored));
        assert!(matches!(harvest(&at("Desktop.INI"), &[]), Entry::Ignored));
    }

    #[test]
    fn every_truncation_of_a_real_link_is_handled() {
        for bytes in [DEEPL, IDLE, CMD, CONTROL_PANEL] {
            for cut in 0..bytes.len() {
                let entry = harvest(&at("x.lnk"), &bytes[..cut]);
                if let Entry::Link { target, .. } = entry {
                    assert!(target.key().starts_with('\\'), "{}", target.key());
                }
            }
        }
    }

    #[test]
    fn corruption_anywhere_in_a_link_is_handled() {
        let mut damaged = CMD.to_vec();
        for i in 0..damaged.len() {
            let original = damaged[i];
            for flip in [0x00u8, 0xFF, 0x80] {
                damaged[i] = flip;
                let _ = harvest(&at("x.lnk"), &damaged);
            }
            damaged[i] = original;
        }
    }

    #[test]
    fn a_file_that_is_not_a_shell_link_is_unknown() {
        assert!(matches!(
            harvest(&at("x.lnk"), b"MZ\x90\x00this is a PE, not a shortcut"),
            Entry::UnreadableLink { .. }
        ));
        assert!(matches!(harvest(&at("x.lnk"), &[]), Entry::UnreadableLink { .. }));
    }

    #[test]
    fn a_lying_length_field_does_not_resolve() {
        let mut lying = DEEPL.to_vec();
        lying[0x4C] = 0xFF;
        lying[0x4D] = 0xFF;
        assert!(matches!(harvest(&at("x.lnk"), &lying), Entry::UnreadableLink { .. }));
    }

    #[test]
    fn control_characters_are_stripped_from_reported_text() {
        let entry = harvest(&at("evil.exe\u{1b}[2J"), &[]);
        if let Entry::File { observation, .. } = entry {
            match &observation.kind {
                ObservationKind::Persistence { raw_value, .. } => {
                    assert!(!raw_value.contains('\u{1b}'), "{raw_value}")
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn a_relative_path_resolves_against_the_links_own_directory() {
        assert_eq!(
            join_relative("\\Users\\bob\\Startup", "..\\..\\evil.exe"),
            Some("\\Users\\evil.exe".to_string())
        );
        assert_eq!(
            join_relative("\\Users\\bob\\Startup", ".\\evil.exe"),
            Some("\\Users\\bob\\Startup\\evil.exe".to_string())
        );
    }

    #[test]
    fn a_relative_path_that_escapes_the_root_is_refused() {
        assert_eq!(join_relative("\\Users", "..\\..\\..\\evil.exe"), None);
    }

    #[test]
    fn the_stock_startup_value_resolves_to_the_default_folder() {
        assert_eq!(
            resolve_directory(
                "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                Some("\\Users\\bob"),
            )
            .as_deref(),
            Some(
                "\\users\\bob\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup"
            )
        );
    }

    #[test]
    fn a_redirected_startup_folder_is_followed() {
        assert_eq!(resolve_directory("C:\\Autostart", None).as_deref(), Some("\\autostart"));
        assert_eq!(
            resolve_directory("%APPDATA%\\Evil", Some("\\Users\\bob")).as_deref(),
            Some("\\users\\bob\\appdata\\roaming\\evil")
        );
    }

    #[test]
    fn a_redirect_we_cannot_follow_is_refused_rather_than_guessed() {
        assert_eq!(resolve_directory("\\\\fileserver\\logon\\startup", None), None);
        assert_eq!(resolve_directory("%OneDriveCommercial%\\Startup", None), None);
        assert_eq!(resolve_directory("   ", None), None);
        assert_eq!(resolve_directory("%APPDATA%\\Evil", None), None);
    }

    #[test]
    fn machine_wide_tokens_still_resolve() {
        assert_eq!(
            resolve_directory("%ProgramData%\\Microsoft\\Windows\\Start Menu", None).as_deref(),
            Some("\\programdata\\microsoft\\windows\\start menu")
        );
    }
}
