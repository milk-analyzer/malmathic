use std::collections::HashSet;

use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind, PersistenceKind};

use crate::{Harvested, HiveSource};

const DELETED_MARK: &str = "[deleted] ";

pub fn harvest(hive: &[u8], source: &HiveSource) -> Harvested {
    let mut out = Vec::new();
    let Some(reg) = regf::Hive::open(hive) else {
        return out;
    };
    let Some(root) = reg.root() else {
        return out;
    };

    let rules = rules_for(&reg, &root, source);
    if rules.is_empty() {
        return out;
    }

    let mut seen = HashSet::new();
    collect_live(&reg, &root, &rules, source, &mut seen, &mut out);
    if reg.exhausted() {
        log::warn!(
            "persistence: {} exhausted its walk budget; the live tree is only \
             partly read (it is self-referential or deliberately malformed)",
            source.hive_name()
        );
    }
    reg.renew_budget();
    collect_deleted(&reg, &rules, source, &mut seen, &mut out);
    reg.renew_budget();
    let already: HashSet<String> =
        out.iter().filter_map(|o| o.path.as_ref().map(|p| p.key().to_string())).collect();
    collect_deleted_values(&reg, source, &already, &mut seen, &mut out);
    if reg.exhausted() {
        log::warn!(
            "persistence: {} exhausted its walk budget recovering deleted keys; \
             the recovery pass is incomplete",
            source.hive_name()
        );
    }
    out
}

pub fn startup_redirect(hive: &[u8], source: &HiveSource) -> Option<String> {
    let (prefix, value_name) = match source {
        HiveSource::NtUser { .. } => {
            (["Software", "Microsoft", "Windows", "CurrentVersion", "Explorer"], "Startup")
        }
        HiveSource::Software => {
            (["Microsoft", "Windows", "CurrentVersion", "Explorer", ""], "Common Startup")
        }
        _ => return None,
    };
    let prefix: Vec<String> =
        prefix.iter().filter(|s| !s.is_empty()).map(|s| (*s).to_string()).collect();

    let reg = regf::Hive::open(hive)?;
    let root = reg.root()?;
    let explorer = reg.descend(&root, &prefix)?;

    for key in ["User Shell Folders", "Shell Folders"] {
        let Some(node) = reg.subkey(&explorer, key) else {
            continue;
        };
        for value in reg.values(&node, &|name| name.eq_ignore_ascii_case(value_name)) {
            for text in value_strings(value.kind, &value.data) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

pub fn system_root(hive: &[u8], source: &HiveSource) -> Option<String> {
    if !matches!(source, HiveSource::Software) {
        return None;
    }
    let reg = regf::Hive::open(hive)?;
    let root = reg.root()?;
    let path: Vec<String> =
        ["Microsoft", "Windows NT", "CurrentVersion"].iter().map(|s| (*s).to_string()).collect();
    let cv = reg.descend(&root, &path)?;

    for name in ["SystemRoot", "PathName"] {
        for value in reg.values(&cv, &|v| v.eq_ignore_ascii_case(name)) {
            for text in value_strings(value.kind, &value.data) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

pub fn mounted_devices(hive: &[u8], source: &HiveSource) -> Vec<(char, String)> {
    const MAX_LETTERS: usize = 26;

    if !matches!(source, HiveSource::System) {
        return Vec::new();
    }
    let Some(reg) = regf::Hive::open(hive) else {
        return Vec::new();
    };
    let Some(root) = reg.root() else {
        return Vec::new();
    };
    let Some(node) = reg.subkey(&root, "MountedDevices") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for value in reg.values(&node, &|name| dos_device_letter(name).is_some()) {
        if out.len() >= MAX_LETTERS {
            break;
        }
        let Some(letter) = dos_device_letter(&value.name) else {
            continue;
        };
        out.push((letter, describe_mount(&value.data)));
    }
    out
}

fn dos_device_letter(name: &str) -> Option<char> {
    let rest =
        name.strip_prefix("\\DosDevices\\").or_else(|| name.strip_prefix("\\dosdevices\\"))?;
    let mut chars = rest.chars();
    let letter = chars.next()?;
    if chars.next()? != ':' || chars.next().is_some() || !letter.is_ascii_alphabetic() {
        return None;
    }
    Some(letter)
}

fn describe_mount(data: &[u8]) -> String {
    const MBR_LEN: usize = 12;
    const DMIO: &[u8] = b"DMIO:ID:";

    if data.len() == MBR_LEN {
        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let offset = u64::from_le_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);
        return format!("MBR disk signature {signature:#010x}, partition at offset {offset}");
    }

    if let Some(guid) = data.strip_prefix(DMIO) {
        if guid.len() >= 16 {
            return format!("volume ID {}", format_guid(&guid[..16]));
        }
    }

    let text = sz(data);
    let trimmed = text.trim();
    if trimmed.len() >= 8 && trimmed.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return trimmed.to_string();
    }

    format!("{} bytes, in a form this tool does not decode", data.len())
}

fn format_guid(b: &[u8]) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

#[derive(Clone, Copy)]
enum Sel {
    All,
    Named(&'static [&'static str]),
    Default,
}

impl Sel {
    fn matches(&self, name: &str) -> bool {
        match self {
            Sel::All => true,
            Sel::Default => name.is_empty(),
            Sel::Named(names) => names.iter().any(|n| n.eq_ignore_ascii_case(name)),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Split {
    Whole,
    List,
}

struct Rule {
    prefix: Vec<String>,
    child: Option<Vec<String>>,
    sel: Sel,
    split: Split,
    kind: PersistenceKind,
    service_path: bool,
}

fn join<'a>(head: &[&'a str], tail: &[&'a str]) -> Vec<&'a str> {
    let mut v = head.to_vec();
    v.extend_from_slice(tail);
    v
}

fn rule(prefix: &[&str], sel: Sel, kind: PersistenceKind) -> Rule {
    Rule {
        prefix: prefix.iter().map(|s| (*s).to_string()).collect(),
        child: None,
        sel,
        split: Split::Whole,
        kind,
        service_path: false,
    }
}

fn rule_under(prefix: &[&str], child: &[&str], sel: Sel, kind: PersistenceKind) -> Rule {
    Rule {
        prefix: prefix.iter().map(|s| (*s).to_string()).collect(),
        child: Some(child.iter().map(|s| (*s).to_string()).collect()),
        sel,
        split: Split::Whole,
        kind,
        service_path: false,
    }
}

impl Rule {
    fn list(mut self) -> Self {
        self.split = Split::List;
        self
    }

    fn service(mut self) -> Self {
        self.service_path = true;
        self
    }

    fn wow(&self, at: usize) -> Rule {
        let mut prefix = self.prefix.clone();
        let at = at.min(prefix.len());
        prefix.insert(at, "Wow6432Node".to_string());
        Rule {
            prefix,
            child: self.child.clone(),
            sel: self.sel,
            split: self.split,
            kind: self.kind,
            service_path: self.service_path,
        }
    }
}

fn push_both(out: &mut Vec<Rule>, at: usize, r: Rule) {
    out.push(r.wow(at));
    out.push(r);
}

fn rules_for(reg: &regf::Hive<'_>, root: &regf::KeyNode<'_>, source: &HiveSource) -> Vec<Rule> {
    match source {
        HiveSource::Software => software_rules(),
        HiveSource::System => system_rules(reg, root),
        HiveSource::NtUser { .. } => ntuser_rules(),
        HiveSource::UsrClass { .. } => usrclass_rules(),
    }
}

const COM_SERVER_KEYS: &[&str] = &[
    "InprocServer32",
    "InprocServer",
    "InprocHandler32",
    "InprocHandler",
    "LocalServer32",
    "LocalServer",
];

fn software_rules() -> Vec<Rule> {
    use PersistenceKind::*;
    let cv = ["Microsoft", "Windows", "CurrentVersion"];
    let ntcv = ["Microsoft", "Windows NT", "CurrentVersion"];
    let mut v = Vec::new();

    for (leaf, kind) in [
        ("Run", RunKey),
        ("RunOnce", RunOnceKey),
        ("RunOnceEx", RunOnceKey),
        ("RunServices", RunKey),
        ("RunServicesOnce", RunOnceKey),
    ] {
        let path = join(&cv, &[leaf]);
        push_both(&mut v, 0, rule(&path, Sel::All, kind));
    }
    let once_ex = join(&cv, &["RunOnceEx"]);
    push_both(&mut v, 0, rule_under(&once_ex, &[], Sel::All, RunOnceKey));

    let pol_run = join(&cv, &["Policies", "Explorer", "Run"]);
    push_both(&mut v, 0, rule(&pol_run, Sel::All, RunKey));
    let pol_sys = join(&cv, &["Policies", "System"]);
    push_both(&mut v, 0, rule(&pol_sys, Sel::Named(&["Shell"]), WinlogonShell));

    let winlogon = join(&ntcv, &["Winlogon"]);
    push_both(&mut v, 0, rule(&winlogon, Sel::Named(&["Userinit"]), WinlogonUserinit));
    push_both(
        &mut v,
        0,
        rule(
            &winlogon,
            Sel::Named(&[
                "Shell", "Taskman", "AppSetup", "GinaDLL", "UIHost", "VMApplet", "System",
            ]),
            WinlogonShell,
        ),
    );
    let notify = join(&ntcv, &["Winlogon", "Notify"]);
    push_both(&mut v, 0, rule_under(&notify, &[], Sel::Named(&["DllName"]), WinlogonShell));

    let windows = join(&ntcv, &["Windows"]);
    push_both(&mut v, 0, rule(&windows, Sel::Named(&["AppInit_DLLs"]), AppInitDlls).list());

    let ifeo = join(&ntcv, &["Image File Execution Options"]);
    push_both(
        &mut v,
        0,
        rule_under(
            &ifeo,
            &[],
            Sel::Named(&["Debugger", "VerifierDlls"]),
            ImageFileExecutionOptions,
        ),
    );
    let spe = join(&ntcv, &["SilentProcessExit"]);
    push_both(
        &mut v,
        0,
        rule_under(&spe, &[], Sel::Named(&["MonitorProcess"]), ImageFileExecutionOptions),
    );

    for server in COM_SERVER_KEYS {
        push_both(
            &mut v,
            0,
            rule_under(&["Classes", "CLSID"], &[server], Sel::Default, PersistenceKind::ComServer),
        );
    }
    v
}

fn system_rules(reg: &regf::Hive<'_>, root: &regf::KeyNode<'_>) -> Vec<Rule> {
    use PersistenceKind::*;
    const LSA_LISTS: &[&str] =
        &["Security Packages", "Notification Packages", "Authentication Packages"];
    let mut v = Vec::new();

    for cs in control_sets(reg, root) {
        let services = [cs.as_str(), "Services"];
        v.push(rule_under(&services, &[], Sel::Named(&["ImagePath"]), Service).service());
        v.push(
            rule_under(&services, &["Parameters"], Sel::Named(&["ServiceDll"]), Service).service(),
        );

        let smgr = [cs.as_str(), "Control", "Session Manager"];
        v.push(rule(
            &smgr,
            Sel::Named(&[
                "BootExecute",
                "SetupExecute",
                "Execute",
                "S0InitialCommand",
                "PlatformExecute",
            ]),
            BootExecute,
        ));
        let appcert = [cs.as_str(), "Control", "Session Manager", "AppCertDlls"];
        v.push(rule(&appcert, Sel::All, AppInitDlls));

        let lsa = [cs.as_str(), "Control", "Lsa"];
        v.push(rule(&lsa, Sel::Named(LSA_LISTS), LsaProvider));
        let lsa_cfg = [cs.as_str(), "Control", "Lsa", "OSConfig"];
        v.push(rule(&lsa_cfg, Sel::Named(LSA_LISTS), LsaProvider));

        let sp = [cs.as_str(), "Control", "SecurityProviders"];
        v.push(rule(&sp, Sel::Named(&["SecurityProviders"]), LsaProvider).list());
    }
    v
}

fn control_sets(reg: &regf::Hive<'_>, root: &regf::KeyNode<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for off in reg.subkey_offsets(root) {
        if out.len() >= 64 {
            break;
        }
        let Some(node) = reg.key_at(off) else { continue };
        let name = node.name();
        let lower = name.to_ascii_lowercase();
        let digits = lower.strip_prefix("controlset");
        let looks_like_set = lower == "currentcontrolset"
            || digits.is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
        if looks_like_set && !out.iter().any(|e| e.eq_ignore_ascii_case(&name)) {
            out.push(name);
        }
    }
    out
}

fn ntuser_rules() -> Vec<Rule> {
    use PersistenceKind::*;
    let cv = ["Software", "Microsoft", "Windows", "CurrentVersion"];
    let ntcv = ["Software", "Microsoft", "Windows NT", "CurrentVersion"];
    let mut v = Vec::new();

    for (leaf, kind) in [
        ("Run", RunKey),
        ("RunOnce", RunOnceKey),
        ("RunOnceEx", RunOnceKey),
        ("RunServices", RunKey),
        ("RunServicesOnce", RunOnceKey),
    ] {
        let path = join(&cv, &[leaf]);
        push_both(&mut v, 1, rule(&path, Sel::All, kind));
    }
    let once_ex = join(&cv, &["RunOnceEx"]);
    push_both(&mut v, 1, rule_under(&once_ex, &[], Sel::All, RunOnceKey));

    let pol_run = join(&cv, &["Policies", "Explorer", "Run"]);
    push_both(&mut v, 1, rule(&pol_run, Sel::All, RunKey));
    let pol_sys = join(&cv, &["Policies", "System"]);
    push_both(&mut v, 1, rule(&pol_sys, Sel::Named(&["Shell"]), WinlogonShell));

    let winlogon = join(&ntcv, &["Winlogon"]);
    push_both(&mut v, 1, rule(&winlogon, Sel::Named(&["Userinit"]), WinlogonUserinit));
    push_both(&mut v, 1, rule(&winlogon, Sel::Named(&["Shell"]), WinlogonShell));

    let windows = join(&ntcv, &["Windows"]);
    push_both(&mut v, 1, rule(&windows, Sel::Named(&["Run", "Load"]), RunKey));

    v.push(rule(&["Control Panel", "Desktop"], Sel::Named(&["SCRNSAVE.EXE"]), ScreenSaver));

    for server in COM_SERVER_KEYS {
        push_both(
            &mut v,
            2,
            rule_under(&["Software", "Classes", "CLSID"], &[server], Sel::Default, ComServer),
        );
    }
    v
}

fn usrclass_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    for server in COM_SERVER_KEYS {
        push_both(
            &mut v,
            0,
            rule_under(&["CLSID"], &[server], Sel::Default, PersistenceKind::ComServer),
        );
    }
    v
}

fn collect_live(
    reg: &regf::Hive<'_>,
    root: &regf::KeyNode<'_>,
    rules: &[Rule],
    source: &HiveSource,
    seen: &mut HashSet<String>,
    out: &mut Harvested,
) {
    let mut groups: Vec<(Vec<String>, Vec<&Rule>)> = Vec::new();
    for r in rules {
        match groups.iter_mut().find(|(p, _)| segs_eq(p, &r.prefix)) {
            Some((_, members)) => members.push(r),
            None => groups.push((r.prefix.clone(), vec![r])),
        }
    }

    for (prefix, members) in &groups {
        let Some(key) = reg.descend(root, prefix) else {
            continue;
        };
        for r in members.iter().filter(|r| r.child.is_none()) {
            emit_key(reg, &key, prefix, r, source, seen, out);
        }
        if members.iter().all(|r| r.child.is_none()) {
            continue;
        }
        let mut visited: HashSet<u32> = HashSet::new();
        for off in reg.subkey_offsets(&key) {
            if !visited.insert(off) {
                continue;
            }
            let Some(child) = reg.key_at(off) else { continue };
            let name = child.name();
            for r in members.iter() {
                let Some(suffix) = r.child.as_ref() else { continue };
                let Some(target) = reg.descend(&child, suffix) else {
                    continue;
                };
                let mut path = prefix.clone();
                path.push(name.clone());
                path.extend(suffix.iter().cloned());
                emit_key(reg, &target, &path, r, source, seen, out);
            }
        }
    }
}

fn collect_deleted(
    reg: &regf::Hive<'_>,
    rules: &[Rule],
    source: &HiveSource,
    seen: &mut HashSet<String>,
    out: &mut Harvested,
) {
    let (max_depth, terminals) = deleted_filter(rules);
    for off in reg.freed_key_offsets() {
        let Some(node) = reg.key_at(off) else { continue };
        if let Some(names) = &terminals {
            if !names.contains(&node.name().to_ascii_lowercase()) {
                continue;
            }
        }
        let Some(path) = reg.key_path(&node, max_depth) else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        for r in rules {
            if rule_matches(r, &path) {
                emit_key(reg, &node, &path, r, source, seen, out);
            }
        }
    }
}

const MAX_DELETED_VALUES: usize = 64;

fn collect_deleted_values(
    reg: &regf::Hive<'_>,
    source: &HiveSource,
    already: &HashSet<String>,
    seen: &mut HashSet<String>,
    out: &mut Harvested,
) {
    let mut emitted = 0usize;
    for off in reg.freed_value_offsets() {
        if emitted >= MAX_DELETED_VALUES {
            return;
        }
        let Some((value, _allocated)) = reg.value_at(off, &|_| true) else {
            continue;
        };
        if value.data_reused {
            continue;
        }
        for piece in value_strings(value.kind, &value.data) {
            if emitted >= MAX_DELETED_VALUES {
                return;
            }
            let rewritten = rewrite_nt_prefix(&piece);
            let Some(command) = command_head(&rewritten) else {
                continue;
            };
            let Some(path) = NormalizedPath::from_command_line(command) else {
                continue;
            };
            if !path.is_located() || !path.is_executable_extension() {
                continue;
            }
            if already.contains(path.key()) {
                continue;
            }
            let dedupe = format!("deleted-value\u{1}{}\u{1}{}", value.name, path.key());
            if !seen.insert(dedupe) {
                continue;
            }
            out.push(Observation::about_path(
                ArtifactSource::Registry {
                    hive: source.hive_name(),
                    key: "(a deleted value; the key it was under is not recoverable)".to_string(),
                },
                path,
                ObservationKind::DeletedRegistryValue {
                    value_name: value.name.clone(),
                    raw_value: format!("{DELETED_MARK}{piece}"),
                },
            ));
            emitted += 1;
        }
    }
}

fn deleted_filter(rules: &[Rule]) -> (usize, Option<HashSet<String>>) {
    let mut max_depth = 0;
    let mut terminals = HashSet::new();
    let mut wildcard_terminal = false;
    for r in rules {
        let (depth, terminal) = match &r.child {
            None => (r.prefix.len(), r.prefix.last()),
            Some(suffix) => (r.prefix.len() + 1 + suffix.len(), suffix.last()),
        };
        max_depth = max_depth.max(depth);
        match terminal {
            Some(name) => {
                terminals.insert(name.to_ascii_lowercase());
            }
            None => wildcard_terminal = true,
        }
    }
    let terminals = if wildcard_terminal { None } else { Some(terminals) };
    (max_depth, terminals)
}

fn rule_matches(r: &Rule, path: &[String]) -> bool {
    match &r.child {
        None => segs_eq(path, &r.prefix),
        Some(suffix) => {
            if path.len() != r.prefix.len() + 1 + suffix.len() {
                return false;
            }
            segs_eq(&path[..r.prefix.len()], &r.prefix)
                && segs_eq(&path[r.prefix.len() + 1..], suffix)
        }
    }
}

fn segs_eq(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn emit_key(
    reg: &regf::Hive<'_>,
    key: &regf::KeyNode<'_>,
    path: &[String],
    r: &Rule,
    source: &HiveSource,
    seen: &mut HashSet<String>,
    out: &mut Harvested,
) {
    for value in reg.values(key, &|name| r.sel.matches(name)) {
        let deleted = value.deleted || !key.allocated;
        let label = key_label(path, &value.name);
        for text in value_strings(value.kind, &value.data) {
            for piece in split_value(&text, r.split) {
                emit_one(reg, &piece, &label, r, deleted, source, seen, out);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_one(
    reg: &regf::Hive<'_>,
    piece: &str,
    label: &str,
    r: &Rule,
    deleted: bool,
    source: &HiveSource,
    seen: &mut HashSet<String>,
    out: &mut Harvested,
) {
    if piece.trim().is_empty() {
        return;
    }
    if !reg.spend_bytes(piece.len() as u64 + 64) {
        return;
    }
    let command =
        if r.service_path { rewrite_service_path(piece) } else { rewrite_nt_prefix(piece) };
    let Some(command) = command_head(&command) else {
        return;
    };
    let Some(path) = NormalizedPath::from_command_line(command) else {
        return;
    };

    let mut raw_value = String::new();
    if deleted {
        raw_value.push_str(DELETED_MARK);
    }
    raw_value.push_str(piece);

    let dedupe = format!("{label}\u{1}{raw_value}\u{1}{}", path.key());
    if !seen.insert(dedupe) {
        return;
    }

    out.push(Observation::about_path(
        ArtifactSource::Registry { hive: source.hive_name(), key: label.to_string() },
        path,
        ObservationKind::Persistence { kind: r.kind, raw_value },
    ));
}

fn key_label(path: &[String], value_name: &str) -> String {
    let mut s = path.join("\\");
    if !s.is_empty() {
        s.push('\\');
    }
    if value_name.is_empty() {
        s.push_str("(Default)");
    } else {
        s.push_str(value_name);
    }
    s
}

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_LINK: u32 = 6;
const REG_MULTI_SZ: u32 = 7;

fn value_strings(kind: u32, data: &[u8]) -> Vec<String> {
    match kind {
        REG_SZ | REG_EXPAND_SZ | REG_LINK => {
            let s = sz(data);
            if s.is_empty() {
                Vec::new()
            } else {
                vec![s]
            }
        }
        REG_MULTI_SZ => multi_sz(data),
        _ => match text_if_clean(data) {
            Some(s) => vec![s],
            None => Vec::new(),
        },
    }
}

fn utf16le(bytes: &[u8]) -> String {
    let units = bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes);
    char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
}

fn sz(data: &[u8]) -> String {
    utf16le(data).split('\0').next().unwrap_or("").to_string()
}

fn multi_sz(data: &[u8]) -> Vec<String> {
    utf16le(data)
        .split('\0')
        .filter(|s| !s.is_empty())
        .take(regf::MAX_PARTS)
        .map(|s| s.to_string())
        .collect()
}

fn text_if_clean(data: &[u8]) -> Option<String> {
    if data.len() < 8 || !data.len().is_multiple_of(2) {
        return None;
    }
    let s = sz(data);
    if s.len() < 4 || !s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }
    Some(s)
}

fn split_value(text: &str, split: Split) -> Vec<String> {
    if split == Split::Whole {
        return vec![text.to_string()];
    }
    let mut out = Vec::new();
    for part in text.split([',', ';']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = part.split_whitespace().collect();
        if tokens.len() > 1 && tokens.iter().all(|t| looks_like_module(t)) {
            out.extend(tokens.iter().map(|t| (*t).to_string()));
        } else {
            out.push(part.to_string());
        }
    }
    out
}

fn looks_like_module(token: &str) -> bool {
    const EXTS: &[&str] = &[".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr", ".drv"];
    let lower = token.trim_matches('"').to_ascii_lowercase();
    EXTS.iter().any(|e| lower.ends_with(e))
}

const MAX_BLANK_RUN: usize = 8;
const MAX_COMMAND: usize = 64 * 1024;

fn command_head(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let bytes = value.as_bytes();
    let mut end = value.len();

    let mut run = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        if b.is_ascii_whitespace() {
            run += 1;
            if run > MAX_BLANK_RUN {
                end = i + 1 - run;
                break;
            }
        } else {
            run = 0;
        }
    }

    if end > MAX_COMMAND {
        end = bytes.get(..MAX_COMMAND)?.iter().rposition(|b| b.is_ascii_whitespace())?;
    }

    let head = value.get(..end)?.trim_end();
    if head.is_empty() {
        return None;
    }
    if head.starts_with('"') && !head[1..].contains('"') {
        return None;
    }
    Some(head)
}

fn rewrite_nt_prefix(value: &str) -> String {
    let trimmed = value.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    for prefix in ["\\systemroot\\", "systemroot\\"] {
        if lower.starts_with(prefix) {
            return format!("%SystemRoot%\\{}", &trimmed[prefix.len()..]);
        }
    }
    value.to_string()
}

fn rewrite_service_path(value: &str) -> String {
    let rewritten = rewrite_nt_prefix(value);
    let probe = rewritten.trim_start().trim_start_matches('"');
    let bytes = probe.as_bytes();
    let absolute = probe.is_empty()
        || probe.starts_with('\\')
        || probe.starts_with('%')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':');
    if absolute {
        rewritten
    } else {
        format!("%SystemRoot%\\{}", rewritten.trim_start())
    }
}

mod regf {
    const BASE_BLOCK: usize = 4096;
    const HBIN_HEADER: usize = 32;
    const HBIN_ALIGN: usize = 4096;
    pub const NIL: u32 = u32::MAX;
    pub const NK_MIN: usize = 76;
    pub const VK_MIN: usize = 20;
    pub const MAX_NAME: usize = 1024;
    pub const BIG_SEGMENT: usize = 16344;

    pub const MAX_DATA: usize = 1 << 20;
    pub const MAX_SUBKEYS: usize = 1 << 18;
    pub const MAX_LIST_ENTRIES: usize = 1 << 20;
    pub const MAX_VALUES: usize = 1 << 13;
    pub const SLACK_SLOTS: usize = 64;
    pub const MAX_PATH_DEPTH: usize = 32;
    pub const MAX_LIST_DEPTH: u32 = 4;
    pub const MAX_CELLS: usize = 8_000_000;
    pub const MAX_FREED_KEYS: usize = 1 << 19;

    pub const WORK_BUDGET: u64 = 24_000_000;
    pub const BYTE_BUDGET: u64 = 32 << 20;
    pub const MAX_PARTS: usize = 1 << 13;
    pub const MAX_ADDRESSABLE: usize = u32::MAX as usize;

    pub const FLAG_HIVE_ENTRY: u16 = 0x0004;
    pub const FLAG_COMP_NAME: u16 = 0x0020;
    pub const VALUE_COMP_NAME: u16 = 0x0001;

    pub fn u16_at(b: &[u8], at: usize) -> Option<u16> {
        let end = at.checked_add(2)?;
        Some(u16::from_le_bytes(b.get(at..end)?.try_into().ok()?))
    }

    pub fn u32_at(b: &[u8], at: usize) -> Option<u32> {
        let end = at.checked_add(4)?;
        Some(u32::from_le_bytes(b.get(at..end)?.try_into().ok()?))
    }

    pub fn i32_at(b: &[u8], at: usize) -> Option<i32> {
        u32_at(b, at).map(|v| v as i32)
    }

    pub fn decode_name(bytes: &[u8], ascii: bool) -> String {
        if ascii {
            bytes.iter().map(|&b| b as char).collect()
        } else {
            let units = bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes);
            char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
        }
    }

    pub struct Cell<'a> {
        pub allocated: bool,
        pub data: &'a [u8],
    }

    #[derive(Clone, Copy)]
    pub struct KeyNode<'a> {
        data: &'a [u8],
        pub allocated: bool,
    }

    impl KeyNode<'_> {
        pub fn flags(&self) -> u16 {
            u16_at(self.data, 2).unwrap_or(0)
        }

        pub fn is_root(&self) -> bool {
            self.flags() & FLAG_HIVE_ENTRY != 0
        }

        pub fn parent(&self) -> u32 {
            u32_at(self.data, 16).unwrap_or(NIL)
        }

        pub fn subkeys_offset(&self) -> u32 {
            u32_at(self.data, 28).unwrap_or(NIL)
        }

        pub fn value_count(&self) -> u32 {
            u32_at(self.data, 36).unwrap_or(0)
        }

        pub fn values_offset(&self) -> u32 {
            u32_at(self.data, 40).unwrap_or(NIL)
        }

        pub fn name_len(&self) -> usize {
            (u16_at(self.data, 72).unwrap_or(0) as usize).min(MAX_NAME)
        }

        pub fn name(&self) -> String {
            let declared = self.name_len();
            let take = declared.min(self.data.len().saturating_sub(NK_MIN));
            let Some(bytes) = self.data.get(NK_MIN..NK_MIN + take) else {
                return String::new();
            };
            decode_name(bytes, self.flags() & FLAG_COMP_NAME != 0)
        }
    }

    pub struct Value {
        pub name: String,
        pub kind: u32,
        pub data: Vec<u8>,
        pub deleted: bool,
        pub data_reused: bool,
    }

    pub struct Hive<'a> {
        bins: &'a [u8],
        root: u32,
        minor: u32,
        work: std::cell::Cell<u64>,
        bytes: std::cell::Cell<u64>,
    }

    impl<'a> Hive<'a> {
        pub fn open(raw: &'a [u8]) -> Option<Self> {
            if raw.get(0..4)? != b"regf" {
                return None;
            }
            let minor = u32_at(raw, 24)?;
            let root = u32_at(raw, 36)?;
            let bins = raw.get(BASE_BLOCK..)?;
            if bins.is_empty() {
                return None;
            }
            let bins = bins.get(..bins.len().min(MAX_ADDRESSABLE)).unwrap_or(bins);
            Some(Hive {
                bins,
                root,
                minor,
                work: std::cell::Cell::new(WORK_BUDGET),
                bytes: std::cell::Cell::new(BYTE_BUDGET),
            })
        }

        pub fn spend(&self, n: u64) -> bool {
            let left = self.work.get();
            if left <= n {
                self.work.set(0);
                return false;
            }
            self.work.set(left - n);
            true
        }

        pub fn spend_bytes(&self, n: u64) -> bool {
            let left = self.bytes.get();
            if left <= n {
                self.bytes.set(0);
                return false;
            }
            self.bytes.set(left - n);
            true
        }

        pub fn exhausted(&self) -> bool {
            self.work.get() == 0 || self.bytes.get() == 0
        }

        pub fn renew_budget(&self) {
            self.work.set(WORK_BUDGET);
            self.bytes.set(BYTE_BUDGET);
        }

        pub fn cell(&self, offset: u32) -> Option<Cell<'a>> {
            if offset == NIL || !self.spend(1) {
                return None;
            }
            let start = offset as usize;
            let raw_size = i32_at(self.bins, start)?;
            let size = raw_size.unsigned_abs() as usize;
            if size < 8 {
                return None;
            }
            let end = start.checked_add(size)?.min(self.bins.len());
            let data = self.bins.get(start.checked_add(4)?..end)?;
            Some(Cell { allocated: raw_size < 0, data })
        }

        pub fn key_at(&self, offset: u32) -> Option<KeyNode<'a>> {
            let cell = self.cell(offset)?;
            if cell.data.get(0..2)? != b"nk" || cell.data.len() < NK_MIN {
                return None;
            }
            let node = KeyNode { data: cell.data, allocated: cell.allocated };
            if !self.spend(node.name_len() as u64 / 8) {
                return None;
            }
            Some(node)
        }

        pub fn root(&self) -> Option<KeyNode<'a>> {
            self.key_at(self.root)
        }

        pub fn subkey_offsets(&self, node: &KeyNode<'a>) -> Vec<u32> {
            let mut out = Vec::new();
            let mut slots = MAX_LIST_ENTRIES;
            self.walk_subkey_list(node.subkeys_offset(), &mut out, 0, &mut slots);
            out
        }

        pub fn walk_subkey_list(
            &self,
            offset: u32,
            out: &mut Vec<u32>,
            depth: u32,
            slots: &mut usize,
        ) {
            if depth > MAX_LIST_DEPTH || out.len() >= MAX_SUBKEYS || *slots == 0 {
                return;
            }
            let Some(cell) = self.cell(offset) else { return };
            let Some(sig) = cell.data.get(0..2) else { return };
            let Some(count) = u16_at(cell.data, 2) else { return };
            let count = count as usize;
            match sig {
                b"lf" | b"lh" => {
                    for i in 0..count.min(*slots) {
                        *slots -= 1;
                        if out.len() >= MAX_SUBKEYS {
                            return;
                        }
                        let Some(v) = u32_at(cell.data, 4 + i * 8) else {
                            return;
                        };
                        out.push(v);
                    }
                }
                b"li" => {
                    for i in 0..count.min(*slots) {
                        *slots -= 1;
                        if out.len() >= MAX_SUBKEYS {
                            return;
                        }
                        let Some(v) = u32_at(cell.data, 4 + i * 4) else {
                            return;
                        };
                        out.push(v);
                    }
                }
                b"ri" => {
                    for i in 0..count {
                        if *slots == 0 {
                            return;
                        }
                        *slots -= 1;
                        let Some(v) = u32_at(cell.data, 4 + i * 4) else {
                            return;
                        };
                        self.walk_subkey_list(v, out, depth + 1, slots);
                        if out.len() >= MAX_SUBKEYS {
                            return;
                        }
                    }
                }
                _ => {}
            }
        }

        pub fn subkey(&self, node: &KeyNode<'a>, name: &str) -> Option<KeyNode<'a>> {
            for off in self.subkey_offsets(node) {
                if let Some(child) = self.key_at(off) {
                    if child.name().eq_ignore_ascii_case(name) {
                        return Some(child);
                    }
                }
            }
            None
        }

        pub fn descend(&self, from: &KeyNode<'a>, path: &[String]) -> Option<KeyNode<'a>> {
            let mut cur = *from;
            for seg in path {
                cur = self.subkey(&cur, seg)?;
            }
            Some(cur)
        }

        pub fn values(&self, node: &KeyNode<'a>, want: &dyn Fn(&str) -> bool) -> Vec<Value> {
            let mut out = Vec::new();
            let Some(list) = self.cell(node.values_offset()) else {
                return out;
            };
            let capacity = list.data.len() / 4;
            let live = (node.value_count() as usize).min(capacity).min(MAX_VALUES);
            let scan = capacity.min(live.saturating_add(SLACK_SLOTS)).min(MAX_VALUES);
            let container_freed = !list.allocated || !node.allocated;
            for i in 0..scan {
                let Some(off) = u32_at(list.data, i * 4) else {
                    break;
                };
                let Some((mut value, allocated)) = self.value_at(off, want) else {
                    continue;
                };
                let residue = i >= live || container_freed;
                if residue && (allocated || value.data_reused) {
                    continue;
                }
                value.deleted = !allocated || residue;
                out.push(value);
            }
            out
        }

        pub fn value_at(&self, offset: u32, want: &dyn Fn(&str) -> bool) -> Option<(Value, bool)> {
            let cell = self.cell(offset)?;
            if cell.data.get(0..2)? != b"vk" || cell.data.len() < VK_MIN {
                return None;
            }
            let name_len = (u16_at(cell.data, 2)? as usize).min(MAX_NAME);
            if !self.spend(name_len as u64 / 8) {
                return None;
            }
            let size_field = u32_at(cell.data, 4)?;
            let data_offset = u32_at(cell.data, 8)?;
            let kind = u32_at(cell.data, 12)?;
            let flags = u16_at(cell.data, 16)?;

            let end = VK_MIN.saturating_add(name_len).min(cell.data.len());
            let name_bytes = cell.data.get(VK_MIN..end).unwrap_or(&[]);
            let name = decode_name(name_bytes, flags & VALUE_COMP_NAME != 0);
            if !want(&name) {
                return None;
            }

            Some((
                Value {
                    name,
                    kind,
                    data: self.value_data(size_field, data_offset),
                    deleted: false,
                    data_reused: self.data_cell_is_allocated(size_field, data_offset),
                },
                cell.allocated,
            ))
        }

        fn data_cell_is_allocated(&self, size_field: u32, data_offset: u32) -> bool {
            const RESIDENT: u32 = 0x8000_0000;
            if size_field & RESIDENT != 0 || size_field == 0 {
                return false;
            }
            self.cell(data_offset).is_some_and(|c| c.allocated)
        }

        pub fn value_data(&self, size_field: u32, data_offset: u32) -> Vec<u8> {
            pub const RESIDENT: u32 = 0x8000_0000;
            if size_field & RESIDENT != 0 {
                let n = ((size_field & !RESIDENT) as usize).min(4);
                return data_offset.to_le_bytes()[..n].to_vec();
            }
            let size = (size_field as usize).min(MAX_DATA);
            if size == 0 {
                return Vec::new();
            }
            let Some(cell) = self.cell(data_offset) else {
                return Vec::new();
            };
            if size > BIG_SEGMENT
                && self.minor >= 4
                && cell.data.get(0..2) == Some(b"db".as_slice())
            {
                return self.big_data(&cell, size);
            }
            let data = cell.data.get(..size.min(cell.data.len())).unwrap_or(&[]);
            if !self.spend_bytes(data.len() as u64) {
                return Vec::new();
            }
            data.to_vec()
        }

        pub fn big_data(&self, cell: &Cell<'a>, size: usize) -> Vec<u8> {
            let segments = u16_at(cell.data, 2).unwrap_or(0) as usize;
            let Some(list_offset) = u32_at(cell.data, 4) else {
                return Vec::new();
            };
            let Some(list) = self.cell(list_offset) else {
                return Vec::new();
            };
            let mut out: Vec<u8> = Vec::new();
            for i in 0..segments {
                if out.len() >= size {
                    break;
                }
                let Some(seg_offset) = u32_at(list.data, i * 4) else {
                    break;
                };
                let Some(seg) = self.cell(seg_offset) else { break };
                let take = size.saturating_sub(out.len()).min(BIG_SEGMENT).min(seg.data.len());
                if !self.spend_bytes(take as u64) {
                    break;
                }
                out.extend_from_slice(&seg.data[..take]);
            }
            out
        }

        pub fn key_path(&self, node: &KeyNode<'a>, max_depth: usize) -> Option<Vec<String>> {
            if node.is_root() {
                return Some(Vec::new());
            }
            let cap = max_depth.clamp(1, MAX_PATH_DEPTH);
            let mut parts = vec![node.name()];
            let mut cur = node.parent();
            let mut seen: Vec<u32> = Vec::new();
            loop {
                if cur == NIL {
                    return None;
                }
                if cur == self.root {
                    parts.reverse();
                    return Some(parts);
                }
                if seen.contains(&cur) {
                    return None;
                }
                seen.push(cur);
                let parent = self.key_at(cur)?;
                if parent.is_root() {
                    parts.reverse();
                    return Some(parts);
                }
                if parts.len() >= cap {
                    return None;
                }
                parts.push(parent.name());
                cur = parent.parent();
            }
        }

        pub fn freed_key_offsets(&self) -> Vec<u32> {
            self.freed_offsets(b"nk")
        }

        pub fn freed_value_offsets(&self) -> Vec<u32> {
            self.freed_offsets(b"vk")
        }

        fn freed_offsets(&self, signature: &[u8; 2]) -> Vec<u32> {
            let mut out = Vec::new();
            let mut budget = MAX_CELLS;
            let mut pos: usize = 0;
            while pos.saturating_add(HBIN_HEADER) <= self.bins.len() {
                if budget == 0 || out.len() >= MAX_FREED_KEYS {
                    return out;
                }
                if self.bins.get(pos..pos + 4) != Some(b"hbin".as_slice()) {
                    pos = pos.saturating_add(HBIN_ALIGN);
                    budget = budget.saturating_sub(1);
                    continue;
                }
                let declared = u32_at(self.bins, pos + 8).unwrap_or(0) as usize;
                let believable = declared >= HBIN_ALIGN
                    && declared.is_multiple_of(HBIN_ALIGN)
                    && pos.saturating_add(declared) <= self.bins.len();
                let bin_size = if believable { declared } else { HBIN_ALIGN };
                let bin_end = pos.saturating_add(bin_size).min(self.bins.len());

                let mut at = pos.saturating_add(HBIN_HEADER);
                while at.saturating_add(8) <= bin_end {
                    if budget == 0 || out.len() >= MAX_FREED_KEYS {
                        return out;
                    }
                    budget -= 1;
                    let Some(raw_size) = i32_at(self.bins, at) else {
                        break;
                    };
                    let size = raw_size.unsigned_abs() as usize;
                    if size < 8 || !size.is_multiple_of(8) || at.saturating_add(size) > bin_end {
                        break;
                    }
                    if raw_size > 0
                        && at <= MAX_ADDRESSABLE
                        && self.bins.get(at + 4..at + 6) == Some(signature.as_slice())
                    {
                        out.push(at as u32);
                    }
                    at += size;
                }
                pos = pos.saturating_add(bin_size);
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::testhive::*;

    fn kinds(obs: &[Observation]) -> Vec<PersistenceKind> {
        obs.iter()
            .filter_map(|o| match &o.kind {
                ObservationKind::Persistence { kind, .. } => Some(*kind),
                _ => None,
            })
            .collect()
    }

    fn raws(obs: &[Observation]) -> Vec<String> {
        obs.iter()
            .filter_map(|o| match &o.kind {
                ObservationKind::Persistence { raw_value, .. } => Some(raw_value.clone()),
                _ => None,
            })
            .collect()
    }

    fn keys(obs: &[Observation]) -> Vec<String> {
        obs.iter()
            .filter_map(|o| match &o.source {
                ArtifactSource::Registry { key, .. } => Some(key.clone()),
                _ => None,
            })
            .collect()
    }

    fn paths(obs: &[Observation]) -> Vec<String> {
        obs.iter().filter_map(|o| o.path.as_ref().map(|p| p.key().to_string())).collect()
    }

    fn software_with_run(values: &[(&str, u32, Vec<u8>)]) -> Vec<u8> {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        let vks: Vec<u32> = values.iter().map(|(n, k, d)| b.value(n, *k, d, true)).collect();
        let list = b.value_list(&vks, true);
        b.set_values(run, list, vks.len() as u32);
        b.finish(root)
    }

    fn software_with_deleted_run_value(list_state: ListState) -> Vec<u8> {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        let gone = b.value(
            "652fab3ea15bd655a912b0600fe39a37",
            REG_SZ_T,
            &utf16("\"C:\\Windows\\TEMP\\server.exe\" .."),
            false,
        );
        match list_state {
            ListState::SurvivingSibling => {
                let kept = b.value("OneDrive", REG_SZ_T, &utf16("C:\\OneDrive.exe"), true);
                let l = b.value_list(&[kept, gone], true);
                b.set_values(run, l, 1);
            }
            ListState::FreedListStillPointedAt => {
                let l = b.value_list(&[gone], false);
                b.set_values(run, l, 0);
            }
            ListState::NilList => {
                let _ = b.value_list(&[gone], false);
                b.set_values(run, NIL_LIST, 0);
            }
        }
        b.finish(root)
    }

    #[derive(Clone, Copy)]
    enum ListState {
        SurvivingSibling,
        FreedListStillPointedAt,
        NilList,
    }

    const NIL_LIST: u32 = u32::MAX;

    #[test]
    fn a_deleted_run_value_is_recovered_when_the_key_kept_another_value() {
        let hive = software_with_deleted_run_value(ListState::SurvivingSibling);
        let out = harvest(&hive, &HiveSource::Software);
        assert!(
            paths(&out).iter().any(|p| p == "\\windows\\temp\\server.exe"),
            "{:?}",
            paths(&out)
        );
        assert!(
            raws(&out).iter().any(|r| r.starts_with(DELETED_MARK)),
            "and it is marked deleted: {:?}",
            raws(&out)
        );
    }

    #[test]
    fn a_deleted_run_value_is_recovered_when_the_freed_list_is_still_pointed_at() {
        let hive = software_with_deleted_run_value(ListState::FreedListStillPointedAt);
        let out = harvest(&hive, &HiveSource::Software);
        assert!(
            paths(&out).iter().any(|p| p == "\\windows\\temp\\server.exe"),
            "{:?}",
            paths(&out)
        );
    }

    #[test]
    fn a_deleted_run_value_is_recovered_when_the_key_lost_its_value_list() {
        let hive = software_with_deleted_run_value(ListState::NilList);
        let out = harvest(&hive, &HiveSource::Software);
        assert!(
            paths(&out).iter().any(|p| p == "\\windows\\temp\\server.exe"),
            "the whole value list is gone and the freed `vk` is the only thing left: {:?}",
            paths(&out)
        );
        let recovered = out
            .iter()
            .find(|o| o.path.as_ref().is_some_and(|p| p.key() == "\\windows\\temp\\server.exe"))
            .expect("the value is back");
        match &recovered.kind {
            ObservationKind::DeletedRegistryValue { value_name, raw_value } => {
                assert_eq!(value_name, "652fab3ea15bd655a912b0600fe39a37");
                assert!(raw_value.starts_with(DELETED_MARK), "{raw_value}");
            }
            other => panic!("the key is unknown and this claims otherwise: {other:?}"),
        }
        match &recovered.source {
            ArtifactSource::Registry { key, .. } => {
                assert!(key.contains("not recoverable"), "the key has to read as unknown: {key}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_deleted_value_that_does_not_name_a_located_executable_is_not_emitted() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        for (name, data) in [
            ("DisplayName", "Contoso Backup Agent"),
            ("Url", "https://example.invalid/update"),
            ("Readme", "C:\\Program Files\\Contoso\\readme.txt"),
            ("Bare", "explorer.exe"),
        ] {
            b.value(name, REG_SZ_T, &utf16(data), false);
        }
        b.set_values(run, NIL_LIST, 0);
        let hive = b.finish(root);

        let out = harvest(&hive, &HiveSource::Software);
        assert!(
            !out.iter().any(|o| matches!(o.kind, ObservationKind::DeletedRegistryValue { .. })),
            "{:?}",
            paths(&out)
        );
    }

    #[test]
    fn deleted_value_recovery_is_bounded() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        for i in 0..(MAX_DELETED_VALUES * 4) {
            b.value(
                &format!("v{i}"),
                REG_SZ_T,
                &utf16(&format!("C:\\Windows\\TEMP\\p{i}.exe")),
                false,
            );
        }
        b.set_values(run, NIL_LIST, 0);
        let hive = b.finish(root);

        let out = harvest(&hive, &HiveSource::Software);
        let recovered = out
            .iter()
            .filter(|o| matches!(o.kind, ObservationKind::DeletedRegistryValue { .. }))
            .count();
        assert_eq!(recovered, MAX_DELETED_VALUES);
    }

    #[test]
    fn software_run_key_yields_one_observation_per_value() {
        let hive = software_with_run(&[
            ("Updater", REG_SZ_T, utf16("\"C:\\Users\\bob\\AppData\\Roaming\\x.exe\" --silent")),
            ("OneDrive", REG_EXPAND_SZ_T, utf16("%SystemRoot%\\System32\\onedrive.exe")),
        ]);
        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(obs.len(), 2);
        assert_eq!(kinds(&obs), vec![PersistenceKind::RunKey; 2]);

        let p = paths(&obs);
        assert!(p.contains(&"\\users\\bob\\appdata\\roaming\\x.exe".to_string()));
        assert!(p.contains(&"\\windows\\system32\\onedrive.exe".to_string()));

        assert!(raws(&obs).iter().any(|r| r.ends_with("x.exe\" --silent")));
        assert!(keys(&obs).iter().any(|k| k == "Microsoft\\Windows\\CurrentVersion\\Run\\Updater"));
    }

    #[test]
    fn wow6432node_run_key_is_read_too() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Wow6432Node", "Microsoft", "Windows", "CurrentVersion", "Run"]);
        let v = b.value("Evil", REG_SZ_T, &utf16("C:\\temp\\evil32.exe"), true);
        let list = b.value_list(&[v], true);
        b.set_values(run, list, 1);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(kinds(&obs), vec![PersistenceKind::RunKey]);
        assert!(keys(&obs)[0].starts_with("Wow6432Node\\"));
    }

    #[test]
    fn winlogon_shell_and_userinit_are_distinguished() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let wl = b.path(root, &["Microsoft", "Windows NT", "CurrentVersion", "Winlogon"]);
        let shell = b.value("Shell", REG_SZ_T, &utf16("explorer.exe,C:\\temp\\evil.exe"), true);
        let userinit =
            b.value("Userinit", REG_SZ_T, &utf16("C:\\Windows\\system32\\userinit.exe,"), true);
        let list = b.value_list(&[shell, userinit], true);
        b.set_values(wl, list, 2);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::Software);
        let k = kinds(&obs);
        assert!(k.contains(&PersistenceKind::WinlogonShell));
        assert!(k.contains(&PersistenceKind::WinlogonUserinit));
    }

    #[test]
    fn appinit_dlls_splits_a_module_list_but_not_a_spaced_path() {
        let build = |value: &str| {
            let mut b = Builder::new();
            let root = b.key("ROOT", ROOT_FLAG, true);
            let win = b.path(root, &["Microsoft", "Windows NT", "CurrentVersion", "Windows"]);
            let v = b.value("AppInit_DLLs", REG_SZ_T, &utf16(value), true);
            let list = b.value_list(&[v], true);
            b.set_values(win, list, 1);
            b.finish(root)
        };

        let obs = harvest(&build("C:\\windows\\system32\\a.dll b.dll"), &HiveSource::Software);
        assert_eq!(obs.len(), 2);
        assert_eq!(kinds(&obs), vec![PersistenceKind::AppInitDlls; 2]);

        let obs = harvest(&build("C:\\Program Files\\Thing\\hook.dll"), &HiveSource::Software);
        assert_eq!(paths(&obs), vec!["\\program files\\thing\\hook.dll"]);
    }

    #[test]
    fn ifeo_debugger_is_reported_per_executable() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let sethc = b.path(
            root,
            &[
                "Microsoft",
                "Windows NT",
                "CurrentVersion",
                "Image File Execution Options",
                "sethc.exe",
            ],
        );
        let dbg = b.value("Debugger", REG_SZ_T, &utf16("C:\\windows\\system32\\cmd.exe"), true);
        let list = b.value_list(&[dbg], true);
        b.set_values(sethc, list, 1);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(kinds(&obs), vec![PersistenceKind::ImageFileExecutionOptions]);
        assert!(keys(&obs)[0].ends_with("Image File Execution Options\\sethc.exe\\Debugger"));
    }

    #[test]
    fn every_control_set_is_walked_and_service_paths_are_resolved() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);

        let netsvc = b.path(root, &["ControlSet001", "Services", "netsvc"]);
        let ip = b.value(
            "ImagePath",
            REG_EXPAND_SZ_T,
            &utf16("%SystemRoot%\\system32\\svchost.exe -k netsvcs"),
            true,
        );
        let ipl = b.value_list(&[ip], true);
        b.set_values(netsvc, ipl, 1);
        let params = b.child(netsvc, "Parameters");
        let sd = b.value(
            "ServiceDll",
            REG_EXPAND_SZ_T,
            &utf16("C:\\Users\\bob\\AppData\\Roaming\\evil.dll"),
            true,
        );
        let sdl = b.value_list(&[sd], true);
        b.set_values(params, sdl, 1);

        let drv = b.path(root, &["ControlSet002", "Services", "rootkit"]);
        let dip = b.value(
            "ImagePath",
            REG_EXPAND_SZ_T,
            &utf16("\\SystemRoot\\System32\\drivers\\rk.sys"),
            true,
        );
        let dipl = b.value_list(&[dip], true);
        b.set_values(drv, dipl, 1);
        let rel = b.path(root, &["ControlSet002", "Services", "relative"]);
        let rip = b.value("ImagePath", REG_EXPAND_SZ_T, &utf16("System32\\drivers\\rel.sys"), true);
        let ripl = b.value_list(&[rip], true);
        b.set_values(rel, ripl, 1);

        let _ = b.child(root, "Select");

        let hive = b.finish(root);
        let obs = harvest(&hive, &HiveSource::System);
        let p = paths(&obs);

        assert!(p.contains(&"\\windows\\system32\\svchost.exe".to_string()));
        assert!(p.contains(&"\\users\\bob\\appdata\\roaming\\evil.dll".to_string()));
        assert!(p.contains(&"\\windows\\system32\\drivers\\rk.sys".to_string()));
        assert!(p.contains(&"\\windows\\system32\\drivers\\rel.sys".to_string()));
        assert!(kinds(&obs).iter().all(|k| *k == PersistenceKind::Service));
    }

    #[test]
    fn boot_execute_and_lsa_packages_split_their_multi_sz() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let smgr = b.path(root, &["ControlSet001", "Control", "Session Manager"]);
        let be = b.value(
            "BootExecute",
            REG_MULTI_SZ_T,
            &utf16_multi(&["autocheck autochk *", "C:\\temp\\boot.exe"]),
            true,
        );
        let bel = b.value_list(&[be], true);
        b.set_values(smgr, bel, 1);

        let lsa = b.path(root, &["ControlSet001", "Control", "Lsa"]);
        let sp = b.value(
            "Security Packages",
            REG_MULTI_SZ_T,
            &utf16_multi(&["kerberos", "msv1_0", "C:\\temp\\evilssp.dll"]),
            true,
        );
        let spl = b.value_list(&[sp], true);
        b.set_values(lsa, spl, 1);

        let hive = b.finish(root);
        let obs = harvest(&hive, &HiveSource::System);
        let k = kinds(&obs);
        assert!(k.contains(&PersistenceKind::BootExecute));
        assert!(k.contains(&PersistenceKind::LsaProvider));
        let p = paths(&obs);
        assert!(p.contains(&"\\temp\\boot.exe".to_string()));
        assert!(p.contains(&"\\temp\\evilssp.dll".to_string()));
        assert!(p.contains(&"\\kerberos".to_string()));
    }

    fn software_with_cv_value(name: &str, value: &str) -> Vec<u8> {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let cv = b.path(root, &["Microsoft", "Windows NT", "CurrentVersion"]);
        let vk = b.value(name, REG_SZ_T, &utf16(value), true);
        let list = b.value_list(&[vk], true);
        b.set_values(cv, list, 1);
        b.finish(root)
    }

    #[test]
    fn the_installation_states_its_own_drive_letter() {
        let hive = software_with_cv_value("SystemRoot", "C:\\WINDOWS");
        assert_eq!(system_root(&hive, &HiveSource::Software).as_deref(), Some("C:\\WINDOWS"));
    }

    #[test]
    fn path_name_is_the_fallback() {
        let hive = software_with_cv_value("PathName", "D:\\Windows");
        assert_eq!(system_root(&hive, &HiveSource::Software).as_deref(), Some("D:\\Windows"));
    }

    #[test]
    fn no_other_hive_is_asked() {
        let hive = software_with_cv_value("SystemRoot", "C:\\WINDOWS");
        assert_eq!(system_root(&hive, &HiveSource::System), None);
        assert_eq!(system_root(&hive, &HiveSource::NtUser { user: "bob".into() }), None);
    }

    #[test]
    fn a_hive_without_the_value_establishes_nothing() {
        let hive = software_with_run(&[("Updater", REG_SZ_T, utf16("C:\\x.exe"))]);
        assert_eq!(system_root(&hive, &HiveSource::Software), None);
        assert_eq!(system_root(b"not a hive at all", &HiveSource::Software), None);
    }

    fn system_with_mounted(values: &[(&str, u32, Vec<u8>)]) -> Vec<u8> {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let node = b.child(root, "MountedDevices");
        let vks: Vec<u32> = values.iter().map(|(n, k, d)| b.value(n, *k, d, true)).collect();
        let list = b.value_list(&vks, true);
        b.set_values(node, list, vks.len() as u32);
        b.finish(root)
    }

    #[test]
    fn an_mbr_mount_is_described_as_a_signature_and_an_offset() {
        let mut blob = 0x1a2b3c4du32.to_le_bytes().to_vec();
        blob.extend_from_slice(&1_048_576u64.to_le_bytes());
        let hive = system_with_mounted(&[("\\DosDevices\\W:", REG_BINARY_T, blob)]);
        let mounts = mounted_devices(&hive, &HiveSource::System);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].0, 'W');
        assert_eq!(mounts[0].1, "MBR disk signature 0x1a2b3c4d, partition at offset 1048576");
    }

    #[test]
    fn a_gpt_mount_keeps_the_volume_name_it_recorded() {
        let hive = system_with_mounted(&[(
            "\\DosDevices\\E:",
            REG_BINARY_T,
            utf16("\\??\\Volume{0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fa}"),
        )]);
        let mounts = mounted_devices(&hive, &HiveSource::System);
        assert_eq!(mounts[0].0, 'E');
        assert_eq!(mounts[0].1, "\\??\\Volume{0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fa}");
    }

    #[test]
    fn an_undecodable_mount_says_so() {
        let hive = system_with_mounted(&[("\\DosDevices\\F:", REG_BINARY_T, vec![0xff; 7])]);
        let mounts = mounted_devices(&hive, &HiveSource::System);
        assert_eq!(mounts[0].1, "7 bytes, in a form this tool does not decode");
    }

    #[test]
    fn the_dynamic_disk_form_is_a_guid_and_not_mojibake() {
        let mut blob = b"DMIO:ID:".to_vec();
        blob.extend_from_slice(&[
            0x0f, 0x9e, 0x8d, 0x7c, 0x2b, 0x1a, 0x3d, 0x4c, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8,
            0xe9, 0xfa,
        ]);
        let hive = system_with_mounted(&[("\\DosDevices\\C:", REG_BINARY_T, blob)]);
        let mounts = mounted_devices(&hive, &HiveSource::System);
        assert_eq!(mounts[0].1, "volume ID {7c8d9e0f-1a2b-4c3d-8394-a5b6c7d8e9fa}");
    }

    #[test]
    fn a_removable_volume_names_the_device() {
        let hive = system_with_mounted(&[(
            "\\DosDevices\\E:",
            REG_BINARY_T,
            utf16("_??_USBSTOR#Disk&Ven_ASolid&Prod_USB&Rev_0000#09819023&0#{53f56307-b6bf}"),
        )]);
        let mounts = mounted_devices(&hive, &HiveSource::System);
        assert!(mounts[0].1.starts_with("_??_USBSTOR#Disk&Ven_ASolid"), "{}", mounts[0].1);
    }

    #[test]
    fn only_drive_letter_entries_are_taken() {
        let hive = system_with_mounted(&[
            ("\\DosDevices\\C:", REG_BINARY_T, vec![1; 12]),
            ("\\??\\Volume{deadbeef}", REG_BINARY_T, vec![1; 12]),
            ("\\DosDevices\\NotALetter", REG_BINARY_T, vec![1; 12]),
        ]);
        let mounts = mounted_devices(&hive, &HiveSource::System);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].0, 'C');
    }

    #[test]
    fn mounted_devices_is_only_read_from_system() {
        let hive = system_with_mounted(&[("\\DosDevices\\W:", REG_BINARY_T, vec![1; 12])]);
        assert!(mounted_devices(&hive, &HiveSource::Software).is_empty());
        assert!(mounted_devices(b"junk", &HiveSource::System).is_empty());
    }

    fn hive_with_shell_folder(
        prefix: &[&str],
        key: &str,
        value_name: &str,
        value: &str,
    ) -> Vec<u8> {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let mut path: Vec<&str> = prefix.to_vec();
        path.push(key);
        let node = b.path(root, &path);
        let vk = b.value(value_name, REG_EXPAND_SZ_T, &utf16(value), true);
        let list = b.value_list(&[vk], true);
        b.set_values(node, list, 1);
        b.finish(root)
    }

    const NTUSER_EXPLORER: &[&str] =
        &["Software", "Microsoft", "Windows", "CurrentVersion", "Explorer"];
    const SOFTWARE_EXPLORER: &[&str] = &["Microsoft", "Windows", "CurrentVersion", "Explorer"];

    #[test]
    fn a_users_startup_redirect_is_read_unexpanded() {
        let hive = hive_with_shell_folder(
            NTUSER_EXPLORER,
            "User Shell Folders",
            "Startup",
            "%USERPROFILE%\\Autostart",
        );
        assert_eq!(
            startup_redirect(&hive, &HiveSource::NtUser { user: "bob".into() }).as_deref(),
            Some("%USERPROFILE%\\Autostart")
        );
        assert_eq!(startup_redirect(&hive, &HiveSource::Software), None);
    }

    #[test]
    fn the_all_users_startup_redirect_comes_from_software() {
        let hive = hive_with_shell_folder(
            SOFTWARE_EXPLORER,
            "User Shell Folders",
            "Common Startup",
            "C:\\Autostart",
        );
        assert_eq!(
            startup_redirect(&hive, &HiveSource::Software).as_deref(),
            Some("C:\\Autostart")
        );
    }

    #[test]
    fn the_setting_wins_over_explorers_cache() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let explorer = b.path(root, NTUSER_EXPLORER);

        let setting = b.child(explorer, "User Shell Folders");
        let vk = b.value("Startup", REG_EXPAND_SZ_T, &utf16("C:\\Evil"), true);
        let list = b.value_list(&[vk], true);
        b.set_values(setting, list, 1);

        let cache = b.child(explorer, "Shell Folders");
        let vk2 = b.value("Startup", REG_SZ_T, &utf16("C:\\Users\\bob\\Old"), true);
        let list2 = b.value_list(&[vk2], true);
        b.set_values(cache, list2, 1);

        let hive = b.finish(root);
        assert_eq!(
            startup_redirect(&hive, &HiveSource::NtUser { user: "bob".into() }).as_deref(),
            Some("C:\\Evil")
        );
    }

    #[test]
    fn the_cache_is_used_when_the_setting_is_absent() {
        let hive = hive_with_shell_folder(
            NTUSER_EXPLORER,
            "Shell Folders",
            "Startup",
            "C:\\Users\\bob\\Cached",
        );
        assert_eq!(
            startup_redirect(&hive, &HiveSource::NtUser { user: "bob".into() }).as_deref(),
            Some("C:\\Users\\bob\\Cached")
        );
    }

    #[test]
    fn no_redirect_is_the_ordinary_answer() {
        let hive = software_with_run(&[("x", REG_SZ_T, utf16("C:\\x.exe"))]);
        assert_eq!(startup_redirect(&hive, &HiveSource::Software), None);
        assert_eq!(startup_redirect(&hive, &HiveSource::NtUser { user: "bob".into() }), None);
        assert_eq!(startup_redirect(b"not a hive at all", &HiveSource::Software), None);
        assert_eq!(startup_redirect(&[], &HiveSource::Software), None);
    }

    #[test]
    fn ntuser_run_screensaver_and_com_server() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);

        let run = b.path(root, &["Software", "Microsoft", "Windows", "CurrentVersion", "Run"]);
        let rv = b.value("Backdoor", REG_SZ_T, &utf16("C:\\temp\\bd.exe"), true);
        let rl = b.value_list(&[rv], true);
        b.set_values(run, rl, 1);

        let desktop = b.path(root, &["Control Panel", "Desktop"]);
        let ss = b.value("SCRNSAVE.EXE", REG_SZ_T, &utf16("C:\\Users\\bob\\evil.scr"), true);
        let ssl = b.value_list(&[ss], true);
        b.set_values(desktop, ssl, 1);

        let inproc =
            b.path(root, &["Software", "Classes", "CLSID", "{deadbeef}", "InprocServer32"]);
        let dv = b.value("", REG_EXPAND_SZ_T, &utf16("C:\\temp\\hijack.dll"), true);
        let dl = b.value_list(&[dv], true);
        b.set_values(inproc, dl, 1);

        let hive = b.finish(root);
        let obs = harvest(&hive, &HiveSource::NtUser { user: "bob".into() });
        let k = kinds(&obs);
        assert!(k.contains(&PersistenceKind::RunKey));
        assert!(k.contains(&PersistenceKind::ScreenSaver));
        assert!(k.contains(&PersistenceKind::ComServer));
        assert!(!k.contains(&PersistenceKind::ComHijack));
        assert!(keys(&obs).iter().any(|s| s.ends_with("(Default)")));
    }

    #[test]
    fn usrclass_com_registration_is_rooted_at_classes() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let inproc =
            b.path(root, &["CLSID", "{01234567-89ab-cdef-0123-456789abcdef}", "InprocServer32"]);
        let dv = b.value("", REG_EXPAND_SZ_T, &utf16("%APPDATA%\\Microsoft\\shell32.dll"), true);
        let dl = b.value_list(&[dv], true);
        b.set_values(inproc, dl, 1);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::UsrClass { user: "bob".into() });
        assert_eq!(kinds(&obs), vec![PersistenceKind::ComServer]);
        assert_eq!(paths(&obs), vec!["\\%appdata%\\microsoft\\shell32.dll"]);
    }

    #[test]
    fn a_deleted_run_key_is_recovered_and_marked() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let cv = b.path(root, &["Microsoft", "Windows", "CurrentVersion"]);

        let v = b.value("Dropper", REG_SZ_T, &utf16("C:\\temp\\dropper.exe"), false);
        let list = b.value_list(&[v], false);
        let run = b.key("Run", 0, false);
        b.set_values(run, list, 1);
        b.set_parent(run, cv);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(kinds(&obs), vec![PersistenceKind::RunKey]);
        assert!(raws(&obs)[0].starts_with(DELETED_MARK));
        assert_eq!(paths(&obs), vec!["\\temp\\dropper.exe"]);
    }

    #[test]
    fn a_deleted_service_is_recovered_through_its_parent_chain() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let services = b.path(root, &["ControlSet001", "Services"]);

        let ip = b.value("ImagePath", REG_EXPAND_SZ_T, &utf16("C:\\Windows\\Temp\\svc.exe"), false);
        let ipl = b.value_list(&[ip], false);
        let svc = b.key("BadSvc", 0, false);
        b.set_values(svc, ipl, 1);
        b.set_parent(svc, services);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::System);
        assert_eq!(kinds(&obs), vec![PersistenceKind::Service]);
        assert!(raws(&obs)[0].starts_with(DELETED_MARK));
        assert!(keys(&obs)[0].contains("Services\\BadSvc\\ImagePath"));
    }

    #[test]
    fn a_deleted_value_left_in_the_list_slack_is_recovered() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);

        let live = b.value("Legit", REG_SZ_T, &utf16("C:\\windows\\legit.exe"), true);
        let gone = b.value("Payload", REG_SZ_T, &utf16("C:\\temp\\payload.exe"), false);
        let list = b.value_list(&[live, gone], true);
        b.set_values(run, list, 1);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(obs.len(), 2);
        let r = raws(&obs);
        assert!(r.iter().any(|s| s == "C:\\windows\\legit.exe"));
        assert!(r.iter().any(|s| s == &format!("{DELETED_MARK}C:\\temp\\payload.exe")));
    }

    #[test]
    fn a_slack_slot_pointing_at_a_live_value_is_not_a_deletion() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        let other = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Explorer"]);

        let kept = b.value("ZoomIt", REG_SZ_T, &utf16("C:\\Tools\\ZoomIt64.exe"), true);
        let elsewhere = b.value("CachePath", REG_SZ_T, &utf16("C:\\cache\\other.exe"), true);
        let other_list = b.value_list(&[elsewhere], true);
        b.set_values(other, other_list, 1);

        let list = b.value_list(&[kept, elsewhere], true);
        b.set_values(run, list, 1);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::Software);
        let r = raws(&obs);
        assert!(
            r.iter().any(|s| s == "C:\\Tools\\ZoomIt64.exe"),
            "the key's real value is unaffected: {r:?}"
        );
        assert!(
            !r.iter().any(|s| s.contains("other.exe")),
            "a live cell reached through a stale slot is not a deleted value: {r:?}"
        );
        assert!(!r.iter().any(|s| s.starts_with(DELETED_MARK)), "nothing here was deleted: {r:?}");
    }

    #[test]
    fn a_freed_value_whose_data_cell_is_back_in_use_recovers_nothing() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);

        b.value("Real", REG_SZ_T, &utf16("C:\\temp\\real.exe"), false);
        b.value_over_reused_data("Stale", REG_SZ_T, &utf16("C:\\temp\\stale.exe"));
        b.set_values(run, NIL_LIST, 0);
        let hive = b.finish(root);

        let out = harvest(&hive, &HiveSource::Software);
        let p = paths(&out);
        assert!(
            p.iter().any(|s| s == "\\temp\\real.exe"),
            "a value whose cells are both freed is still recovered: {p:?}"
        );
        assert!(
            !p.iter().any(|s| s == "\\temp\\stale.exe"),
            "a freed `vk` over a live data cell states a deletion that did not happen: {p:?}"
        );
    }

    #[test]
    fn a_freed_key_whose_parent_is_gone_invents_no_persistence() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let v = b.value("X", REG_SZ_T, &utf16("C:\\temp\\orphan.exe"), false);
        let list = b.value_list(&[v], false);
        let orphan = b.key("Run", 0, false);
        b.set_values(orphan, list, 1);
        b.set_parent(orphan, 0x0010_0000);
        let hive = b.finish(root);

        let out = harvest(&hive, &HiveSource::Software);
        assert!(
            !out.iter().any(|o| matches!(o.kind, ObservationKind::Persistence { .. })),
            "a chain that does not reach the root must never produce persistence: {:?}",
            keys(&out)
        );
        for o in &out {
            match (&o.kind, &o.source) {
                (
                    ObservationKind::DeletedRegistryValue { .. },
                    ArtifactSource::Registry { key, .. },
                ) => assert!(key.contains("not recoverable"), "{key}"),
                other => panic!("nothing else may come out of a broken chain: {other:?}"),
            }
        }
    }

    #[test]
    fn a_parent_cycle_terminates() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let a = b.key("A", 0, false);
        let c = b.key("Run", 0, false);
        b.set_parent(a, c);
        b.set_parent(c, a);
        let hive = b.finish(root);

        assert!(harvest(&hive, &HiveSource::Software).is_empty());
    }

    #[test]
    fn identical_recovered_facts_are_reported_once() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let cv = b.path(root, &["Microsoft", "Windows", "CurrentVersion"]);
        for _ in 0..2 {
            let v = b.value("D", REG_SZ_T, &utf16("C:\\temp\\d.exe"), false);
            let list = b.value_list(&[v], false);
            let run = b.key("Run", 0, false);
            b.set_values(run, list, 1);
            b.set_parent(run, cv);
        }
        let hive = b.finish(root);
        assert_eq!(harvest(&hive, &HiveSource::Software).len(), 1);
    }

    #[test]
    fn index_leaf_and_index_root_subkey_lists_are_followed() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let ms = b.key("Microsoft", 0, true);
        let li = b.index_leaf(&[ms], true);
        let ri = b.index_root(&[li], true);
        b.set_subkeys(root, ri, 1);
        b.set_parent(ms, root);

        let win = b.key("Windows", 0, true);
        let li2 = b.index_leaf(&[win], true);
        b.set_subkeys(ms, li2, 1);
        b.set_parent(win, ms);

        let run = b.path(win, &["CurrentVersion", "Run"]);
        let v = b.value("A", REG_SZ_T, &utf16("C:\\temp\\li.exe"), true);
        let vl = b.value_list(&[v], true);
        b.set_values(run, vl, 1);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(paths(&obs), vec!["\\temp\\li.exe"]);
    }

    #[test]
    fn big_data_values_are_reassembled_on_vista_era_hives() {
        let long = format!("C:\\temp\\{}\\big.exe", "a".repeat(9000));
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        let v = b.big_value("Big", REG_SZ_T, &utf16(&long));
        let list = b.value_list(&[v], true);
        b.set_values(run, list, 1);
        let hive = b.finish(root);

        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(obs.len(), 1);
        assert!(obs[0].path.as_ref().unwrap().key().ends_with("big.exe"));
    }

    #[test]
    fn a_pre_vista_hive_without_big_data_still_parses() {
        let mut b = Builder::new().minor(3);
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        let v = b.value("A", REG_SZ_T, &utf16("C:\\temp\\old.exe"), true);
        let vl = b.value_list(&[v], true);
        b.set_values(run, vl, 1);
        let hive = b.finish(root);

        assert_eq!(paths(&harvest(&hive, &HiveSource::Software)), vec!["\\temp\\old.exe"]);
    }

    #[test]
    fn a_utf16_key_name_is_decoded() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let ms = b.key_wide("Microsoft");
        b.link(root, ms);
        let run = b.path(ms, &["Windows", "CurrentVersion", "Run"]);
        let v = b.value("A", REG_SZ_T, &utf16("C:\\temp\\u.exe"), true);
        let vl = b.value_list(&[v], true);
        b.set_values(run, vl, 1);
        let hive = b.finish(root);

        assert_eq!(paths(&harvest(&hive, &HiveSource::Software)), vec!["\\temp\\u.exe"]);
    }

    #[test]
    fn a_zero_length_buffer_yields_nothing() {
        assert!(harvest(&[], &HiveSource::Software).is_empty());
        assert!(harvest(&[], &HiveSource::System).is_empty());
        assert!(harvest(&[], &HiveSource::NtUser { user: "b".into() }).is_empty());
        assert!(harvest(&[], &HiveSource::UsrClass { user: "b".into() }).is_empty());
    }

    #[test]
    fn a_buffer_that_is_not_a_hive_yields_nothing() {
        assert!(harvest(b"MZ\x90\x00not a hive at all", &HiveSource::Software).is_empty());
        assert!(harvest(&vec![0u8; 8192], &HiveSource::Software).is_empty());
        assert!(harvest(&vec![0xffu8; 8192], &HiveSource::System).is_empty());
        assert!(harvest(b"regf", &HiveSource::Software).is_empty());
    }

    #[test]
    fn every_truncation_of_a_good_hive_is_survivable() {
        let hive = software_with_run(&[(
            "Updater",
            REG_SZ_T,
            utf16("C:\\Users\\bob\\AppData\\Roaming\\x.exe"),
        )]);
        for len in 0..hive.len() {
            let obs = harvest(&hive[..len], &HiveSource::Software);
            assert!(obs.len() <= 1, "len {len} produced {} rows", obs.len());
        }
    }

    #[test]
    fn every_single_byte_corruption_of_a_good_hive_is_survivable() {
        let hive = software_with_run(&[(
            "Updater",
            REG_SZ_T,
            utf16("C:\\Users\\bob\\AppData\\Roaming\\x.exe"),
        )]);
        let interesting = (4096 + 1024).min(hive.len());
        for i in 0..interesting {
            for pattern in [0x00u8, 0xff, 0x80, 0x41] {
                let mut damaged = hive.clone();
                damaged[i] = pattern;
                let _ = harvest(&damaged, &HiveSource::Software);
                let _ = harvest(&damaged, &HiveSource::System);
                let _ = harvest(&damaged, &HiveSource::UsrClass { user: "b".into() });
            }
        }
    }

    #[test]
    fn absurd_counts_and_offsets_are_not_believed() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let liar = b.key("Microsoft", 0, true);
        b.set_subkeys(liar, 0x7fff_fff8, u32::MAX - 1);
        b.set_values(liar, 0x7fff_fff0, u32::MAX);
        b.link(root, liar);
        let hive = b.finish(root);
        assert!(harvest(&hive, &HiveSource::Software).is_empty());
    }

    #[test]
    fn an_absurd_value_data_size_allocates_nothing() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        let mut c = Vec::new();
        c.extend_from_slice(b"vk");
        c.extend_from_slice(&4u16.to_le_bytes());
        c.extend_from_slice(&0x7fff_ffffu32.to_le_bytes());
        c.extend_from_slice(&40u32.to_le_bytes());
        c.extend_from_slice(&REG_SZ_T.to_le_bytes());
        c.extend_from_slice(&1u16.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(b"Evil");
        let v = b.add(&c, true);
        let list = b.value_list(&[v], true);
        b.set_values(run, list, 1);
        let hive = b.finish(root);
        let _ = harvest(&hive, &HiveSource::Software);
    }

    #[test]
    fn a_cell_size_of_zero_or_int_min_does_not_hang_or_panic() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        let v = b.value("A", REG_SZ_T, &utf16("C:\\temp\\a.exe"), true);
        let list = b.value_list(&[v], true);
        b.set_values(run, list, 1);
        let mut hive = b.finish(root);

        let at = 4096 + 32;
        for size in [0i32, i32::MIN, i32::MAX, -1, 7] {
            hive[at..at + 4].copy_from_slice(&size.to_le_bytes());
            let _ = harvest(&hive, &HiveSource::Software);
        }
    }

    #[test]
    fn a_root_offset_pointing_nowhere_yields_nothing() {
        let hive = software_with_run(&[("A", REG_SZ_T, utf16("C:\\temp\\a.exe"))]);
        for bogus in [0u32, u32::MAX, 0x7fff_ffff, 1] {
            let mut damaged = hive.clone();
            damaged[36..40].copy_from_slice(&bogus.to_le_bytes());
            assert!(harvest(&damaged, &HiveSource::Software).len() <= 1);
        }
    }

    #[test]
    fn a_self_referential_subkey_list_terminates() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let ri = b.index_root(&[0], true);
        b.set_u32(ri, 0, u32::from_le_bytes([b'r', b'i', 1, 0]));
        let at = ri as usize + 4 + 4;
        b.bins[at..at + 4].copy_from_slice(&ri.to_le_bytes());
        b.set_subkeys(root, ri, 1);
        let hive = b.finish(root);
        assert!(harvest(&hive, &HiveSource::Software).is_empty());
    }

    #[test]
    fn a_deleted_key_in_a_later_hive_bin_is_recovered() {
        let hive = two_bin_hive_with_a_deleted_run_key(None);
        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(paths(&obs), vec!["\\temp\\dropper.exe"]);
        assert!(raws(&obs)[0].starts_with(DELETED_MARK));
    }

    #[test]
    fn a_hive_bin_claiming_to_be_longer_than_the_file_hides_nothing() {
        let hive = two_bin_hive_with_a_deleted_run_key(Some(64 * 4096));
        let obs = harvest(&hive, &HiveSource::Software);
        assert_eq!(paths(&obs), vec!["\\temp\\dropper.exe"]);
    }

    fn two_bin_hive_with_a_deleted_run_key(lie: Option<u32>) -> Vec<u8> {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let cv = b.path(root, &["Microsoft", "Windows", "CurrentVersion"]);
        b.bin_break();
        let v = b.value("Dropper", REG_SZ_T, &utf16("C:\\temp\\dropper.exe"), false);
        let list = b.value_list(&[v], false);
        let run = b.key("Run", 0, false);
        b.set_values(run, list, 1);
        b.set_parent(run, cv);
        let mut hive = b.finish(root);
        if let Some(lie) = lie {
            hive[4096 + 8..4096 + 12].copy_from_slice(&lie.to_le_bytes());
        }
        hive
    }

    fn within(name: &str, took: std::time::Duration) {
        assert!(took.as_secs_f64() < 20.0, "{name} took {took:?}");
    }

    #[test]
    fn a_self_referential_ri_list_with_a_large_count_terminates() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let ri = b.index_root(&vec![0u32; 20_000], true);
        for i in 0..20_000usize {
            let at = ri as usize + 4 + 4 + i * 4;
            b.bins[at..at + 4].copy_from_slice(&ri.to_le_bytes());
        }
        b.set_subkeys(root, ri, 20_000);
        let hive = b.finish(root);

        let t = std::time::Instant::now();
        assert!(harvest(&hive, &HiveSource::Software).is_empty());
        within("self-referential ri", t.elapsed());
    }

    #[test]
    fn a_subkey_list_naming_one_key_repeatedly_is_walked_once() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let clsid = b.key("CLSID", 0, true);
        let top = b.hash_leaf(&[clsid], true);
        b.set_subkeys(root, top, 1);
        b.set_parent(clsid, root);

        let guid = b.key("{0000ffff-0000-0000-0000-000000000000}", 0, true);
        let inproc = b.key("InprocServer32", 0, true);
        let v = b.value("", REG_SZ_T, &utf16("C:\\temp\\com.dll"), true);
        let vl = b.value_list(&[v], true);
        b.set_values(inproc, vl, 1);
        let gl = b.hash_leaf(&[inproc], true);
        b.set_subkeys(guid, gl, 1);
        b.set_parent(inproc, guid);
        b.set_parent(guid, clsid);

        let repeated = b.index_leaf(&vec![guid; 20_000], true);
        b.set_subkeys(clsid, repeated, 20_000);
        let hive = b.finish(root);

        let t = std::time::Instant::now();
        let obs = harvest(&hive, &HiveSource::UsrClass { user: "b".into() });
        within("repeated subkey", t.elapsed());
        assert_eq!(paths(&obs), vec!["\\temp\\com.dll"]);
    }

    #[test]
    fn a_value_list_aimed_at_one_fat_cell_does_not_exhaust_memory() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
        let fat = b.add(&vec![0x41u8; 2 << 20], true);
        let v = b.value("A", REG_SZ_T, &utf16("C:\\temp\\a.exe"), true);
        b.set_u32(v, 4, (2 << 20) as u32);
        b.set_u32(v, 8, fat);
        let list = b.value_list(&vec![v; 8192], true);
        b.set_values(run, list, 8192);
        let hive = b.finish(root);

        let t = std::time::Instant::now();
        let obs = harvest(&hive, &HiveSource::Software);
        within("fat value list", t.elapsed());
        assert!(obs.len() <= 1);
    }

    #[test]
    fn a_value_that_is_a_field_of_blanks_normalizes_in_bounded_time() {
        let mut padded = String::from("C:\\temp\\pad.exe");
        padded.push_str(&" ".repeat(200_000));
        padded.push_str("tail");
        let hive = software_with_run(&[("A", REG_SZ_T, utf16(&padded))]);

        let t = std::time::Instant::now();
        let obs = harvest(&hive, &HiveSource::Software);
        within("blank field", t.elapsed());
        assert_eq!(paths(&obs), vec!["\\temp\\pad.exe"]);
        assert_eq!(raws(&obs)[0].len(), padded.len());
    }

    #[test]
    fn a_key_name_longer_than_windows_permits_does_not_dominate_the_walk() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let fat = b.key(&"n".repeat(60_000), 0, true);
        let leaf = b.index_leaf(&vec![fat; 8192], true);
        let ri = b.index_root(&[leaf; 32], true);
        b.set_subkeys(root, ri, 262_144);
        let hive = b.finish(root);

        let t = std::time::Instant::now();
        assert!(harvest(&hive, &HiveSource::Software).is_empty());
        within("64 KB key name", t.elapsed());
    }

    #[test]
    fn a_multi_sz_with_absurdly_many_elements_is_capped() {
        let parts: Vec<String> = (0..100_000).map(|i| format!("C:\\t\\m{i}.dll")).collect();
        let refs: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let sm = b.path(root, &["ControlSet001", "Control", "Session Manager"]);
        let v = b.value("BootExecute", REG_MULTI_SZ_T, &utf16_multi(&refs), true);
        let vl = b.value_list(&[v], true);
        b.set_values(sm, vl, 1);
        let hive = b.finish(root);

        let t = std::time::Instant::now();
        let obs = harvest(&hive, &HiveSource::System);
        within("huge multi_sz", t.elapsed());
        assert!(!obs.is_empty() && obs.len() <= 8192, "{} rows", obs.len());
    }

    #[test]
    fn a_large_well_formed_hive_is_not_clipped_by_the_budgets() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let clsid = b.path(root, &["CLSID"]);
        for i in 0..20_000 {
            let guid = b.key(&format!("{{{i:08x}-1111-2222-3333-444444444444}}"), 0, true);
            b.link(clsid, guid);
            let inproc = b.key("InprocServer32", 0, true);
            b.link(guid, inproc);
            let v = b.value(
                "",
                REG_EXPAND_SZ_T,
                &utf16(&format!("C:\\windows\\system32\\wide{i}.dll")),
                true,
            );
            let vl = b.value_list(&[v], true);
            b.set_values(inproc, vl, 1);
        }
        let hive = b.finish(root);
        let obs = harvest(&hive, &HiveSource::UsrClass { user: "b".into() });
        assert_eq!(obs.len(), 20_000, "the budget clipped a well-formed hive");
    }

    #[test]
    fn the_command_head_keeps_what_names_the_program() {
        for cmd in [
            "C:\\Windows\\system32\\svchost.exe -k netsvcs",
            "\"C:\\Program Files\\Thing\\a b.exe\" -q",
            "explorer.exe",
        ] {
            assert_eq!(command_head(cmd), Some(cmd), "{cmd}");
        }
        assert_eq!(command_head("   C:\\a.exe -x"), Some("C:\\a.exe -x"));
        assert_eq!(command_head(&format!("C:\\a.exe{}tail", " ".repeat(400))), Some("C:\\a.exe"));
        assert_eq!(command_head("C:\\Program  Files\\a.exe"), Some("C:\\Program  Files\\a.exe"));
        assert_eq!(command_head(&" ".repeat(100)), None);
        assert_eq!(command_head(&format!("\"C:\\dir{}name\\a.exe\"", " ".repeat(40))), None);
        assert_eq!(command_head(&"a".repeat(70_000)), None);
    }

    #[test]
    fn a_binary_value_that_is_not_text_is_not_turned_into_a_path() {
        let hive = software_with_run(&[(
            "Blob",
            REG_BINARY_T,
            vec![0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0x11, 0x22],
        )]);
        assert!(harvest(&hive, &HiveSource::Software).is_empty());
    }

    #[test]
    fn a_path_recorded_under_the_wrong_type_is_still_recovered() {
        let hive = software_with_run(&[("Sneaky", REG_BINARY_T, utf16("C:\\temp\\typed.exe"))]);
        assert_eq!(paths(&harvest(&hive, &HiveSource::Software)), vec!["\\temp\\typed.exe"]);
    }

    #[test]
    fn the_wrong_hive_kind_reads_nothing_rather_than_guessing() {
        let hive = software_with_run(&[("A", REG_SZ_T, utf16("C:\\temp\\a.exe"))]);
        assert!(harvest(&hive, &HiveSource::System).is_empty());
        assert!(harvest(&hive, &HiveSource::UsrClass { user: "b".into() }).is_empty());
    }

    #[test]
    fn observations_always_identify_a_file() {
        let hive = software_with_run(&[
            ("A", REG_SZ_T, utf16("C:\\temp\\a.exe")),
            ("Empty", REG_SZ_T, utf16("")),
            ("Spaces", REG_SZ_T, utf16("    ")),
        ]);
        let obs = harvest(&hive, &HiveSource::Software);
        assert!(obs.iter().all(|o| o.identifies_something()));
        assert_eq!(obs.len(), 1);
    }

    #[test]
    fn a_system_hive_full_of_services_and_freed_cells_stays_linear() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let services = b.path(root, &["ControlSet001", "Services"]);
        for i in 0..1200 {
            let k = b.key(&format!("svc{i:04}"), 0, true);
            b.link(services, k);
            let v = b.value(
                "ImagePath",
                REG_EXPAND_SZ_T,
                &utf16(&format!("System32\\drivers\\d{i:04}.sys")),
                true,
            );
            let vl = b.value_list(&[v], true);
            b.set_values(k, vl, 1);
        }
        for i in 0..20_000 {
            let k = b.key(&format!("ghost{i}"), 0, false);
            if i % 1000 == 0 {
                let v = b.value(
                    "ImagePath",
                    REG_EXPAND_SZ_T,
                    &utf16(&format!("C:\\temp\\g{i}.exe")),
                    false,
                );
                let vl = b.value_list(&[v], false);
                b.set_values(k, vl, 1);
                b.set_parent(k, services);
            } else {
                b.set_parent(k, 0x0f00_0000);
            }
        }
        let hive = b.finish(root);

        let start = std::time::Instant::now();
        let obs = harvest(&hive, &HiveSource::System);
        let took = start.elapsed();
        assert_eq!(obs.len(), 1200 + 20);
        assert!(took.as_secs_f64() < 20.0, "too slow: {took:?}");
    }

    #[test]
    fn a_usrclass_hive_full_of_clsids_stays_linear() {
        let mut b = Builder::new();
        let root = b.key("ROOT", ROOT_FLAG, true);
        let clsid = b.path(root, &["CLSID"]);
        for i in 0..6000 {
            let guid = b.key(&format!("{{{i:08x}-0000-0000-0000-000000000000}}"), 0, true);
            b.link(clsid, guid);
            let inproc = b.key("InprocServer32", 0, true);
            b.link(guid, inproc);
            let v = b.value(
                "",
                REG_EXPAND_SZ_T,
                &utf16(&format!("C:\\windows\\system32\\c{i}.dll")),
                true,
            );
            let vl = b.value_list(&[v], true);
            b.set_values(inproc, vl, 1);
        }
        let hive = b.finish(root);

        let start = std::time::Instant::now();
        let obs = harvest(&hive, &HiveSource::UsrClass { user: "b".into() });
        let took = start.elapsed();
        assert_eq!(obs.len(), 6000);
        assert!(took.as_secs_f64() < 20.0, "too slow: {took:?}");
    }

    #[test]
    fn the_hive_name_and_key_travel_with_every_observation() {
        let hive = software_with_run(&[("A", REG_SZ_T, utf16("C:\\temp\\a.exe"))]);
        let obs = harvest(&hive, &HiveSource::Software);
        match &obs[0].source {
            ArtifactSource::Registry { hive, key } => {
                assert_eq!(hive, "SOFTWARE");
                assert_eq!(key, "Microsoft\\Windows\\CurrentVersion\\Run\\A");
            }
            other => panic!("wrong source: {other:?}"),
        }
        assert_eq!(obs[0].source.family(), "persistence");
    }
}
