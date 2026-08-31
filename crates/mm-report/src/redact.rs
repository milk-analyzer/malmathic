use serde_json::Value;

use crate::Report;

const WELL_KNOWN_PROFILES: [&str; 9] = [
    "public",
    "default",
    "default user",
    "all users",
    "defaultuser0",
    "administrator",
    "guest",
    "wdagutilityaccount",
    "desktop.ini",
];
const PROFILE_ROOTS: [&str; 2] = ["users", "documents and settings"];
const USER_KEYS: [&str; 5] = ["user", "author", "owner", "profile", "account"];
const HIVE_PREFIXES: [&str; 2] = ["ntuser.dat (", "usrclass.dat ("];
const SID_PREFIX: &str = "s-1-5-21-";
const MARK: &str = "redacted";
const SHORT_NAME: usize = 3;

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub keep_urls: bool,
}

#[derive(Debug, Default)]
pub struct Redaction {
    users: Vec<(String, String)>,
    hosts: Vec<(String, String)>,
    domains: Vec<String>,
    volumes: Vec<String>,
    serials: Vec<String>,
    addresses: Vec<String>,
    emails: usize,
    urls_trimmed: usize,
}

impl Redaction {
    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        let mut count = |what: &str, n: usize| {
            if n > 0 {
                lines.push(format!("  {what}: {n}"));
            }
        };
        count("user names replaced", self.users.len());
        count("machine names replaced", self.hosts.len());
        count("SID domains replaced", self.domains.len());
        count("volume GUIDs replaced", self.volumes.len());
        count("volume serials replaced", self.serials.len());
        count("IP addresses replaced", self.addresses.len());
        count("e-mail addresses replaced", self.emails);
        count("URLs cut to their host", self.urls_trimmed);
        lines.push("  case directory: dropped".to_string());
        lines.join("\n")
    }

    fn learn_user(&mut self, name: &str) {
        let folded = fold_all(name.trim());
        if folded.is_empty()
            || WELL_KNOWN_PROFILES.contains(&folded.as_str())
            || self.users.iter().any(|(known, _)| *known == folded)
        {
            return;
        }
        let token = format!("user{}", self.users.len() + 1);
        self.users.push((folded, token));
    }

    fn learn_host(&mut self, name: &str) {
        let folded = fold_all(name);
        if !folded.chars().any(char::is_alphabetic)
            || self.hosts.iter().any(|(known, _)| *known == folded)
            || self.users.iter().any(|(known, _)| *known == folded)
        {
            return;
        }
        let token = format!("host{}", self.hosts.len() + 1);
        self.hosts.push((folded, token));
    }

    fn learn_from(&mut self, key: Option<&str>, text: &str) {
        if key.is_some_and(|key| USER_KEYS.contains(&key)) {
            self.learn_user(text);
        }
        for name in profile_names(text) {
            self.learn_user(&name);
        }
        for prefix in HIVE_PREFIXES {
            for name in bracketed_after(text, prefix) {
                self.learn_user(&name);
            }
        }
    }

    fn learn_hosts_from(&mut self, text: &str) {
        let users: Vec<String> = self.users.iter().map(|(name, _)| name.clone()).collect();
        for host in domain_prefixes(text, &users) {
            self.learn_host(&host);
        }
        for host in unc_hosts(text) {
            self.learn_host(&host);
        }
    }

    fn apply(&mut self, text: &str, options: Options) -> String {
        let mut out = text.to_string();
        if !options.keep_urls {
            out = trim_urls(&out, &mut self.urls_trimmed);
        }
        out = replace_emails(&out, &mut self.emails);
        out = replace_addresses(&out, &mut self.addresses);
        out = replace_sids(&out, &mut self.domains);
        out = replace_volume_guids(&out, &mut self.volumes);
        for (index, serial) in self.serials.iter().enumerate() {
            out = replace_word(&out, serial, &format!("{:016x}", index + 1));
        }
        let hosts = self.hosts.clone();
        for (name, token) in &hosts {
            out = replace_word(&out, name, token);
        }
        let mut users = self.users.clone();
        users.sort_by_key(|(name, _)| std::cmp::Reverse(name.chars().count()));
        for (name, token) in &users {
            out = replace_segment(&out, name, token);
            if name.chars().count() >= SHORT_NAME {
                out = replace_word(&out, name, token);
            }
        }
        out
    }
}

pub fn redact(report: &Report, options: Options) -> serde_json::Result<(Report, Redaction)> {
    let mut value = serde_json::to_value(report)?;
    let mut redaction = Redaction::default();

    let serial = report.target.volume_serial.trim();
    if !serial.is_empty() {
        redaction.serials.push(fold_all(serial));
    }
    if let Some(target) = value.get_mut("target") {
        let device = report.target.device_path.clone();
        if !device.starts_with(r"\\?\") && !device.starts_with(r"\\.\") {
            let name = file_name(&device).to_string();
            target["device_path"] = Value::String(name.clone());
            target["display_name"] =
                Value::String(report.target.display_name.replacen(&device, &name, 1));
        }
    }
    value["case_directory"] = Value::Null;
    if !report.environment.contains(MARK) {
        value["environment"] = Value::String(format!("{} · {MARK}", report.environment));
    }

    visit(&value, None, &mut |key, text| redaction.learn_from(key, text));
    visit(&value, None, &mut |_, text| redaction.learn_hosts_from(text));
    rewrite(&mut value, &mut |text| redaction.apply(text, options));

    let report = serde_json::from_value(value)?;
    Ok((report, redaction))
}

fn visit(value: &Value, key: Option<&str>, f: &mut impl FnMut(Option<&str>, &str)) {
    match value {
        Value::String(text) => f(key, text),
        Value::Array(items) => {
            for item in items {
                visit(item, None, f);
            }
        }
        Value::Object(map) => {
            for (name, item) in map {
                visit(item, Some(name.as_str()), f);
            }
        }
        _ => {}
    }
}

fn rewrite(value: &mut Value, f: &mut impl FnMut(&str) -> String) {
    match value {
        Value::String(text) => {
            let replaced = f(text);
            if replaced != *text {
                *text = replaced;
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite(item, f);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                rewrite(item, f);
            }
        }
        _ => {}
    }
}

fn fold(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

fn fold_all(text: &str) -> String {
    text.chars().map(fold).collect()
}

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

fn is_token(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-' || c == '.'
}

fn ends_segment(c: char) -> bool {
    is_separator(c) || matches!(c, '"' | '\'' | '<' | '>' | '|')
}

fn file_name(path: &str) -> &str {
    path.rsplit(is_separator).next().unwrap_or(path)
}

fn profile_names(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let folded: Vec<char> = chars.iter().map(|c| fold(*c)).collect();
    let roots: Vec<Vec<char>> = PROFILE_ROOTS.iter().map(|r| r.chars().collect()).collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let preceded = i == 0 || is_separator(chars[i - 1]);
        let root = roots.iter().find(|root| {
            let end = i + root.len();
            preceded && end < chars.len() && folded[i..end] == root[..] && is_separator(chars[end])
        });
        let Some(root) = root else {
            i += 1;
            continue;
        };
        let start = i + root.len() + 1;
        let end =
            chars[start..].iter().position(|c| ends_segment(*c)).map_or(chars.len(), |p| start + p);
        let name: String = chars[start..end].iter().collect();
        if !name.trim().is_empty() {
            found.push(name);
        }
        i = end;
    }
    found
}

fn bracketed_after(text: &str, prefix: &str) -> Vec<String> {
    let lowered = text.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = lowered[from..].find(prefix) {
        let start = from + at + prefix.len();
        let Some(len) = lowered[start..].find(')') else { break };
        found.push(text[start..start + len].to_string());
        from = start + len;
    }
    found
}

fn unc_hosts(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i + 2 < chars.len() {
        let at_start =
            i == 0 || chars[i - 1].is_whitespace() || matches!(chars[i - 1], '"' | '\'' | '(');
        if at_start && chars[i] == '\\' && chars[i + 1] == '\\' && is_token(chars[i + 2]) {
            let start = i + 2;
            let end = chars[start..]
                .iter()
                .position(|c| !is_token(*c))
                .map_or(chars.len(), |p| start + p);
            if end < chars.len()
                && chars[end] == '\\'
                && chars[start..end].iter().any(|c| c.is_alphabetic())
            {
                found.push(chars[start..end].iter().collect());
            }
            i = end;
        } else {
            i += 1;
        }
    }
    found
}

fn domain_prefixes(text: &str, users: &[String]) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let folded: Vec<char> = chars.iter().map(|c| fold(*c)).collect();
    let names: Vec<Vec<char>> = users.iter().map(|u| u.chars().collect()).collect();
    let mut found = Vec::new();
    for i in 1..chars.len().saturating_sub(1) {
        if chars[i] != '\\'
            || chars[i - 1] == '\\'
            || chars[i - 1] == ':'
            || is_separator(chars[i + 1])
        {
            continue;
        }
        let names_a_user = names.iter().any(|name| {
            let end = i + 1 + name.len();
            end <= chars.len()
                && folded[i + 1..end] == name[..]
                && (end == chars.len() || !chars[end].is_alphanumeric())
        });
        if !names_a_user {
            continue;
        }
        let start = chars[..i].iter().rposition(|c| !is_token(*c)).map_or(0, |p| p + 1);
        let in_a_path = start > 0 && (is_separator(chars[start - 1]) || chars[start - 1] == ':');
        if start < i && !in_a_path {
            found.push(chars[start..i].iter().collect());
        }
    }
    found
}

fn replace_word(text: &str, needle: &str, with: &str) -> String {
    replace_bounded(text, needle, with, |c| !c.is_alphanumeric())
}

fn replace_segment(text: &str, needle: &str, with: &str) -> String {
    replace_bounded(text, needle, with, ends_segment)
}

fn replace_bounded(
    text: &str,
    needle: &str,
    with: &str,
    boundary: impl Fn(char) -> bool,
) -> String {
    let needle: Vec<char> = needle.chars().collect();
    if needle.is_empty() {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let end = i + needle.len();
        let matches = end <= chars.len()
            && chars[i..end].iter().map(|c| fold(*c)).eq(needle.iter().copied())
            && (i == 0 || boundary(chars[i - 1]))
            && (end == chars.len() || boundary(chars[end]));
        if matches {
            out.push_str(with);
            i = end;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn trim_urls(text: &str, trimmed: &mut usize) -> String {
    let lowered = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    loop {
        let Some(at) = ["https://", "http://"]
            .iter()
            .filter_map(|scheme| lowered[from..].find(scheme).map(|p| from + p))
            .min()
        else {
            out.push_str(&text[from..]);
            return out;
        };
        let scheme_len = if lowered[at..].starts_with("https://") { 8 } else { 7 };
        let host_start = at + scheme_len;
        let url_end = text[host_start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']'))
            .map_or(text.len(), |p| host_start + p);
        let host_end =
            text[host_start..url_end].find(['/', '?', '#']).map_or(url_end, |p| host_start + p);
        out.push_str(&text[from..host_end]);
        if url_end - host_end > 1 {
            out.push_str("/\u{2026}");
            *trimmed += 1;
        } else {
            out.push_str(&text[host_end..url_end]);
        }
        from = url_end;
    }
}

fn replace_emails(text: &str, count: &mut usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let local = |c: char| c.is_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-');
    let domain = |c: char| c.is_alphanumeric() || matches!(c, '.' | '-');
    while i < chars.len() {
        if chars[i] == '@' && i > 0 && local(chars[i - 1]) {
            let start = chars[..i].iter().rposition(|c| !local(*c)).map_or(0, |p| p + 1);
            let end =
                chars[i + 1..].iter().position(|c| !domain(*c)).map_or(chars.len(), |p| i + 1 + p);
            let host: String = chars[i + 1..end].iter().collect();
            if host.contains('.') && !host.starts_with('.') && !host.ends_with('.') {
                let local_bytes: usize = chars[start..i].iter().map(|c| c.len_utf8()).sum();
                out.truncate(out.len() - local_bytes);
                out.push_str("redacted@example.invalid");
                *count += 1;
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn replace_addresses(text: &str, known: &mut Vec<String>) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let at_boundary = i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '.');
        if chars[i].is_ascii_digit() && at_boundary {
            if let Some((end, address)) = dotted_quad(&chars, i) {
                let index = index_of(known, address);
                out.push_str(&format!("192.0.2.{}", index.min(254)));
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn dotted_quad(chars: &[char], start: usize) -> Option<(usize, String)> {
    let mut i = start;
    for octet in 0..4 {
        let digits_end =
            chars[i..].iter().position(|c| !c.is_ascii_digit()).map_or(chars.len(), |p| i + p);
        let digits: String = chars[i..digits_end].iter().collect();
        if digits.is_empty() || digits.len() > 3 || digits.parse::<u16>().ok()? > 255 {
            return None;
        }
        i = digits_end;
        if octet < 3 {
            if i >= chars.len() || chars[i] != '.' {
                return None;
            }
            i += 1;
        }
    }
    if i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '.') {
        return None;
    }
    Some((i, chars[start..i].iter().collect()))
}

fn index_of(known: &mut Vec<String>, value: String) -> usize {
    match known.iter().position(|k| *k == value) {
        Some(p) => p + 1,
        None => {
            known.push(value);
            known.len()
        }
    }
}

fn replace_sids(text: &str, domains: &mut Vec<String>) -> String {
    let lowered = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(at) = lowered[from..].find(SID_PREFIX) {
        let start = from + at;
        let body = start + SID_PREFIX.len();
        let mut groups = Vec::new();
        let mut cursor = body;
        while groups.len() < 4 {
            let digits_end = text[cursor..]
                .find(|c: char| !c.is_ascii_digit())
                .map_or(text.len(), |p| cursor + p);
            if digits_end == cursor {
                break;
            }
            groups.push(text[cursor..digits_end].to_string());
            cursor = digits_end;
            if groups.len() < 4
                && text[cursor..].starts_with('-')
                && text[cursor + 1..].starts_with(|c: char| c.is_ascii_digit())
            {
                cursor += 1;
            } else {
                break;
            }
        }
        if groups.len() < 3 {
            out.push_str(&text[from..body]);
            from = body;
            continue;
        }
        let index = index_of(domains, groups[..3].join("-"));
        out.push_str(&text[from..body]);
        out.push_str(&format!("0-0-{index}"));
        if let Some(rid) = groups.get(3) {
            out.push('-');
            out.push_str(rid);
        }
        from = cursor;
    }
    out.push_str(&text[from..]);
    out
}

fn replace_volume_guids(text: &str, volumes: &mut Vec<String>) -> String {
    const PREFIX: &str = "volume{";
    let lowered = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(at) = lowered[from..].find(PREFIX) {
        let start = from + at + PREFIX.len();
        let Some(close) = lowered[start..].find('}') else { break };
        let guid = &lowered[start..start + close];
        if guid.len() != 36 {
            out.push_str(&text[from..start]);
            from = start;
            continue;
        }
        let index = index_of(volumes, guid.to_string());
        out.push_str(&text[from..start]);
        out.push_str(&format!("00000000-0000-0000-0000-{index:012x}"));
        from = start + close;
    }
    out.push_str(&text[from..]);
    out
}

#[cfg(test)]
mod tests {
    use mm_core::{
        ArtifactSource, Candidate, CandidateId, NormalizedPath, Observation, ObservationKind,
        UrlZone,
    };

    use super::*;
    use crate::{Coverage, CoverageStatus, Target};

    fn observation(source: ArtifactSource, path: &str, kind: ObservationKind) -> Observation {
        Observation::about_path(source, NormalizedPath::parse(path).expect("a path"), kind)
    }

    fn exists() -> ObservationKind {
        ObservationKind::FileExists {
            size: 4096,
            created: None,
            modified: None,
            mft_modified: None,
            record: Some(77),
        }
    }

    fn report() -> Report {
        let mut candidate = Candidate::new(CandidateId(1), -8.0);
        candidate.observe(observation(
            ArtifactSource::Mft,
            r"C:\Users\Bob Smith\AppData\Local\Temp\svcupdate.exe",
            exists(),
        ));
        candidate.observe(observation(
            ArtifactSource::Registry {
                hive: "NTUSER.DAT (Bob Smith)".into(),
                key: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
            },
            r"C:\Users\Bob Smith\AppData\Local\Temp\svcupdate.exe",
            ObservationKind::Persistence {
                kind: mm_core::PersistenceKind::RunKey,
                raw_value: r"C:\Users\Bob Smith\AppData\Local\Temp\svcupdate.exe".into(),
            },
        ));
        candidate.observe(observation(
            ArtifactSource::ZoneIdentifier,
            r"C:\Users\Bob Smith\Downloads\invoice.exe",
            ObservationKind::DownloadedFrom {
                zone: UrlZone::Internet,
                host_url: Some("https://onedrive.live.com/download?cid=BOBSMITH42&resid=1".into()),
                referrer_url: Some("https://mail.example.com/".into()),
            },
        ));
        candidate.observe(observation(
            ArtifactSource::ScheduledTask { file: r"\Vendor\Update".into() },
            r"C:\Users\Bob Smith\AppData\Local\Temp\svcupdate.exe",
            ObservationKind::ProcessRunning {
                pid: 4,
                parent_pid: None,
                command_line: Some(r"BOBS-LAPTOP\Bob Smith ran \\FILESRV01\share\tool.exe --mail bob.smith@corp.example --to 10.1.2.3".into()),
            },
        ));
        candidate.observe(observation(
            ArtifactSource::RecycleBin,
            r"C:\$Recycle.Bin\S-1-5-21-1111111111-2222222222-333333333-1001\$RABCDEF.exe",
            ObservationKind::FileDeleted { when: None, record: None, sequence: None },
        ));
        candidate.evidence.push(mm_core::Evidence::new(
            "persistence_run_key",
            3.2,
            "wired to run again from NTUSER.DAT (Bob Smith), pointing at C:\\Users\\Bob Smith\\AppData\\Local\\Temp\\svcupdate.exe",
        ));

        let mut coverage = Coverage::default();
        coverage.record("NTUSER.DAT (Bob Smith)", CoverageStatus::Read { observations: 12 });
        coverage.record("$MFT", CoverageStatus::Read { observations: 900 });

        let mut report = Report::new(
            "0.1.0",
            "WinRE",
            Target {
                display_name: "D:".into(),
                device_path: r"\\?\Volume{0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fa}".into(),
                volume_serial: "b1a2c3d4e5f60718".into(),
            },
            vec![candidate],
            coverage,
            false,
        );
        report.set_case_directory(r"C:\Users\Bob Smith\Desktop\malmathic-case");
        report
    }

    fn redacted(options: Options) -> (Report, Redaction, String) {
        let (report, redaction) = redact(&report(), options).expect("a report survives redaction");
        let json = report.to_json();
        (report, redaction, json)
    }

    #[test]
    fn nothing_that_names_the_person_or_the_machine_survives() {
        let (report, _, json) = redacted(Options::default());
        for secret in [
            "Bob",
            "bob",
            "BOBSMITH42",
            "BOBS-LAPTOP",
            "FILESRV01",
            "corp.example",
            "10.1.2.3",
            "1111111111",
            "2222222222",
            "0b1c2d3e",
            "b1a2c3d4e5f60718",
            "malmathic-case",
            "Desktop",
        ] {
            assert!(!json.contains(secret), "{secret} survived:\n{json}");
        }
        assert!(report.case_directory.is_none());
        assert_eq!(report.environment, "WinRE · redacted");
        let text = crate::text::render(&report);
        assert!(!text.contains("Bob"), "{text}");
        assert!(text.contains("redacted"), "{text}");
    }

    #[test]
    fn identifiers_are_replaced_consistently_and_the_structure_is_kept() {
        let (report, redaction, json) = redacted(Options::default());
        let candidate = &report.candidates[0];
        assert_eq!(
            candidate.path.as_ref().unwrap().raw(),
            r"C:\Users\user1\AppData\Local\Temp\svcupdate.exe"
        );
        assert!(json.contains(r"C:\\Users\\user1\\Downloads\\invoice.exe"), "{json}");
        assert!(json.contains("NTUSER.DAT (user1)"), "{json}");
        assert!(json.contains("host1\\\\user1 ran \\\\\\\\host2\\\\share\\\\tool.exe"), "{json}");
        assert!(json.contains("redacted@example.invalid"), "{json}");
        assert!(json.contains("192.0.2.1"), "{json}");
        assert!(json.contains("S-1-5-21-0-0-1-1001"), "{json}");
        assert!(
            json.contains("s-1-5-21-0-0-1-1001"),
            "the lowercase path key is a second copy: {json}"
        );
        assert!(json.contains("Volume{00000000-0000-0000-0000-000000000001}"), "{json}");
        assert_eq!(report.target.volume_serial, "0000000000000001");
        assert!(json.contains("https://onedrive.live.com/\u{2026}"), "{json}");
        assert!(json.contains("https://mail.example.com/\""), "{json}");
        let summary = redaction.describe();
        assert!(summary.contains("user names replaced: 1"), "{summary}");
        assert!(summary.contains("machine names replaced: 2"), "{summary}");
        assert!(summary.contains("URLs cut to their host: 1"), "{summary}");
    }

    #[test]
    fn urls_can_be_kept_whole_on_request() {
        let (_, _, json) = redacted(Options { keep_urls: true });
        assert!(
            json.contains("https://onedrive.live.com/download?cid=BOBSMITH42&resid=1"),
            "{json}"
        );
    }

    #[test]
    fn redacting_twice_changes_nothing_more() {
        let (once, _) = redact(&report(), Options::default()).unwrap();
        let (twice, _) = redact(&once, Options::default()).unwrap();
        assert_eq!(once.to_json(), twice.to_json());
    }

    #[test]
    fn well_known_profiles_and_unrelated_words_are_left_alone() {
        let mut candidate = Candidate::new(CandidateId(1), -8.0);
        candidate.observe(observation(
            ArtifactSource::Mft,
            r"C:\Users\Public\Desktop\public notice.exe",
            exists(),
        ));
        candidate.observe(observation(
            ArtifactSource::Mft,
            r"C:\Users\Иван\Documents\счёт.exe",
            exists(),
        ));
        candidate.observe(observation(
            ArtifactSource::Mft,
            r"C:\Users\al\Documents\et al.exe",
            exists(),
        ));
        let report = Report::new(
            "0.1.0",
            "live Windows",
            Target {
                display_name: "C:".into(),
                device_path: r"\\.\C:".into(),
                volume_serial: String::new(),
            },
            vec![candidate],
            Coverage::default(),
            false,
        );
        let (redacted, redaction) = redact(&report, Options::default()).unwrap();
        let json = redacted.to_json();
        assert!(json.contains(r"C:\\Users\\Public\\Desktop\\public notice.exe"), "{json}");
        assert!(json.contains(r"C:\\Users\\user1\\Documents\\счёт.exe"), "{json}");
        assert!(!json.contains("Иван"), "{json}");
        assert!(
            json.contains(r"C:\\Users\\user2\\Documents\\et al.exe"),
            "a two-letter name is only a path segment: {json}"
        );
        assert_eq!(redaction.users.len(), 2);
        assert!(redaction.hosts.is_empty(), "{:?}", redaction.hosts);
    }

    #[test]
    fn an_image_target_keeps_only_the_file_name() {
        let report = Report::new(
            "0.1.0",
            "image",
            Target {
                display_name:
                    r"D:\vms\ClientX\snapshot4\disk-000004.vmdk@1048576 — before the update".into(),
                device_path: r"D:\vms\ClientX\snapshot4\disk-000004.vmdk".into(),
                volume_serial: "1".into(),
            },
            Vec::new(),
            Coverage::default(),
            false,
        );
        let (redacted, _) = redact(&report, Options::default()).unwrap();
        assert_eq!(redacted.target.device_path, "disk-000004.vmdk");
        assert_eq!(redacted.target.display_name, "disk-000004.vmdk@1048576 — before the update");
    }

    #[test]
    fn the_scanners_handle_the_shapes_they_were_written_for() {
        assert_eq!(profile_names(r"c:\users\alice\x"), ["alice"]);
        assert_eq!(profile_names("C:/Users/Carol Danvers/Desktop"), ["Carol Danvers"]);
        assert_eq!(profile_names(r"C:\Documents and Settings\erin\x"), ["erin"]);
        assert!(profile_names(r"C:\Program Files\users_tool\x").is_empty());
        assert_eq!(bracketed_after("hive NTUSER.DAT (dave) read", "ntuser.dat ("), ["dave"]);
        assert_eq!(unc_hosts(r"copy \\SERVER\share\x \\?\Volume{a}\y \\.\C:"), ["SERVER"]);
        let users = ["alice".to_string(), "bob smith".to_string()];
        assert_eq!(
            domain_prefixes(r"CORP\alice and C:\Users\alice and PC-7\Bob Smith", &users),
            ["CORP", "PC-7"]
        );
        assert_eq!(replace_word("Bob, bob and bobby", "bob", "user1"), "user1, user1 and bobby");
        assert_eq!(replace_segment(r"\al\al.exe al", "al", "user2"), r"\user2\al.exe al");
        let mut n = 0;
        assert_eq!(
            trim_urls("see https://a.example/p?q=1 and http://b.example", &mut n),
            "see https://a.example/\u{2026} and http://b.example"
        );
        assert_eq!(n, 1);
        let mut domains = Vec::new();
        assert_eq!(
            replace_sids(
                "S-1-5-21-1-2-3-500 and s-1-5-21-1-2-3 and S-1-5-18 and S-1-5-21-9-9-9-1001-x",
                &mut domains
            ),
            "S-1-5-21-0-0-1-500 and s-1-5-21-0-0-1 and S-1-5-18 and S-1-5-21-0-0-2-1001-x"
        );
        let mut addresses = Vec::new();
        assert_eq!(
            replace_addresses("v1.2.3.4 at 10.0.0.1 and 999.1.1.1", &mut addresses),
            "v1.2.3.4 at 192.0.2.1 and 999.1.1.1"
        );
    }
}
