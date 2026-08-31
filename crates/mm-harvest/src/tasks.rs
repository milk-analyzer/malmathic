use mm_core::{
    ArtifactSource, FileHash, NormalizedPath, Observation, ObservationKind, PersistenceKind,
};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::Harvested;

const MAX_EVENTS: usize = 500_000;
const MAX_DEPTH: usize = 64;
const MAX_TEXT: usize = 64 * 1024;
const MAX_ACTIONS: usize = 512;
const MAX_TRIGGERS: usize = 512;
const MAX_PRINCIPALS: usize = 64;
const MAX_FIELD: usize = 4096;
const MAX_NOTE: usize = 160;
const MAX_TRIGGER_SUMMARY: usize = 512;

pub fn harvest(xml: &[u8], task_path: &str) -> Harvested {
    let doc = decode(xml);
    if doc.is_empty() {
        return Vec::new();
    }
    let task = parse(&doc);
    build(&task, task_path)
}

fn decode(bytes: &[u8]) -> String {
    let mut s = match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, false),
        _ => match sniff_utf16(bytes) {
            Some(true) => decode_utf16(bytes, true),
            Some(false) => decode_utf16(bytes, false),
            None => String::from_utf8_lossy(bytes).into_owned(),
        },
    };
    let leading = s.len() - s.trim_start_matches('\u{feff}').len();
    if leading > 0 {
        s.drain(..leading);
    }
    s
}

fn sniff_utf16(bytes: &[u8]) -> Option<bool> {
    let sample = bytes.get(..bytes.len().min(512)).unwrap_or(bytes);
    if sample.len() < 4 {
        return None;
    }
    let (mut even, mut odd) = (0usize, 0usize);
    for (i, b) in sample.iter().enumerate() {
        if *b == 0 {
            if i % 2 == 0 {
                even += 1;
            } else {
                odd += 1;
            }
        }
    }
    let (winner, loser, little_endian) =
        if odd > even { (odd, even, true) } else { (even, odd, false) };
    let threshold = sample.len() / 4;
    if winner > threshold && winner > loser.saturating_mul(4) {
        Some(little_endian)
    } else {
        None
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units = bytes.as_chunks::<2>().0.iter().map(|&c| {
        if little_endian {
            u16::from_le_bytes(c)
        } else {
            u16::from_be_bytes(c)
        }
    });
    char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
}

#[derive(Default)]
struct Exec {
    command: String,
    arguments: String,
    working_dir: String,
}

impl Exec {
    fn is_empty(&self) -> bool {
        self.command.is_empty() && self.arguments.is_empty() && self.working_dir.is_empty()
    }
}

#[derive(Default)]
struct Com {
    class_id: String,
    data: String,
}

impl Com {
    fn is_empty(&self) -> bool {
        self.class_id.is_empty() && self.data.is_empty()
    }
}

enum Action {
    Exec(Exec),
    Com(Com),
}

#[derive(Default)]
struct Principal {
    id: String,
    user_id: String,
    group_id: String,
    display_name: String,
    run_level: String,
    logon_type: String,
}

#[derive(Default)]
struct Trigger {
    name: String,
    name_lc: String,
    user_id: String,
    start_boundary: String,
    state_change: String,
    subscription: String,
    schedule: String,
    enabled: String,
}

#[derive(Default)]
struct Task {
    author: String,
    registered: String,
    hidden: Option<bool>,
    enabled: Option<bool>,
    context: String,
    actions: Vec<Action>,
    triggers: Vec<Trigger>,
    principals: Vec<Principal>,
}

#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Exec,
    Com,
    Trigger,
    Principal,
    RegInfo,
    Settings,
    Other,
}

#[derive(Default)]
struct Walk {
    stack: Vec<String>,
    suspended: Vec<String>,
    overflow: usize,
    skipping: Option<usize>,
    text: String,
    exec: Option<Exec>,
    com: Option<Com>,
    trigger: Option<Trigger>,
    principal: Option<Principal>,
}

fn parse(doc: &str) -> Task {
    let mut reader = Reader::from_str(doc);
    {
        let cfg = reader.config_mut();
        cfg.trim_text(false);
        cfg.check_end_names = false;
        cfg.allow_unmatched_ends = true;
        cfg.check_comments = false;
        cfg.allow_dangling_amp = true;
    }

    let mut task = Task::default();
    let mut walk = Walk::default();

    for _ in 0..MAX_EVENTS {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let (name, lower) = element_name(&e);
                walk.on_start(&mut task, &name, &lower, &e);
            }
            Ok(Event::Empty(e)) => {
                let (name, lower) = element_name(&e);
                walk.on_start(&mut task, &name, &lower, &e);
                walk.on_end(&mut task, &lower);
            }
            Ok(Event::End(e)) => {
                let lower = String::from_utf8_lossy(e.local_name().as_ref()).to_ascii_lowercase();
                walk.on_end(&mut task, &lower);
            }
            Ok(Event::Text(e)) => {
                if let Ok(t) = e.xml10_content() {
                    walk.push_text(&t);
                }
            }
            Ok(Event::CData(e)) => {
                if let Ok(t) = e.xml10_content() {
                    walk.push_text(&t);
                }
            }
            Ok(Event::GeneralRef(e)) => {
                walk.push_text(&resolve_entity(&e));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    walk.flush(&mut task);
    task
}

fn resolve_entity(e: &quick_xml::events::BytesRef) -> String {
    if let Ok(Some(c)) = e.resolve_char_ref() {
        return c.to_string();
    }
    let name = match e.decode() {
        Ok(n) => n.into_owned(),
        Err(_) => return String::new(),
    };
    match name.as_str() {
        "amp" => "&".to_string(),
        "lt" => "<".to_string(),
        "gt" => ">".to_string(),
        "apos" => "'".to_string(),
        "quot" => "\"".to_string(),
        other => format!("&{other};"),
    }
}

fn element_name(e: &BytesStart) -> (String, String) {
    let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
    let lower = name.to_ascii_lowercase();
    (name, lower)
}

impl Walk {
    fn parent_is(&self, name: &str) -> bool {
        self.stack.last().is_some_and(|s| s == name)
    }

    fn ctx(&self) -> Ctx {
        let depth = self.stack.len();
        if depth < 2 {
            return Ctx::Other;
        }
        match self.stack[depth - 2].as_str() {
            "exec" if self.exec.is_some() => Ctx::Exec,
            "comhandler" if self.com.is_some() => Ctx::Com,
            "principal" if self.principal.is_some() => Ctx::Principal,
            "registrationinfo" => Ctx::RegInfo,
            "settings" => Ctx::Settings,
            parent => {
                if self.trigger.as_ref().is_some_and(|t| t.name_lc == parent) {
                    Ctx::Trigger
                } else {
                    Ctx::Other
                }
            }
        }
    }

    fn on_start(&mut self, task: &mut Task, name: &str, lower: &str, e: &BytesStart) {
        if self.overflow > 0 || self.stack.len() >= MAX_DEPTH {
            self.overflow += 1;
            self.text.clear();
            return;
        }
        self.suspended.push(std::mem::take(&mut self.text));

        if self.skipping.is_none() && lower == "data" && self.parent_is("task") {
            self.skipping = Some(self.stack.len());
        }

        if self.skipping.is_some() {
            self.stack.push(lower.to_string());
            return;
        }

        match lower {
            "actions" => {
                let ctx = attr(e, "context");
                if !ctx.is_empty() {
                    task.context = ctx;
                }
            }
            "exec" => {
                self.close_exec(task);
                self.exec = Some(Exec::default());
            }
            "comhandler" => {
                self.close_com(task);
                self.com = Some(Com::default());
            }
            "principal" => {
                self.close_principal(task);
                self.principal = Some(Principal { id: attr(e, "id"), ..Principal::default() });
            }
            _ if self.parent_is("triggers") || lower.ends_with("trigger") => {
                self.close_trigger(task);
                self.trigger = Some(Trigger {
                    name: sanitize(name, MAX_NOTE),
                    name_lc: lower.to_string(),
                    ..Trigger::default()
                });
            }
            _ if lower.starts_with("scheduleby") => {
                if let Some(t) = self.trigger.as_mut() {
                    t.schedule = lower.to_string();
                }
            }
            _ => {}
        }

        self.stack.push(lower.to_string());
    }

    fn on_end(&mut self, task: &mut Task, lower: &str) {
        if self.overflow > 0 {
            self.overflow -= 1;
            self.text.clear();
            return;
        }
        let text = std::mem::take(&mut self.text);
        self.text = self.suspended.pop().unwrap_or_default();

        if self.skipping.is_some() {
            self.stack.pop();
            if self.skipping.is_some_and(|depth| self.stack.len() <= depth) {
                self.skipping = None;
            }
            return;
        }

        self.fold(&text);

        match self.ctx() {
            Ctx::Exec => {
                if let Some(x) = self.exec.as_mut() {
                    match lower {
                        "command" => x.command = sanitize(&text, MAX_FIELD),
                        "arguments" => x.arguments = sanitize(&text, MAX_FIELD),
                        "workingdirectory" => x.working_dir = sanitize(&text, MAX_FIELD),
                        _ => {}
                    }
                }
            }
            Ctx::Com => {
                if let Some(c) = self.com.as_mut() {
                    match lower {
                        "classid" => c.class_id = sanitize(&text, MAX_NOTE),
                        "data" => c.data = sanitize(&text, MAX_NOTE),
                        _ => {}
                    }
                }
            }
            Ctx::Trigger => {
                if let Some(t) = self.trigger.as_mut() {
                    match lower {
                        "userid" => t.user_id = sanitize(&text, MAX_NOTE),
                        "startboundary" => t.start_boundary = sanitize(&text, MAX_NOTE),
                        "statechange" => t.state_change = sanitize(&text, MAX_NOTE),
                        "subscription" => t.subscription = sanitize(&text, MAX_FIELD),
                        "enabled" => t.enabled = sanitize(&text, MAX_NOTE),
                        _ => {}
                    }
                }
            }
            Ctx::Principal => {
                if let Some(p) = self.principal.as_mut() {
                    match lower {
                        "userid" => p.user_id = sanitize(&text, MAX_NOTE),
                        "groupid" => p.group_id = sanitize(&text, MAX_NOTE),
                        "displayname" => p.display_name = sanitize(&text, MAX_NOTE),
                        "runlevel" => p.run_level = sanitize(&text, MAX_NOTE),
                        "logontype" => p.logon_type = sanitize(&text, MAX_NOTE),
                        _ => {}
                    }
                }
            }
            Ctx::RegInfo => match lower {
                "author" => task.author = sanitize(&text, MAX_NOTE),
                "date" => task.registered = sanitize(&text, MAX_NOTE),
                _ => {}
            },
            Ctx::Settings => match lower {
                "hidden" => task.hidden = parse_bool(&text),
                "enabled" => task.enabled = parse_bool(&text),
                _ => {}
            },
            Ctx::Other => {}
        }

        match lower {
            "exec" => self.close_exec(task),
            "comhandler" => self.close_com(task),
            "principal" => self.close_principal(task),
            _ => {
                if self.trigger.as_ref().is_some_and(|t| t.name_lc == lower) {
                    self.close_trigger(task);
                }
            }
        }

        self.stack.pop();
    }

    fn push_text(&mut self, s: &str) {
        let room = MAX_TEXT.saturating_sub(self.text.len());
        if room == 0 {
            return;
        }
        if s.len() <= room {
            self.text.push_str(s);
            return;
        }
        let mut end = room;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(head) = s.get(..end) {
            self.text.push_str(head);
        }
    }

    fn fold(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let mut end = text.len().min(MAX_FIELD);
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(head) = text.get(..end) {
            self.push_text(head);
        }
    }

    fn close_exec(&mut self, task: &mut Task) {
        if let Some(x) = self.exec.take() {
            if !x.is_empty() && task.actions.len() < MAX_ACTIONS {
                task.actions.push(Action::Exec(x));
            }
        }
    }

    fn close_com(&mut self, task: &mut Task) {
        if let Some(c) = self.com.take() {
            if !c.is_empty() && task.actions.len() < MAX_ACTIONS {
                task.actions.push(Action::Com(c));
            }
        }
    }

    fn close_principal(&mut self, task: &mut Task) {
        if let Some(p) = self.principal.take() {
            if task.principals.len() < MAX_PRINCIPALS {
                task.principals.push(p);
            }
        }
    }

    fn close_trigger(&mut self, task: &mut Task) {
        if let Some(t) = self.trigger.take() {
            if task.triggers.len() < MAX_TRIGGERS {
                task.triggers.push(t);
            }
        }
    }

    fn flush(&mut self, task: &mut Task) {
        self.close_exec(task);
        self.close_com(task);
        self.close_principal(task);
        self.close_trigger(task);
    }
}

fn attr(e: &BytesStart, want: &str) -> String {
    for a in e.attributes().flatten() {
        let key = String::from_utf8_lossy(a.key.local_name().as_ref()).to_ascii_lowercase();
        if key == want {
            return match a.unescape_value() {
                Ok(v) => sanitize(&v, MAX_NOTE),
                Err(_) => String::new(),
            };
        }
    }
    String::new()
}

fn build(task: &Task, task_path: &str) -> Harvested {
    let tail = context_segments(task);
    let mut out = Vec::with_capacity(task.actions.len());

    for action in &task.actions {
        let (mut parts, path) = match action {
            Action::Exec(x) => {
                let mut parts = Vec::new();
                parts.push(command_line(x));
                if !x.working_dir.is_empty() {
                    parts.push(format!("workdir: {}", x.working_dir));
                }
                (parts, exec_path(x))
            }
            Action::Com(c) => {
                let mut parts = Vec::new();
                parts.push(if c.class_id.is_empty() {
                    "ComHandler (no ClassId)".to_string()
                } else {
                    format!("ComHandler {}", c.class_id)
                });
                if !c.data.is_empty() {
                    parts.push(format!("data: {}", c.data));
                }
                (parts, None)
            }
        };
        parts.extend(tail.iter().cloned());

        out.push(Observation {
            source: ArtifactSource::ScheduledTask { file: task_path.to_string() },
            kind: ObservationKind::Persistence {
                kind: PersistenceKind::ScheduledTask,
                raw_value: parts.join(" | "),
            },
            path,
            hash: FileHash::default(),
        });
    }

    out
}

fn command_line(x: &Exec) -> String {
    match (x.command.is_empty(), x.arguments.is_empty()) {
        (true, true) => "(no command)".to_string(),
        (true, false) => format!("(no command) {}", x.arguments),
        (false, true) => x.command.clone(),
        (false, false) => format!("{} {}", x.command, x.arguments),
    }
}

fn exec_path(x: &Exec) -> Option<NormalizedPath> {
    let command = x.command.trim();
    if command.is_empty() {
        return None;
    }
    let line = if x.arguments.is_empty() {
        command.to_string()
    } else {
        format!("{command} {}", x.arguments)
    };
    match (NormalizedPath::from_command_line(&line), NormalizedPath::parse(command)) {
        (Some(split), Some(whole)) => {
            Some(if split_is_a_program_boundary(command, &split) { split } else { whole })
        }
        (split, whole) => split.or(whole),
    }
}

fn split_is_a_program_boundary(command: &str, split: &NormalizedPath) -> bool {
    if split.is_executable_extension() {
        return true;
    }
    match command.trim_matches('"').strip_prefix(split.raw()) {
        None => true,
        Some(rest) => {
            let rest = rest.trim_start();
            rest.is_empty() || rest.starts_with('-') || rest.starts_with('/')
        }
    }
}

fn context_segments(task: &Task) -> Vec<String> {
    let mut out = Vec::new();

    out.push(trigger_summary(task));

    if let Some(p) = principal_for(task) {
        let subject = if !p.user_id.is_empty() {
            Some(p.user_id.clone())
        } else if !p.group_id.is_empty() {
            Some(format!("group {}", p.group_id))
        } else if !p.display_name.is_empty() {
            Some(p.display_name.clone())
        } else {
            None
        };
        if let Some(subject) = subject {
            let sid = if p.user_id.is_empty() { &p.group_id } else { &p.user_id };
            match well_known(sid) {
                Some(friendly)
                    if !subject.to_ascii_uppercase().contains(&friendly.to_ascii_uppercase()) =>
                {
                    out.push(format!("runs as: {subject} ({friendly})"));
                }
                _ => out.push(format!("runs as: {subject}")),
            }
        }
        if !p.run_level.is_empty() {
            out.push(format!("runlevel: {}", p.run_level));
        }
        if !p.logon_type.is_empty() {
            out.push(format!("logon: {}", p.logon_type));
        }
    }

    if task.hidden == Some(true) {
        out.push("hidden".to_string());
    }
    if task.enabled == Some(false) {
        out.push("disabled".to_string());
    }
    if !task.author.is_empty() {
        out.push(format!("author: {}", task.author));
    }
    if !task.registered.is_empty() {
        out.push(format!("registered: {}", task.registered));
    }

    out
}

fn principal_for(task: &Task) -> Option<&Principal> {
    if !task.context.is_empty() {
        if let Some(p) = task.principals.iter().find(|p| p.id.eq_ignore_ascii_case(&task.context)) {
            return Some(p);
        }
    }
    task.principals.first()
}

fn trigger_summary(task: &Task) -> String {
    if task.triggers.is_empty() {
        return "triggers: none".to_string();
    }
    let mut out = String::from("triggers: ");
    let (mut used, mut shown) = (0usize, 0usize);
    for t in &task.triggers {
        let described = describe_trigger(t);
        let width = described.chars().count();
        if shown > 0 && used + width > MAX_TRIGGER_SUMMARY {
            break;
        }
        if shown > 0 {
            out.push_str(", ");
        }
        out.push_str(&described);
        used += width + 2;
        shown += 1;
    }
    let dropped = task.triggers.len() - shown;
    if dropped > 0 {
        out.push_str(&format!(", +{dropped} more"));
    }
    out
}

fn describe_trigger(t: &Trigger) -> String {
    let base = match t.name_lc.as_str() {
        "boottrigger" => "boot".to_string(),
        "logontrigger" => qualify("logon", &t.user_id),
        "timetrigger" => qualify("time", &t.start_boundary),
        "calendartrigger" => {
            let schedule = match t.schedule.as_str() {
                "schedulebyday" => "daily",
                "schedulebyweek" => "weekly",
                "schedulebymonth" => "monthly",
                "schedulebymonthdayofweek" => "monthly-dayofweek",
                _ => "calendar",
            };
            qualify(schedule, &t.start_boundary)
        }
        "eventtrigger" => match event_summary(&t.subscription) {
            Some(s) => format!("event({s})"),
            None => "event".to_string(),
        },
        "idletrigger" => "idle".to_string(),
        "registrationtrigger" => "registration".to_string(),
        "sessionstatechangetrigger" => qualify("session-change", &t.state_change),
        "wnfstatechangetrigger" => "wnf-state-change".to_string(),
        _ => t.name.clone(),
    };
    if parse_bool(&t.enabled) == Some(false) {
        format!("{base} [disabled]")
    } else {
        base
    }
}

fn qualify(base: &str, detail: &str) -> String {
    if detail.is_empty() {
        base.to_string()
    } else {
        format!("{base}({detail})")
    }
}

fn event_summary(subscription: &str) -> Option<String> {
    let channel = quoted_after(subscription, "Path=");
    let id = digits_after(subscription, "EventID=");
    match (channel, id) {
        (Some(c), Some(i)) => Some(format!("{c}:{i}")),
        (Some(c), None) => Some(c),
        (None, Some(i)) => Some(format!("id {i}")),
        (None, None) => None,
    }
}

fn quoted_after(haystack: &str, needle: &str) -> Option<String> {
    let rest = haystack.get(haystack.find(needle)? + needle.len()..)?;
    let mut chars = rest.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let value: String = chars.take_while(|c| *c != quote).take(MAX_NOTE).collect();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn digits_after(haystack: &str, needle: &str) -> Option<String> {
    let rest = haystack.get(haystack.find(needle)? + needle.len()..)?;
    let value: String =
        rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).take(10).collect();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn well_known(sid: &str) -> Option<&'static str> {
    let sid = sid.trim();
    for (needle, name) in [
        ("S-1-5-18", "SYSTEM"),
        ("LocalSystem", "SYSTEM"),
        ("NT AUTHORITY\\SYSTEM", "SYSTEM"),
        ("S-1-5-19", "LOCAL SERVICE"),
        ("S-1-5-20", "NETWORK SERVICE"),
        ("S-1-5-32-544", "Administrators"),
        ("S-1-5-32-545", "Users"),
        ("S-1-5-11", "Authenticated Users"),
        ("S-1-1-0", "Everyone"),
    ] {
        if sid.eq_ignore_ascii_case(needle) {
            return Some(name);
        }
    }
    None
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim() {
        v if v.eq_ignore_ascii_case("true") || v == "1" => Some(true),
        v if v.eq_ignore_ascii_case("false") || v == "0" => Some(false),
        _ => None,
    }
}

fn sanitize(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut pending_space = false;
    for c in s.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if c == ' ' {
            pending_space = !out.is_empty();
            continue;
        }
        if count >= max {
            out.push('…');
            break;
        }
        if pending_space {
            out.push(' ');
            count += 1;
            pending_space = false;
        }
        out.push(c);
        count += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut out = vec![0xFF, 0xFE];
        for unit in s.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    fn utf16be(s: &str) -> Vec<u8> {
        let mut out = vec![0xFE, 0xFF];
        for unit in s.encode_utf16() {
            out.extend_from_slice(&unit.to_be_bytes());
        }
        out
    }

    fn utf8_bom(s: &str) -> Vec<u8> {
        let mut out = vec![0xEF, 0xBB, 0xBF];
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn raw(o: &Observation) -> &str {
        match &o.kind {
            ObservationKind::Persistence { raw_value, .. } => raw_value,
            _ => panic!("expected a Persistence observation"),
        }
    }

    const TYPICAL: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-06-01T12:00:00</Date>
    <Author>WIN10\bob</Author>
    <URI>\Updater</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>WIN10\bob</UserId>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\bob\AppData\Roaming\updater.exe</Command>
      <Arguments>--silent -k netsvcs</Arguments>
      <WorkingDirectory>C:\Users\bob\AppData\Roaming</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#;

    #[test]
    fn a_well_formed_task_yields_its_action() {
        let obs = harvest(&utf16le(TYPICAL), "\\Updater");
        assert_eq!(obs.len(), 1);

        let o = &obs[0];
        assert_eq!(o.source, ArtifactSource::ScheduledTask { file: "\\Updater".into() });
        assert!(matches!(
            o.kind,
            ObservationKind::Persistence { kind: PersistenceKind::ScheduledTask, .. }
        ));
        assert_eq!(o.path.as_ref().unwrap().key(), "\\users\\bob\\appdata\\roaming\\updater.exe");
        assert!(o.identifies_something());
    }

    #[test]
    fn raw_value_carries_what_the_analyst_needs() {
        let obs = harvest(&utf16le(TYPICAL), "\\Updater");
        let r = raw(&obs[0]);

        assert!(r.contains("updater.exe --silent -k netsvcs"), "{r}");
        assert!(r.contains("triggers: logon(WIN10\\bob), boot"), "{r}");
        assert!(r.contains("runs as: S-1-5-18 (SYSTEM)"), "{r}");
        assert!(r.contains("runlevel: HighestAvailable"), "{r}");
        assert!(r.contains("hidden"), "{r}");
        assert!(r.contains("author: WIN10\\bob"), "{r}");
        assert!(r.contains("registered: 2024-06-01T12:00:00"), "{r}");
        assert!(r.contains("workdir: C:\\Users\\bob\\AppData\\Roaming"), "{r}");
        assert!(!r.contains('\n'), "{r}");
    }

    #[test]
    fn every_encoding_yields_the_same_observation() {
        let bom_le = harvest(&utf16le(TYPICAL), "t");
        let bom_be = harvest(&utf16be(TYPICAL), "t");
        let bom_u8 = harvest(&utf8_bom(TYPICAL), "t");
        let plain = harvest(TYPICAL.as_bytes(), "t");

        let mut headless = Vec::new();
        for unit in TYPICAL.encode_utf16() {
            headless.extend_from_slice(&unit.to_le_bytes());
        }
        let sniffed = harvest(&headless, "t");

        for set in [&bom_be, &bom_u8, &plain, &sniffed] {
            assert_eq!(set.len(), 1);
            assert_eq!(raw(&set[0]), raw(&bom_le[0]));
        }
    }

    #[test]
    fn utf16_without_a_bom_is_sniffed_in_both_byte_orders() {
        let doc = "<Task><Actions><Exec><Command>C:\\a\\b.exe</Command></Exec></Actions></Task>";
        for big_endian in [false, true] {
            let mut bytes = Vec::new();
            for unit in doc.encode_utf16() {
                bytes.extend_from_slice(&if big_endian {
                    unit.to_be_bytes()
                } else {
                    unit.to_le_bytes()
                });
            }
            let obs = harvest(&bytes, "t");
            assert_eq!(obs.len(), 1, "big_endian={big_endian}");
            assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\a\\b.exe");
        }
    }

    #[test]
    fn a_dangling_utf16_byte_does_not_panic() {
        let mut bytes = utf16le(TYPICAL);
        bytes.push(0x41);
        let obs = harvest(&bytes, "t");
        assert_eq!(obs.len(), 1);
    }

    #[test]
    fn an_unpaired_surrogate_becomes_a_replacement_char() {
        let mut bytes =
            utf16le("<Task><Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>");
        bytes.splice(2..2, [0x00, 0xD8]);
        let obs = harvest(&bytes, "t");
        assert!(obs.len() <= 1);
    }

    #[test]
    fn a_zero_length_buffer_yields_nothing() {
        assert!(harvest(&[], "t").is_empty());
        assert!(harvest(&[0xFF, 0xFE], "t").is_empty());
        assert!(harvest(&[0xEF, 0xBB, 0xBF], "t").is_empty());
    }

    #[test]
    fn truncation_at_any_offset_is_survivable() {
        let full = utf16le(TYPICAL);
        for cut in 0..full.len() {
            let obs = harvest(&full[..cut], "t");
            assert!(obs.len() <= 1, "cut at {cut} produced {}", obs.len());
        }
        let marker = "</Exec>";
        let idx = TYPICAL.find(marker).unwrap() + marker.len();
        let obs = harvest(&utf16le(&TYPICAL[..idx]), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(
            obs[0].path.as_ref().unwrap().key(),
            "\\users\\bob\\appdata\\roaming\\updater.exe"
        );
    }

    #[test]
    fn a_document_cut_inside_exec_still_yields_the_command() {
        let doc = "<Task><Actions><Exec><Command>C:\\Temp\\evil.exe</Command>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\temp\\evil.exe");
    }

    #[test]
    fn garbage_that_is_not_xml_at_all_yields_nothing() {
        assert!(harvest(b"not xml, just bytes", "t").is_empty());
        assert!(harvest(&[0u8; 1024], "t").is_empty());
        assert!(harvest(&(0u8..=255).collect::<Vec<u8>>(), "t").is_empty());
        assert!(harvest(b"<<<<<<<<<<>>>>>>>>>>", "t").is_empty());
        assert!(harvest(b"<Task", "t").is_empty());
    }

    #[test]
    fn mismatched_and_unclosed_tags_do_not_stop_the_walk() {
        let doc = "<Task><Actions><Exec><Command>C:\\a.exe</Wrong></Exec>\
                   <Exec><Command>C:\\b.exe</Command></Exec></Actions></Task>";
        let obs = harvest(doc.as_bytes(), "t");
        let keys: Vec<_> =
            obs.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect();
        assert!(keys.contains(&"\\b.exe".to_string()), "{keys:?}");
    }

    #[test]
    fn a_mangled_wrapper_element_does_not_hide_its_contents() {
        let doc = "<Task><BootTrigger/>\
                   <Exec><Command>C:\\orphan.exe</Command></Exec>\
                   <Principal id=\"A\"><UserId>S-1-5-18</UserId></Principal></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\orphan.exe");
        let r = raw(&obs[0]);
        assert!(r.contains("triggers: boot"), "{r}");
        assert!(r.contains("(SYSTEM)"), "{r}");
    }

    #[test]
    fn absurd_nesting_depth_is_bounded_not_fatal() {
        let mut doc = String::from("<Task>");
        for _ in 0..5000 {
            doc.push_str("<a>");
        }
        doc.push_str("<Actions><Exec><Command>C:\\deep.exe</Command></Exec></Actions>");
        for _ in 0..5000 {
            doc.push_str("</a>");
        }
        doc.push_str("</Task>");
        let obs = harvest(doc.as_bytes(), "t");
        assert!(obs.len() <= 1);
    }

    #[test]
    fn an_absurd_number_of_actions_is_capped() {
        let mut doc = String::from("<Task><Actions>");
        for i in 0..5000 {
            doc.push_str(&format!("<Exec><Command>C:\\a{i}.exe</Command></Exec>"));
        }
        doc.push_str("</Actions></Task>");
        let obs = harvest(doc.as_bytes(), "t");
        assert_eq!(obs.len(), MAX_ACTIONS);
    }

    #[test]
    fn an_enormous_field_is_capped_without_panicking() {
        let doc = format!(
            "<Task><Actions><Exec><Command>C:\\{}.exe</Command></Exec></Actions></Task>",
            "A".repeat(400_000)
        );
        let obs = harvest(doc.as_bytes(), "t");
        assert!(obs.len() <= 1);
        for o in &obs {
            assert!(raw(o).chars().count() < 16_000);
        }
    }

    #[test]
    fn multibyte_text_truncates_on_a_character_boundary() {
        let doc = format!(
            "<Task><Actions><Exec><Command>C:\\x.exe</Command><Arguments>{}</Arguments></Exec></Actions></Task>",
            "\u{1F600}\u{4E2D}".repeat(50_000)
        );
        let obs = harvest(doc.as_bytes(), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\x.exe");
    }

    #[test]
    fn every_action_becomes_its_own_observation() {
        let doc = r#"<Task><Actions>
            <Exec><Command>C:\a.exe</Command></Exec>
            <Exec><Command>C:\b.exe</Command><Arguments>-x</Arguments></Exec>
            <ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler>
        </Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 3);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\a.exe");
        assert_eq!(obs[1].path.as_ref().unwrap().key(), "\\b.exe");
        assert!(obs[2].path.is_none());
        assert!(raw(&obs[2]).contains("ComHandler {11111111-2222-3333-4444-555555555555}"));
    }

    #[test]
    fn com_handler_data_is_reported() {
        let doc = r#"<Task><Actions Context="Author"><ComHandler>
            <ClassId>{ABCD1234-0000-0000-0000-000000000001}</ClassId>
            <Data>&lt;config&gt;payload&lt;/config&gt;</Data>
        </ComHandler></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        let r = raw(&obs[0]);
        assert!(r.contains("{ABCD1234-0000-0000-0000-000000000001}"), "{r}");
        assert!(r.contains("data: <config>payload</config>"), "{r}");
    }

    #[test]
    fn an_empty_exec_produces_no_observation() {
        let obs = harvest(b"<Task><Actions><Exec/></Actions></Task>", "t");
        assert!(obs.is_empty());
        let obs = harvest(b"<Task><Actions><Exec><Command></Command></Exec></Actions></Task>", "t");
        assert!(obs.is_empty());
    }

    #[test]
    fn a_task_with_no_actions_produces_nothing() {
        let doc = "<Task><Triggers><BootTrigger/></Triggers><Actions/></Task>";
        assert!(harvest(&utf16le(doc), "t").is_empty());
    }

    #[test]
    fn empty_elements_are_read_like_open_close_pairs() {
        let doc = r#"<Task>
            <Triggers><BootTrigger/><IdleTrigger/></Triggers>
            <Settings><Hidden>true</Hidden></Settings>
            <Actions><Exec><Command>C:\a.exe</Command></Exec></Actions>
        </Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        let r = raw(&obs[0]);
        assert!(r.contains("triggers: boot, idle"), "{r}");
        assert!(r.contains("hidden"), "{r}");
    }

    #[test]
    fn each_trigger_type_is_named() {
        let cases = [
            ("<BootTrigger/>", "boot"),
            ("<IdleTrigger/>", "idle"),
            ("<RegistrationTrigger/>", "registration"),
            ("<LogonTrigger><UserId>bob</UserId></LogonTrigger>", "logon(bob)"),
            ("<LogonTrigger/>", "logon"),
            (
                "<TimeTrigger><StartBoundary>2024-01-01T03:00:00</StartBoundary></TimeTrigger>",
                "time(2024-01-01T03:00:00)",
            ),
            (
                "<CalendarTrigger><StartBoundary>2024-01-01T03:00:00</StartBoundary>\
                 <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>",
                "daily(2024-01-01T03:00:00)",
            ),
            (
                "<CalendarTrigger><ScheduleByWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>",
                "weekly",
            ),
            (
                "<CalendarTrigger><ScheduleByMonth><Months><January/></Months></ScheduleByMonth></CalendarTrigger>",
                "monthly",
            ),
            (
                "<SessionStateChangeTrigger><StateChange>ConsoleConnect</StateChange></SessionStateChangeTrigger>",
                "session-change(ConsoleConnect)",
            ),
            ("<WnfStateChangeTrigger><StateName>ABCD</StateName></WnfStateChangeTrigger>", "wnf-state-change"),
        ];
        for (trigger, expected) in cases {
            let doc = format!(
                "<Task><Triggers>{trigger}</Triggers>\
                 <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>"
            );
            let obs = harvest(&utf16le(&doc), "t");
            assert_eq!(obs.len(), 1, "{trigger}");
            assert!(
                raw(&obs[0]).contains(&format!("triggers: {expected}")),
                "{trigger} -> {}",
                raw(&obs[0])
            );
        }
    }

    #[test]
    fn an_event_trigger_surfaces_its_channel_and_event_id() {
        let doc = r#"<Task><Triggers><EventTrigger>
            <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4625]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
        </EventTrigger></Triggers>
        <Actions><Exec><Command>C:\a.exe</Command></Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        let r = raw(&obs[0]);
        assert!(r.contains("triggers: event(Security:4625)"), "{r}");
    }

    #[test]
    fn an_event_trigger_with_an_unparseable_subscription_is_still_an_event() {
        let doc = "<Task><Triggers><EventTrigger><Subscription>garbage</Subscription></EventTrigger></Triggers>\
                   <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert!(raw(&obs[0]).contains("triggers: event"));
    }

    #[test]
    fn a_disabled_trigger_says_so() {
        let doc = "<Task><Triggers><BootTrigger><Enabled>false</Enabled></BootTrigger></Triggers>\
                   <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert!(raw(&obs[0]).contains("triggers: boot [disabled]"), "{}", raw(&obs[0]));
    }

    #[test]
    fn an_unknown_trigger_element_is_reported_under_its_own_name() {
        let doc = "<Task><Triggers><FutureWindowsTrigger/></Triggers>\
                   <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert!(raw(&obs[0]).contains("FutureWindowsTrigger"), "{}", raw(&obs[0]));
    }

    #[test]
    fn a_task_with_no_triggers_says_so() {
        let doc = "<Task><Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert!(raw(&obs[0]).contains("triggers: none"), "{}", raw(&obs[0]));
    }

    #[test]
    fn a_trigger_userid_is_not_confused_with_the_principal() {
        let doc = r#"<Task>
            <Triggers><LogonTrigger><UserId>WIN\alice</UserId></LogonTrigger></Triggers>
            <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
            <Actions Context="Author"><Exec><Command>C:\a.exe</Command></Exec></Actions>
        </Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        let r = raw(&obs[0]);
        assert!(r.contains("logon(WIN\\alice)"), "{r}");
        assert!(r.contains("runs as: S-1-5-18 (SYSTEM)"), "{r}");
    }

    #[test]
    fn the_actions_context_selects_the_principal() {
        let doc = r#"<Task><Principals>
            <Principal id="Author"><UserId>WIN\bob</UserId></Principal>
            <Principal id="LocalSystem"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
        </Principals>
        <Actions Context="LocalSystem"><Exec><Command>C:\a.exe</Command></Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        let r = raw(&obs[0]);
        assert!(r.contains("runs as: S-1-5-18 (SYSTEM)"), "{r}");
        assert!(!r.contains("bob"), "{r}");
    }

    #[test]
    fn a_missing_context_falls_back_to_the_first_principal() {
        let doc = r#"<Task><Principals>
            <Principal id="Author"><UserId>WIN\bob</UserId><LogonType>InteractiveToken</LogonType></Principal>
        </Principals>
        <Actions><Exec><Command>C:\a.exe</Command></Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        let r = raw(&obs[0]);
        assert!(r.contains("runs as: WIN\\bob"), "{r}");
        assert!(r.contains("logon: InteractiveToken"), "{r}");
    }

    #[test]
    fn well_known_sids_are_named() {
        for (sid, name) in [
            ("S-1-5-18", "SYSTEM"),
            ("S-1-5-19", "LOCAL SERVICE"),
            ("S-1-5-20", "NETWORK SERVICE"),
            ("S-1-5-32-544", "Administrators"),
        ] {
            let doc = format!(
                "<Task><Principals><Principal id=\"A\"><UserId>{sid}</UserId></Principal></Principals>\
                 <Actions Context=\"A\"><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>"
            );
            let obs = harvest(&utf16le(&doc), "t");
            assert!(raw(&obs[0]).contains(&format!("runs as: {sid} ({name})")), "{}", raw(&obs[0]));
        }
    }

    #[test]
    fn a_textual_system_principal_is_not_double_labelled() {
        let doc = r#"<Task><Principals><Principal id="A"><UserId>LocalSystem</UserId></Principal></Principals>
            <Actions Context="A"><Exec><Command>C:\a.exe</Command></Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert!(raw(&obs[0]).contains("runs as: LocalSystem"), "{}", raw(&obs[0]));
    }

    #[test]
    fn a_textual_nt_authority_principal_is_not_double_labelled() {
        let doc = r#"<Task><Principals><Principal id="A"><UserId>NT AUTHORITY\SYSTEM</UserId></Principal></Principals>
            <Actions Context="A"><Exec><Command>C:\a.exe</Command></Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        let r = raw(&obs[0]);
        assert!(r.contains("runs as: NT AUTHORITY\\SYSTEM"), "{r}");
        assert!(!r.contains("(SYSTEM)"), "{r}");
    }

    #[test]
    fn a_group_principal_is_reported_as_a_group() {
        let doc = r#"<Task><Principals><Principal id="A"><GroupId>S-1-5-32-544</GroupId></Principal></Principals>
            <Actions Context="A"><Exec><Command>C:\a.exe</Command></Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert!(raw(&obs[0]).contains("runs as: group S-1-5-32-544"), "{}", raw(&obs[0]));
    }

    #[test]
    fn a_task_with_no_principal_omits_the_segment() {
        let doc = "<Task><Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert!(!raw(&obs[0]).contains("runs as"), "{}", raw(&obs[0]));
    }

    #[test]
    fn hidden_and_disabled_are_only_stated_when_true() {
        let doc = "<Task><Settings><Hidden>false</Hidden><Enabled>true</Enabled></Settings>\
                   <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let r = raw(&harvest(&utf16le(doc), "t")[0]).to_string();
        assert!(!r.contains("hidden"), "{r}");
        assert!(!r.contains("disabled"), "{r}");

        let doc = "<Task><Settings><Hidden>true</Hidden><Enabled>false</Enabled></Settings>\
                   <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let r = raw(&harvest(&utf16le(doc), "t")[0]).to_string();
        assert!(r.contains("hidden"), "{r}");
        assert!(r.contains("disabled"), "{r}");
    }

    #[test]
    fn trigger_enabled_does_not_disable_the_task() {
        let doc = "<Task><Triggers><BootTrigger><Enabled>false</Enabled></BootTrigger></Triggers>\
                   <Settings><Enabled>true</Enabled></Settings>\
                   <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let r = raw(&harvest(&utf16le(doc), "t")[0]).to_string();
        assert!(r.contains("boot [disabled]"), "{r}");
        assert!(!r.contains("| disabled"), "{r}");
    }

    #[test]
    fn a_namespace_prefix_does_not_hide_the_elements() {
        let doc = r#"<td:Task xmlns:td="http://schemas.microsoft.com/windows/2004/02/mit/task" version="1.3">
            <td:Triggers><td:BootTrigger/></td:Triggers>
            <td:Principals><td:Principal id="A"><td:UserId>S-1-5-18</td:UserId></td:Principal></td:Principals>
            <td:Settings><td:Hidden>true</td:Hidden></td:Settings>
            <td:Actions Context="A"><td:Exec><td:Command>C:\evil.exe</td:Command></td:Exec></td:Actions>
        </td:Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        let r = raw(&obs[0]);
        assert!(r.contains("triggers: boot"), "{r}");
        assert!(r.contains("(SYSTEM)"), "{r}");
        assert!(r.contains("hidden"), "{r}");
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\evil.exe");
    }

    #[test]
    fn every_schema_version_parses_the_same_way() {
        for version in ["1.0", "1.1", "1.2", "1.3", "1.4", "9.9", ""] {
            let doc = format!(
                "<Task version=\"{version}\"><Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>"
            );
            let obs = harvest(&utf16le(&doc), "t");
            assert_eq!(obs.len(), 1, "version {version}");
            assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\a.exe");
        }
    }

    #[test]
    fn a_vista_v1_0_task_parses() {
        let doc = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Microsoft Corporation</Author></RegistrationInfo>
  <Triggers><CalendarTrigger><StartBoundary>2006-11-02T02:00:00</StartBoundary>
    <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>
  <Principals><Principal id="LocalSystem"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="LocalSystem"><Exec><Command>%windir%\system32\defrag.exe</Command>
    <Arguments>-c -i -g -h</Arguments></Exec></Actions>
</Task>"#;
        let obs = harvest(&utf16le(doc), "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\windows\\system32\\defrag.exe");
        let r = raw(&obs[0]);
        assert!(r.contains("daily(2006-11-02T02:00:00)"), "{r}");
        assert!(r.contains("runs as: S-1-5-18 (SYSTEM)"), "{r}");
    }

    #[test]
    fn a_quoted_command_with_spaces_survives() {
        let doc = r#"<Task><Actions><Exec>
            <Command>"C:\Program Files\Thing\a b.exe"</Command><Arguments>-q</Arguments>
        </Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\program files\\thing\\a b.exe");
    }

    #[test]
    fn an_unquoted_command_with_spaces_uses_the_extension_boundary() {
        let doc = r#"<Task><Actions><Exec>
            <Command>C:\Program Files\Thing\a b.exe</Command><Arguments>-q</Arguments>
        </Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\program files\\thing\\a b.exe");
    }

    #[test]
    fn a_command_that_is_really_a_command_line_still_resolves() {
        let doc = r#"<Task><Actions><Exec>
            <Command>C:\Windows\System32\cmd.exe /c powershell -enc ZQB2AGkAbAA=</Command>
        </Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\windows\\system32\\cmd.exe");
        assert!(raw(&obs[0]).contains("powershell -enc"));
    }

    #[test]
    fn a_command_with_no_recognisable_path_still_reports_the_action() {
        let doc = "<Task><Actions><Exec><Command>notepad.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\notepad.exe");
    }

    #[test]
    fn arguments_alone_still_produce_an_observation() {
        let doc = "<Task><Actions><Exec><Arguments>-whatever</Arguments></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert!(obs[0].path.is_none());
        assert!(raw(&obs[0]).contains("-whatever"));
    }

    #[test]
    fn xml_entities_in_arguments_are_unescaped() {
        let doc = "<Task><Actions><Exec><Command>C:\\a.exe</Command>\
                   <Arguments>-x &amp; -y &lt;in&gt; &quot;q&quot;</Arguments></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert!(raw(&obs[0]).contains("-x & -y <in> \"q\""), "{}", raw(&obs[0]));
    }

    #[test]
    fn newlines_in_a_field_are_flattened() {
        let doc = "<Task><Actions><Exec><Command>C:\\a.exe</Command>\
                   <Arguments>-a\n-b\r\n\t-c</Arguments></Exec></Actions></Task>";
        let r = raw(&harvest(&utf16le(doc), "t")[0]).to_string();
        assert!(r.contains("-a -b -c"), "{r}");
        assert!(!r.contains('\n'));
    }

    #[test]
    fn cdata_content_is_read() {
        let doc = "<Task><Actions><Exec><Command><![CDATA[C:\\Temp\\evil.exe]]></Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\temp\\evil.exe");
    }

    #[test]
    fn comments_and_processing_instructions_are_ignored() {
        let doc = "<?xml version=\"1.0\"?><!-- planted --><Task><Actions><Exec>\
                   <!-- x --><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\a.exe");
    }

    #[test]
    fn boring_signed_system_tasks_are_reported_too() {
        let doc = r#"<Task><Principals><Principal id="A"><UserId>S-1-5-18</UserId></Principal></Principals>
            <Actions Context="A"><Exec><Command>C:\Windows\System32\svchost.exe</Command>
            <Arguments>-k netsvcs</Arguments></Exec></Actions></Task>"#;
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\windows\\system32\\svchost.exe");
    }

    #[test]
    fn the_task_path_is_echoed_verbatim() {
        let path = "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot";
        let obs = harvest(
            b"<Task><Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>",
            path,
        );
        assert_eq!(obs[0].source, ArtifactSource::ScheduledTask { file: path.into() });
        assert_eq!(obs[0].source.family(), "persistence");
    }

    #[test]
    fn the_persistence_kind_maps_to_t1053_005() {
        let obs = harvest(
            b"<Task><Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>",
            "t",
        );
        match obs[0].kind {
            ObservationKind::Persistence { kind, .. } => {
                assert_eq!(kind.attack_id(), "T1053.005");
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn unicode_whitespace_in_a_path_survives_verbatim() {
        let doc = "<Task><Actions><Exec><Command>C:\\Windows\u{a0}\\svchost.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\windows\u{a0}\\svchost.exe");
        assert!(raw(&obs[0]).contains('\u{a0}'));
    }

    #[test]
    fn sanitize_never_splits_a_codepoint() {
        let s = "\u{1F600}".repeat(10_000);
        let out = sanitize(&s, 8);
        assert!(out.chars().count() <= 9);
        assert!(out.starts_with('\u{1F600}'));
    }

    #[test]
    fn quoted_after_handles_hostile_input() {
        assert_eq!(quoted_after("", "Path="), None);
        assert_eq!(quoted_after("Path=", "Path="), None);
        assert_eq!(quoted_after("Path=x", "Path="), None);
        assert_eq!(quoted_after("Path=\"", "Path="), None);
        assert_eq!(quoted_after("Path=\"\"", "Path="), None);
        assert_eq!(quoted_after("Path=\"Se\u{e9}c\"", "Path="), Some("Se\u{e9}c".into()));
        assert_eq!(quoted_after("Path='S'", "Path="), Some("S".into()));
        assert_eq!(quoted_after("Path=\"Security", "Path="), Some("Security".into()));
    }

    #[test]
    fn digits_after_handles_hostile_input() {
        assert_eq!(digits_after("EventID=", "EventID="), None);
        assert_eq!(digits_after("EventID=abc", "EventID="), None);
        assert_eq!(digits_after("EventID=4625]", "EventID="), Some("4625".into()));
        assert_eq!(
            digits_after(&format!("EventID={}", "9".repeat(500)), "EventID="),
            Some("9".repeat(10))
        );
    }

    #[test]
    fn sniffing_is_not_fooled_by_short_or_binary_buffers() {
        assert_eq!(sniff_utf16(&[]), None);
        assert_eq!(sniff_utf16(b"<T"), None);
        assert_eq!(sniff_utf16(b"<Task version=\"1.2\">"), None);
        assert_eq!(sniff_utf16(&[0u8; 64]), None);
    }

    #[test]
    fn parse_bool_accepts_what_windows_writes() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool(" TRUE "), Some(true));
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool(""), None);
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn nul_padding_does_not_destroy_an_eight_bit_document() {
        let doc = b"<Task><Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        for pad in [1usize, 3, 5, 63, 100, 129, 255, 256, 511, 512, 1000] {
            let mut bytes = vec![0u8; pad];
            bytes.extend_from_slice(doc);
            let obs = harvest(&bytes, "t");
            assert_eq!(obs.len(), 1, "{pad} leading NULs lost the document");
            assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\a.exe", "pad {pad}");
        }
        let mut bytes = doc.to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 4097));
        assert_eq!(harvest(&bytes, "t").len(), 1);
    }

    #[test]
    fn sniffing_requires_one_parity_to_dominate_not_merely_lead() {
        assert_eq!(sniff_utf16(&[0u8; 129]), None);
        assert_eq!(sniff_utf16(&[0u8; 511]), None);
        let le: Vec<u8> = "<Task><Actions>".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(sniff_utf16(&le), Some(true));
        let be: Vec<u8> = "<Task><Actions>".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(sniff_utf16(&be), Some(false));
    }

    #[test]
    fn a_field_split_by_a_child_element_keeps_its_whole_value() {
        let doc = "<Task><Actions><Exec>\
                   <Command>C:\\Windows\\<x/>System32\\evil.exe</Command>\
                   <Arguments>-a<y></y>-b</Arguments></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\windows\\system32\\evil.exe");
        assert!(raw(&obs[0]).contains("-a-b"), "{}", raw(&obs[0]));
    }

    #[test]
    fn folding_a_child_back_does_not_contaminate_the_next_field() {
        let doc = "<Task><Actions>junk<Exec><Command>C:\\a.exe</Command>noise\
                   <Arguments>-x</Arguments></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\a.exe");
        let r = raw(&obs[0]);
        assert!(r.starts_with("C:\\a.exe -x"), "{r}");
        assert!(!r.contains("junk") && !r.contains("noise"), "{r}");
    }

    #[test]
    fn an_opaque_task_data_blob_cannot_forge_an_action() {
        let doc = "<Task>\
            <Data><Exec><Command>C:\\Windows\\System32\\notepad.exe</Command></Exec>\
                  <Triggers><BootTrigger/></Triggers>\
                  <Principal id=\"A\"><UserId>S-1-5-18</UserId></Principal>\
                  <Settings><Hidden>true</Hidden></Settings></Data>\
            <Actions><Exec><Command>C:\\evil.exe</Command></Exec></Actions></Task>";
        let obs = harvest(&utf16le(doc), "t");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].path.as_ref().unwrap().key(), "\\evil.exe");
        let r = raw(&obs[0]);
        assert!(r.contains("triggers: none"), "{r}");
        assert!(!r.contains("runs as"), "{r}");
        assert!(!r.contains("hidden"), "{r}");
    }

    #[test]
    fn skipping_task_data_leaves_everything_around_it_intact() {
        for data in ["<Data/>", "<Data></Data>", "<Data><a><b/></a></Data>"] {
            let doc = format!(
                "<Task>{data}<Triggers><BootTrigger/></Triggers>\
                 <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>"
            );
            let obs = harvest(&utf16le(&doc), "t");
            assert_eq!(obs.len(), 1, "{data}");
            assert!(raw(&obs[0]).contains("triggers: boot"), "{data} -> {}", raw(&obs[0]));
        }
        let doc = "<Task><Actions><ComHandler><ClassId>{1}</ClassId>\
                   <Data>payload</Data></ComHandler></Actions></Task>";
        assert!(raw(&harvest(&utf16le(doc), "t")[0]).contains("data: payload"));
    }

    #[test]
    fn a_spaced_command_with_no_extension_is_not_cut_at_the_first_space() {
        for (command, arguments, expected) in [
            (r"C:\Program Files\Sneaky\payload", "", r"\program files\sneaky\payload"),
            (
                r"C:\Program Files\Common Files\thing.tmp",
                "",
                r"\program files\common files\thing.tmp",
            ),
            (r"C:\Users\Public Documents\svc", "", r"\users\public documents\svc"),
            (r"C:\Temp\a b.tmp", "", r"\temp\a b.tmp"),
            (r"C:\Temp\a b.tmp", "-x", r"\temp\a b.tmp"),
            (
                r"C:\Windows\System32\cmd.exe /c powershell -enc ZQ==",
                "",
                r"\windows\system32\cmd.exe",
            ),
            ("powershell -enc AAA", "", r"\powershell"),
            (r"C:\Program Files\Thing\a b.exe", "-q", r"\program files\thing\a b.exe"),
            (r#""C:\Program Files\Thing\a b.exe""#, "-q", r"\program files\thing\a b.exe"),
            (r"%windir%\system32\defrag.exe", "-c -i -g -h", r"\windows\system32\defrag.exe"),
            ("notepad.exe", "", r"\notepad.exe"),
        ] {
            let doc = format!(
                "<Task><Actions><Exec><Command>{command}</Command>\
                 <Arguments>{arguments}</Arguments></Exec></Actions></Task>"
            );
            let obs = harvest(&utf16le(&doc), "t");
            assert_eq!(obs.len(), 1, "{command:?}");
            assert_eq!(
                obs[0].path.as_ref().unwrap().key(),
                expected,
                "{command:?} + {arguments:?}"
            );
        }
    }

    #[test]
    fn the_trigger_list_cannot_multiply_across_actions() {
        let mut doc = String::from("<Task><Triggers>");
        for i in 0..600 {
            doc.push_str(&format!("<{}{i}Trigger/>", "Z".repeat(150)));
        }
        doc.push_str("</Triggers><Actions>");
        for i in 0..600 {
            doc.push_str(&format!("<Exec><Command>C:\\a{i}.exe</Command></Exec>"));
        }
        doc.push_str("</Actions></Task>");

        let obs = harvest(doc.as_bytes(), "t");
        assert_eq!(obs.len(), MAX_ACTIONS);
        let total: usize = obs.iter().map(|o| raw(o).len()).sum();
        assert!(total < 10 * doc.len(), "raw_value total {total} from a {} byte file", doc.len());
        assert!(raw(&obs[0]).contains(" more"), "{}", raw(&obs[0]));
    }

    #[test]
    fn a_short_trigger_list_is_not_capped_or_annotated() {
        let doc = "<Task><Triggers><BootTrigger/><IdleTrigger/></Triggers>\
                   <Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>";
        let r = raw(&harvest(&utf16le(doc), "t")[0]).to_string();
        assert!(r.contains("triggers: boot, idle"), "{r}");
        assert!(!r.contains("more"), "{r}");
    }

    #[test]
    fn structural_bombs_return_bounded() {
        let bombs = [
            "<".repeat(50_000),
            "&".repeat(50_000),
            "</a>".repeat(50_000),
            "<a/>".repeat(50_000),
            "<Exec>".repeat(50_000),
            "<Exec><Command>C:\\a.exe".repeat(20_000),
            "<Triggers>".repeat(20_000),
            "<Principal id=\"A\">".repeat(20_000),
            format!("<{}>", "z".repeat(200_000)),
            format!(
                "<Task><Actions><Exec><Command>&{};</Command></Exec></Actions></Task>",
                "z".repeat(200_000)
            ),
            format!("<Task><Actions><Exec><Command><![CDATA[{}", "A".repeat(200_000)),
            format!("<!DOCTYPE Task [{}", "<!ENTITY a \"b\">".repeat(20_000)),
            format!("{}{}", "<a>".repeat(200), "</a>".repeat(50_000)),
            format!(
                "<Task><Actions><Exec><Command>{}</Command></Exec></Actions></Task>",
                "C:\\a<x/>".repeat(20_000)
            ),
            {
                let mut s = String::new();
                for _ in 0..63 {
                    s.push_str("<a>");
                    s.push_str(&"T".repeat(50_000));
                }
                s
            },
        ];
        for (i, bomb) in bombs.iter().enumerate() {
            let start = std::time::Instant::now();
            let obs = harvest(bomb.as_bytes(), "t");
            assert!(obs.len() <= MAX_ACTIONS, "bomb {i}");
            assert!(start.elapsed().as_secs() < 10, "bomb {i} took {:?}", start.elapsed());
        }
    }

    #[test]
    fn a_declared_entity_is_never_expanded() {
        let doc = "<!DOCTYPE Task [<!ENTITY a \"aaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]>\
                   <Task><Actions><Exec><Command>C:\\x.exe</Command>\
                   <Arguments>&b;&b;</Arguments></Exec></Actions></Task>";
        let obs = harvest(doc.as_bytes(), "t");
        assert_eq!(obs.len(), 1);
        assert!(raw(&obs[0]).contains("&b;&b;"), "{}", raw(&obs[0]));
    }

    #[test]
    fn malformed_character_references_are_left_alone() {
        let doc = "<Task><Actions><Exec><Command>C:\\a.exe</Command>\
                   <Arguments>&#x41;|&#66;|&#xD800;|&#x110000;|&#999999999999;|&;|&#;|&#x;</Arguments>\
                   </Exec></Actions></Task>";
        let obs = harvest(doc.as_bytes(), "t");
        assert_eq!(obs.len(), 1);
        let r = raw(&obs[0]);
        assert!(r.contains("A|B|"), "{r}");
        assert!(r.contains("&#xD800;"), "{r}");
        assert!(r.contains("&#x110000;"), "{r}");
    }

    #[test]
    fn truncation_never_grows_the_result_in_any_encoding() {
        for bytes in [utf16le(TYPICAL), utf16be(TYPICAL), utf8_bom(TYPICAL), TYPICAL.into()] {
            let full = harvest(&bytes, "t").len();
            for cut in 0..=bytes.len() {
                let n = harvest(&bytes[..cut], "t").len();
                assert!(n <= full, "cut at {cut} gave {n}, whole document gives {full}");
            }
        }
    }

    #[test]
    fn a_fuzz_sweep_never_panics() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let corpus: Vec<Vec<u8>> =
            vec![utf16le(TYPICAL), TYPICAL.as_bytes().to_vec(), utf16be(TYPICAL)];
        for seed in &corpus {
            for _ in 0..300 {
                let mut b = seed.clone();
                if b.is_empty() {
                    continue;
                }
                for _ in 0..12 {
                    let i = (next() as usize) % b.len();
                    b[i] = (next() % 256) as u8;
                }
                let cut = (next() as usize) % b.len();
                let _ = harvest(&b[..cut], "fuzz");
                let _ = harvest(&b, "fuzz");
            }
        }
    }
}
