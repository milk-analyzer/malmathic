use std::cell::Cell;
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use chrono::{DateTime, Utc};
use mm_core::{from_filetime, ArtifactSource, NormalizedPath, Observation, ObservationKind};

use crate::{Harvested, HiveSource};

const USERASSIST_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

const V3_LEN: usize = 16;
const V5_LEN: usize = 72;
const RUN_COUNT_OFF: usize = 4;
const V3_TIME_OFF: usize = 8;
const V5_TIME_OFF: usize = 0x3c;

pub fn harvest(hive: &[u8], source: &HiveSource) -> Harvested {
    match source {
        HiveSource::NtUser { user } => guarded(|| user_assist(hive, user)),
        HiveSource::System => guarded(|| bam_dam(hive)),
        HiveSource::Software | HiveSource::UsrClass { .. } => Vec::new(),
    }
}

fn guarded(parse: impl FnOnce() -> Harvested) -> Harvested {
    catch_unwind(AssertUnwindSafe(parse)).unwrap_or_else(|_| {
        log::warn!("hive parser panicked; discarding this hive's user-activity observations");
        Vec::new()
    })
}

fn user_assist(bytes: &[u8], profile: &str) -> Harvested {
    let Some((hive, root)) = Hive::open(bytes) else {
        return Vec::new();
    };
    let Some(user_assist) = hive.subpath(&root, USERASSIST_KEY) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for guid_key in hive.subkeys(&user_assist) {
        let Some(count) = hive.subkey(&guid_key, "Count") else {
            continue;
        };
        for value in hive.values(&count) {
            let Some(entry) = decode_entry_name(&value.name) else {
                continue;
            };
            let Some(path) = NormalizedPath::parse(&resolve_known_folder(&entry, profile)) else {
                continue;
            };
            let (when, run_count) = read_record(value.binary().unwrap_or_default());
            out.push(Observation::about_path(
                ArtifactSource::UserAssist,
                path,
                ObservationKind::Executed { when, run_count },
            ));
        }
    }
    out
}

fn decode_entry_name(raw: &str) -> Option<String> {
    let name = rot13(raw.trim_end_matches('\0'));

    let Some(rest) = name.strip_prefix("UEME_") else {
        return non_empty(name);
    };
    if rest.starts_with("CTL") {
        return None;
    }
    let (_verb, program) = rest.split_once(':')?;
    non_empty(program.to_string())
}

fn non_empty(s: String) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

fn read_record(data: &[u8]) -> (Option<DateTime<Utc>>, Option<u32>) {
    let time_off = if data.len() >= V5_LEN {
        V5_TIME_OFF
    } else if data.len() == V3_LEN {
        V3_TIME_OFF
    } else {
        return (None, None);
    };
    (read_u64(data, time_off).and_then(from_filetime), read_u32(data, RUN_COUNT_OFF))
}

fn resolve_known_folder(entry: &str, profile: &str) -> String {
    let Some(end) = guid_prefix_len(entry) else {
        return entry.to_string();
    };
    let Some(guid) = entry.get(1..end - 1) else {
        return entry.to_string();
    };
    let Some(folder) = KNOWN_FOLDERS
        .iter()
        .find(|(id, _)| id.eq_ignore_ascii_case(guid))
        .map(|(_, folder)| *folder)
    else {
        return entry.to_string();
    };
    let folder = match profile.trim() {
        "" => folder.to_string(),
        user => folder.replace("%USERPROFILE%", &format!("%SystemDrive%\\Users\\{user}")),
    };
    let rest = entry.get(end..).unwrap_or("").trim_start_matches('\\');
    if rest.is_empty() {
        folder
    } else {
        format!("{folder}\\{rest}")
    }
}

fn guid_prefix_len(s: &str) -> Option<usize> {
    const GUID_LEN: usize = 38;
    let bytes = s.as_bytes();
    if bytes.len() < GUID_LEN || bytes[0] != b'{' || bytes[GUID_LEN - 1] != b'}' {
        return None;
    }
    let inner = bytes.get(1..GUID_LEN - 1)?;
    let shaped = inner.iter().enumerate().all(|(i, b)| match i {
        8 | 13 | 18 | 23 => *b == b'-',
        _ => b.is_ascii_hexdigit(),
    });
    shaped.then_some(GUID_LEN)
}

const KNOWN_FOLDERS: &[(&str, &str)] = &[
    ("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7", "%SystemRoot%\\System32"),
    ("D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27", "%SystemRoot%\\SysWOW64"),
    ("F38BF404-1D43-42F2-9305-67DE0B28FC23", "%SystemRoot%"),
    ("FD228CB7-AE11-4AE3-864C-16F3910AB8FE", "%SystemRoot%\\Fonts"),
    ("8AD10C31-2ADB-4296-A8F7-E4701232C972", "%SystemRoot%\\Resources"),
    ("905E63B6-C1BF-494E-B29C-65B732D3D21A", "%ProgramFiles%"),
    ("6D809377-6AF0-444B-8957-A3773F02200E", "%ProgramFiles%"),
    ("7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E", "%ProgramFiles(x86)%"),
    ("F7F1ED05-9F6D-47A2-AAAE-29D317C6F066", "%ProgramFiles%\\Common Files"),
    ("6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D", "%ProgramFiles%\\Common Files"),
    ("DE974D24-D9C6-4D3E-BF91-F4455120B917", "%ProgramFiles(x86)%\\Common Files"),
    ("5CD7AEE2-2219-4A67-B85D-6C9CE15660CB", "%USERPROFILE%\\AppData\\Local\\Programs"),
    ("BCBD3057-CA5C-4622-B42D-BC56DB0AE516", "%USERPROFILE%\\AppData\\Local\\Programs\\Common"),
    ("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97", "%ProgramData%"),
    ("A4115719-D62E-491D-AA7C-E74B8BE3B067", "%ProgramData%\\Microsoft\\Windows\\Start Menu"),
    ("0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs"),
    ("82A5EA35-D9CD-47C5-9629-E15D2F714E6E", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"),
    ("D0384E7D-BAC3-4797-8F14-CBA229B392B5", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"),
    ("B94237E7-57AC-4347-9151-B08C6C32D1F7", "%ProgramData%\\Microsoft\\Windows\\Templates"),
    ("C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D", "%ProgramData%\\OEM Links"),
    ("0762D272-C50A-4BB0-A382-697DCD729B80", "%SystemDrive%\\Users"),
    ("DFDF76A2-C82A-4D63-906A-5644AC457385", "%SystemDrive%\\Users\\Public"),
    ("C4AA340D-F20F-4863-AFEF-F87EF2E6BA25", "%SystemDrive%\\Users\\Public\\Desktop"),
    ("ED4824AF-DCE4-45A8-81E2-FC7965083634", "%SystemDrive%\\Users\\Public\\Documents"),
    ("3D644C9B-1FB8-4F30-9B45-F670235F79C0", "%SystemDrive%\\Users\\Public\\Downloads"),
    ("3214FAB5-9757-4298-BB61-92A9DEAA44FF", "%SystemDrive%\\Users\\Public\\Music"),
    ("B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5", "%SystemDrive%\\Users\\Public\\Pictures"),
    ("2400183A-6185-49FB-A2D8-4A392A602BA3", "%SystemDrive%\\Users\\Public\\Videos"),
    ("5E6C858F-0E22-4760-9AFE-EA3317B67173", "%USERPROFILE%"),
    ("B4BFCC3A-DB2C-424C-B029-7FE99A87C641", "%USERPROFILE%\\Desktop"),
    ("FDD39AD0-238F-46AF-ADB4-6C85480369C7", "%USERPROFILE%\\Documents"),
    ("374DE290-123F-4565-9164-39C4925E467B", "%USERPROFILE%\\Downloads"),
    ("4BD8D571-6D19-48D3-BE97-422220080E43", "%USERPROFILE%\\Music"),
    ("33E28130-4E1E-4676-835A-98395C3BC3BB", "%USERPROFILE%\\Pictures"),
    ("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "%USERPROFILE%\\Videos"),
    ("AB5FB87B-7CE2-4F83-915D-550846C9537B", "%USERPROFILE%\\Pictures\\Camera Roll"),
    ("B7BEDE81-DF94-4682-A7D8-57A52620B86F", "%USERPROFILE%\\Pictures\\Screenshots"),
    ("1777F761-68AD-4D8A-87BD-30B759FA33DD", "%USERPROFILE%\\Favorites"),
    ("56784854-C6CB-462B-8169-88E350ACB882", "%USERPROFILE%\\Contacts"),
    ("BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968", "%USERPROFILE%\\Links"),
    ("4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4", "%USERPROFILE%\\Saved Games"),
    ("31C0DD25-9439-4F12-BF41-7FF4EDA38722", "%USERPROFILE%\\3D Objects"),
    ("F1B32785-6FBA-4FCF-9D55-7B8E7F157091", "%USERPROFILE%\\AppData\\Local"),
    ("A520A1A4-1780-4FF6-BD18-167343C5AF16", "%USERPROFILE%\\AppData\\LocalLow"),
    ("3EB685DB-65F9-4CF6-A03A-E3EF65729F3D", "%USERPROFILE%\\AppData\\Roaming"),
    ("625B53C3-AB48-4EC1-BA1F-A1EF4146FC19", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"),
    ("A77F5D77-2E2B-44C3-A6A2-ABA601054A51", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"),
    ("B97D20BB-F46A-4C97-BA10-5E3608430854", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"),
    ("724EF170-A42D-4FEF-9F26-B60E846FBA4F", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"),
    ("8983036C-27C0-404B-8F08-102D10DCFD74", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\SendTo"),
    ("AE50C081-EBD2-438A-8655-8A092E34987A", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent"),
    ("A63293E8-664E-48DB-A079-DF759E0509F7", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Templates"),
    ("C5ABBF53-E17F-4121-8900-86626FC2C973", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts"),
    ("9274BD8D-CFD1-41C3-B35E-B13F55A758F4", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts"),
    ("008CA0B1-55B4-4C56-B8A8-4DE4B299D3BE", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\AccountPictures"),
    ("52A4F021-7B75-48A9-9F6B-4B87A210BC8F", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch"),
    ("9E3995AB-1F9C-4F13-B827-48B24B6C7174", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned"),
    ("BCB5256F-79F6-4CEE-B725-DC34E402FD46", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\ImplicitAppShortcuts"),
    ("054FAE61-4DD8-4787-80B6-090220C4B700", "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\GameExplorer"),
];

const BAM_SERVICES: &[&str] = &["bam", "dam"];
const BAM_SUBPATHS: &[&str] = &["State\\UserSettings", "UserSettings"];

const BAM_TIME_LEN: usize = 8;

fn bam_dam(bytes: &[u8]) -> Harvested {
    let Some((hive, root)) = Hive::open(bytes) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut seen: HashSet<(String, Option<DateTime<Utc>>)> = HashSet::new();
    for control_set in hive.subkeys(&root) {
        if !is_control_set(&control_set.name) {
            continue;
        }
        let Some(services) = hive.subkey(&control_set, "Services") else {
            continue;
        };
        for moderator in BAM_SERVICES {
            let Some(service) = hive.subkey(&services, moderator) else {
                continue;
            };
            for tail in BAM_SUBPATHS {
                let Some(settings) = hive.subpath(&service, tail) else {
                    continue;
                };
                for sid in hive.subkeys(&settings) {
                    collect_bam_entries(&hive, &sid, &mut seen, &mut out);
                }
            }
        }
    }
    out
}

fn collect_bam_entries(
    hive: &Hive<'_>,
    sid: &Node<'_>,
    seen: &mut HashSet<(String, Option<DateTime<Utc>>)>,
    out: &mut Harvested,
) {
    for value in hive.values(sid) {
        let Some(data) = value.binary() else {
            continue;
        };
        if data.len() < BAM_TIME_LEN {
            continue;
        }
        let Some(path) = NormalizedPath::parse(value.name.trim_end_matches('\0')) else {
            continue;
        };
        let when = read_u64(data, 0).and_then(from_filetime);
        if !seen.insert((path.key().to_string(), when)) {
            continue;
        }
        out.push(Observation::about_path(
            ArtifactSource::BamDam,
            path,
            ObservationKind::Executed { when, run_count: None },
        ));
    }
}

fn is_control_set(name: &str) -> bool {
    if name.eq_ignore_ascii_case("CurrentControlSet") {
        return true;
    }
    match name.get(..10) {
        Some(head) if head.eq_ignore_ascii_case("ControlSet") => {
            let digits = &name[10..];
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

const BASE_BLOCK: usize = 4096;
const HBIN_HEADER: usize = 32;
const NIL: u32 = u32::MAX;

const CELL_BUDGET: u32 = 2_000_000;
const MAX_SUBKEYS: usize = 100_000;
const MAX_VALUES: usize = 100_000;
const MAX_LIST_DEPTH: u32 = 8;
const MAX_VALUE_BYTES: usize = 1 << 20;
const BIG_DATA_SEGMENT: usize = 16_344;
const REG_BINARY: u32 = 3;

const NK_MIN: usize = 76;
const VK_MIN: usize = 20;

struct Hive<'a> {
    bins: &'a [u8],
    budget: Cell<u32>,
}

struct Node<'a> {
    cell: &'a [u8],
    name: String,
}

struct Value<'a> {
    name: String,
    kind: u32,
    data: ValueData<'a>,
}

enum ValueData<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl Value<'_> {
    fn binary(&self) -> Option<&[u8]> {
        if self.kind != REG_BINARY {
            return None;
        }
        Some(match &self.data {
            ValueData::Borrowed(bytes) => bytes,
            ValueData::Owned(bytes) => bytes,
        })
    }
}

impl<'a> Hive<'a> {
    fn open(bytes: &'a [u8]) -> Option<(Hive<'a>, Node<'a>)> {
        if !looks_like_a_hive(bytes) {
            return None;
        }
        let root_offset = read_u32(bytes, 0x24)?;
        let declared = read_u32(bytes, 0x28)? as usize;
        let all = bytes.get(BASE_BLOCK..)?;
        let bins = all.get(..declared.min(all.len()))?;
        if bins.len() < HBIN_HEADER || bins.get(..4) != Some(b"hbin") {
            return None;
        }
        let hive = Hive { bins, budget: Cell::new(CELL_BUDGET) };
        let root = hive.node(root_offset)?;
        Some((hive, root))
    }

    fn spend(&self) -> bool {
        match self.budget.get() {
            0 => false,
            left => {
                self.budget.set(left - 1);
                true
            }
        }
    }

    fn cell(&self, offset: u32) -> Option<&'a [u8]> {
        if offset == NIL || !self.spend() {
            return None;
        }
        let start = offset as usize;
        let size = (read_i32(self.bins, start)? as i64).unsigned_abs();
        if size < 8 || !size.is_multiple_of(8) || size > self.bins.len() as u64 {
            return None;
        }
        let end = start.checked_add(size as usize)?;
        self.bins.get(start + 4..end)
    }

    fn node(&self, offset: u32) -> Option<Node<'a>> {
        let cell = self.cell(offset)?;
        if cell.len() < NK_MIN || cell.get(..2) != Some(b"nk") {
            return None;
        }
        let compressed = read_u16(cell, 2)? & 0x0020 != 0;
        let declared = read_u16(cell, 72)? as usize;
        let name = decode_name(clamped(cell, NK_MIN, declared), compressed);
        Some(Node { cell, name })
    }

    fn subkeys(&self, node: &Node<'a>) -> Vec<Node<'a>> {
        let mut out = Vec::new();
        if read_u32(node.cell, 20).unwrap_or(0) == 0 {
            return out;
        }
        let Some(list) = read_u32(node.cell, 28) else {
            return out;
        };
        let mut seen = HashSet::new();
        self.collect_subkeys(list, 0, &mut seen, &mut out);
        out
    }

    fn collect_subkeys(
        &self,
        offset: u32,
        depth: u32,
        seen: &mut HashSet<u32>,
        out: &mut Vec<Node<'a>>,
    ) {
        if depth > MAX_LIST_DEPTH || offset == NIL || !seen.insert(offset) {
            return;
        }
        let Some(cell) = self.cell(offset) else {
            return;
        };
        let (stride, nested) = match cell.get(..2) {
            Some(b"li") => (4, false),
            Some(b"lf") | Some(b"lh") => (8, false),
            Some(b"ri") => (4, true),
            _ => return,
        };
        let Some(items) = cell.get(4..) else {
            return;
        };
        let claimed = read_u16(cell, 2).unwrap_or(0) as usize;
        let count = claimed.min(items.len() / stride).min(MAX_SUBKEYS);
        for index in 0..count {
            if out.len() >= MAX_SUBKEYS {
                return;
            }
            let Some(child) = read_u32(items, index * stride) else {
                continue;
            };
            if nested {
                self.collect_subkeys(child, depth + 1, seen, out);
            } else if let Some(node) = self.node(child) {
                out.push(node);
            }
        }
    }

    fn subkey(&self, node: &Node<'a>, name: &str) -> Option<Node<'a>> {
        self.subkeys(node).into_iter().find(|k| k.name.eq_ignore_ascii_case(name))
    }

    fn subpath(&self, node: &Node<'a>, path: &str) -> Option<Node<'a>> {
        let mut parts = path.split('\\');
        let mut current = self.subkey(node, parts.next()?)?;
        for part in parts {
            current = self.subkey(&current, part)?;
        }
        Some(current)
    }

    fn values(&self, node: &Node<'a>) -> Vec<Value<'a>> {
        let claimed = read_u32(node.cell, 36).unwrap_or(0) as usize;
        if claimed == 0 {
            return Vec::new();
        }
        let Some(list) = read_u32(node.cell, 40).and_then(|offset| self.cell(offset)) else {
            return Vec::new();
        };
        let count = claimed.min(list.len() / 4).min(MAX_VALUES);
        (0..count)
            .filter_map(|index| read_u32(list, index * 4))
            .filter_map(|offset| self.value(offset))
            .collect()
    }

    fn value(&self, offset: u32) -> Option<Value<'a>> {
        let cell = self.cell(offset)?;
        if cell.len() < VK_MIN || cell.get(..2) != Some(b"vk") {
            return None;
        }
        let declared_name = read_u16(cell, 2)? as usize;
        let raw_size = read_u32(cell, 4)?;
        let kind = read_u32(cell, 12)?;
        let compressed = read_u16(cell, 16)? & 0x0001 != 0;
        let name = decode_name(clamped(cell, VK_MIN, declared_name), compressed);

        let resident = raw_size & 0x8000_0000 != 0;
        let size = (raw_size & 0x7fff_ffff) as usize;
        let data = if resident {
            ValueData::Borrowed(cell.get(8..8 + size.min(4))?)
        } else if size == 0 {
            ValueData::Borrowed(&[])
        } else {
            self.value_data(read_u32(cell, 8)?, size)?
        };
        Some(Value { name, kind, data })
    }

    fn value_data(&self, offset: u32, size: usize) -> Option<ValueData<'a>> {
        let cell = self.cell(offset)?;
        if size > BIG_DATA_SEGMENT && cell.get(..2) == Some(b"db") {
            return self.big_data(cell, size).map(ValueData::Owned);
        }
        Some(ValueData::Borrowed(cell.get(..size.min(cell.len()).min(MAX_VALUE_BYTES))?))
    }

    fn big_data(&self, cell: &'a [u8], size: usize) -> Option<Vec<u8>> {
        let claimed = read_u16(cell, 2)? as usize;
        let list = self.cell(read_u32(cell, 4)?)?;
        let count = claimed.min(list.len() / 4);
        let mut wanted = size.min(MAX_VALUE_BYTES);
        let mut out = Vec::new();
        for index in 0..count {
            if wanted == 0 {
                break;
            }
            let Some(segment) = read_u32(list, index * 4).and_then(|offset| self.cell(offset))
            else {
                continue;
            };
            let take = wanted.min(segment.len()).min(BIG_DATA_SEGMENT);
            out.extend_from_slice(&segment[..take]);
            wanted -= take;
        }
        Some(out)
    }
}

fn clamped(cell: &[u8], from: usize, declared: usize) -> &[u8] {
    match cell.get(from..) {
        Some(rest) => &rest[..declared.min(rest.len())],
        None => &[],
    }
}

fn decode_name(bytes: &[u8], compressed: bool) -> String {
    if compressed {
        return bytes.iter().map(|&b| b as char).collect();
    }
    let units = bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes);
    char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
}

fn looks_like_a_hive(bytes: &[u8]) -> bool {
    if bytes.len() < BASE_BLOCK + HBIN_HEADER {
        return false;
    }
    if bytes.get(..4) != Some(b"regf") {
        return false;
    }
    let field = |off: usize| read_u32(bytes, off);
    if field(0x14) != Some(1) {
        return false;
    }
    if !matches!(field(0x18), Some(3..=6)) {
        return false;
    }
    if field(0x1c) != Some(0) {
        return false;
    }
    if field(0x20) != Some(1) {
        return false;
    }
    match field(0x28) {
        Some(size) if size != 0 && size % 4096 == 0 => {}
        _ => return false,
    }

    let Some(header) = bytes.get(..508) else {
        return false;
    };
    let xor = header.as_chunks::<4>().0.iter().fold(0u32, |acc, w| acc ^ u32::from_le_bytes(*w));
    let expected = match xor {
        0xffff_ffff => 0xffff_fffe,
        0 => 1,
        other => other,
    };
    field(0x1fc) == Some(expected)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let word = data.get(offset..end)?;
    Some(u16::from_le_bytes([word[0], word[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let word = data.get(offset..end)?;
    Some(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    read_u32(data, offset).map(|value| value as i32)
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let word = data.get(offset..end)?;
    Some(u64::from_le_bytes([
        word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hive_builder::{Key, Val};

    mod hive_builder {
        const BASE_BLOCK: usize = 4096;
        const HBIN_HEADER: usize = 32;

        pub struct Val {
            name: String,
            data_type: u32,
            data: Vec<u8>,
        }

        impl Val {
            pub fn binary(name: &str, data: Vec<u8>) -> Self {
                Val { name: name.to_string(), data_type: 3, data }
            }

            pub fn dword(name: &str, value: u32) -> Self {
                Val { name: name.to_string(), data_type: 4, data: value.to_le_bytes().to_vec() }
            }

            pub fn string(name: &str, value: &str) -> Self {
                let mut data: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
                data.extend_from_slice(&[0, 0]);
                Val { name: name.to_string(), data_type: 1, data }
            }
        }

        pub struct Key {
            name: String,
            subkeys: Vec<Key>,
            values: Vec<Val>,
        }

        impl Key {
            pub fn new(name: &str) -> Self {
                Key { name: name.to_string(), subkeys: Vec::new(), values: Vec::new() }
            }

            pub fn sub(mut self, key: Key) -> Self {
                self.subkeys.push(key);
                self
            }

            pub fn vals(mut self, values: Vec<Val>) -> Self {
                self.values = values;
                self
            }

            pub fn build(self) -> Vec<u8> {
                let mut bins = vec![0u8; HBIN_HEADER];
                let root = write_key(&mut bins, &self, 0xffff_ffff);

                let padded = bins.len().div_ceil(BASE_BLOCK) * BASE_BLOCK;
                bins.resize(padded, 0);
                bins[0..4].copy_from_slice(b"hbin");
                bins[8..12].copy_from_slice(&(padded as u32).to_le_bytes());

                let mut out = base_block(root, padded as u32);
                out.extend_from_slice(&bins);
                out
            }
        }

        fn alloc(bins: &mut Vec<u8>, body: &[u8]) -> u32 {
            let offset = bins.len() as u32;
            let size = (body.len() + 4).div_ceil(8) * 8;
            bins.extend_from_slice(&(-(size as i64) as i32).to_le_bytes());
            bins.extend_from_slice(body);
            bins.resize(offset as usize + size, 0);
            offset
        }

        fn write_key(bins: &mut Vec<u8>, key: &Key, parent: u32) -> u32 {
            let children: Vec<u32> = key.subkeys.iter().map(|k| write_key(bins, k, 0)).collect();
            let subkeys_list = if children.is_empty() {
                0xffff_ffff
            } else {
                let mut list = Vec::new();
                list.extend_from_slice(b"lh");
                list.extend_from_slice(&(children.len() as u16).to_le_bytes());
                for child in &children {
                    list.extend_from_slice(&child.to_le_bytes());
                    list.extend_from_slice(&0u32.to_le_bytes());
                }
                alloc(bins, &list)
            };

            let values: Vec<u32> = key.values.iter().map(|v| write_value(bins, v)).collect();
            let values_list = if values.is_empty() {
                0xffff_ffff
            } else {
                let mut list = Vec::new();
                for value in &values {
                    list.extend_from_slice(&value.to_le_bytes());
                }
                alloc(bins, &list)
            };

            let name = key.name.as_bytes();
            let mut nk = Vec::new();
            nk.extend_from_slice(b"nk");
            let flags: u16 = if parent == 0xffff_ffff { 0x002c } else { 0x0020 };
            nk.extend_from_slice(&flags.to_le_bytes());
            nk.extend_from_slice(&0u64.to_le_bytes());
            nk.extend_from_slice(&0u32.to_le_bytes());
            nk.extend_from_slice(&parent.to_le_bytes());
            nk.extend_from_slice(&(children.len() as u32).to_le_bytes());
            nk.extend_from_slice(&0u32.to_le_bytes());
            nk.extend_from_slice(&subkeys_list.to_le_bytes());
            nk.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
            nk.extend_from_slice(&(values.len() as u32).to_le_bytes());
            nk.extend_from_slice(&values_list.to_le_bytes());
            nk.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
            nk.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
            for _ in 0..5 {
                nk.extend_from_slice(&0u32.to_le_bytes());
            }
            nk.extend_from_slice(&(name.len() as u16).to_le_bytes());
            nk.extend_from_slice(&0u16.to_le_bytes());
            nk.extend_from_slice(name);
            alloc(bins, &nk)
        }

        fn write_value(bins: &mut Vec<u8>, value: &Val) -> u32 {
            let data_offset = alloc(bins, &value.data);
            let name = value.name.as_bytes();
            let mut vk = Vec::new();
            vk.extend_from_slice(b"vk");
            vk.extend_from_slice(&(name.len() as u16).to_le_bytes());
            vk.extend_from_slice(&(value.data.len() as u32).to_le_bytes());
            vk.extend_from_slice(&data_offset.to_le_bytes());
            vk.extend_from_slice(&value.data_type.to_le_bytes());
            vk.extend_from_slice(&1u16.to_le_bytes());
            vk.extend_from_slice(&0u16.to_le_bytes());
            vk.extend_from_slice(name);
            alloc(bins, &vk)
        }

        fn base_block(root_cell: u32, bins_size: u32) -> Vec<u8> {
            let mut block = vec![0u8; BASE_BLOCK];
            block[0x00..0x04].copy_from_slice(b"regf");
            block[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
            block[0x08..0x0c].copy_from_slice(&1u32.to_le_bytes());
            block[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
            block[0x18..0x1c].copy_from_slice(&5u32.to_le_bytes());
            block[0x1c..0x20].copy_from_slice(&0u32.to_le_bytes());
            block[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
            block[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());
            block[0x28..0x2c].copy_from_slice(&bins_size.to_le_bytes());
            block[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes());
            checksum(&mut block);
            block
        }

        pub fn checksum(hive: &mut [u8]) {
            let xor = hive[..508]
                .as_chunks::<4>()
                .0
                .iter()
                .fold(0u32, |acc, w| acc ^ u32::from_le_bytes(*w));
            let value = match xor {
                0xffff_ffff => 0xffff_fffe,
                0 => 1,
                other => other,
            };
            hive[0x1fc..0x200].copy_from_slice(&value.to_le_bytes());
        }
    }

    const EPOCH_DELTA: u64 = 11_644_473_600;

    fn filetime(unix_secs: u64) -> u64 {
        (unix_secs + EPOCH_DELTA) * 10_000_000
    }

    const JAN_2024: u64 = 1_704_067_200;

    fn ntuser(user: &str) -> HiveSource {
        HiveSource::NtUser { user: user.into() }
    }

    fn v5_record(run_count: u32, when: u64) -> Vec<u8> {
        let mut data = vec![0u8; V5_LEN];
        data[RUN_COUNT_OFF..RUN_COUNT_OFF + 4].copy_from_slice(&run_count.to_le_bytes());
        data[V5_TIME_OFF..V5_TIME_OFF + 8].copy_from_slice(&when.to_le_bytes());
        data
    }

    fn v3_record(run_count: u32, when: u64) -> Vec<u8> {
        let mut data = vec![0u8; V3_LEN];
        data[RUN_COUNT_OFF..RUN_COUNT_OFF + 4].copy_from_slice(&run_count.to_le_bytes());
        data[V3_TIME_OFF..V3_TIME_OFF + 8].copy_from_slice(&when.to_le_bytes());
        data
    }

    fn last_run(data: &[u8]) -> Option<DateTime<Utc>> {
        read_record(data).0
    }

    fn run_count(data: &[u8]) -> Option<u32> {
        read_record(data).1
    }

    fn ntuser_hive(guid: &str, values: Vec<Val>) -> Vec<u8> {
        Key::new("ROOT")
            .sub(Key::new("Software").sub(Key::new("Microsoft").sub(Key::new("Windows").sub(
                Key::new("CurrentVersion").sub(Key::new("Explorer").sub(
                    Key::new("UserAssist").sub(Key::new(guid).sub(Key::new("Count").vals(values))),
                )),
            ))))
            .build()
    }

    fn system_hive(control_set: &str, tail: &str, sid: &str, values: Vec<Val>) -> Vec<u8> {
        let mut settings = Key::new(sid).vals(values);
        for part in tail.rsplit('\\') {
            settings = Key::new(part).sub(settings);
        }
        Key::new("ROOT")
            .sub(Key::new(control_set).sub(Key::new("Services").sub(Key::new("bam").sub(settings))))
            .build()
    }

    fn keys(found: &Harvested) -> Vec<String> {
        found.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect()
    }

    #[test]
    fn rot13_leaves_everything_but_letters_alone() {
        assert_eq!(rot13("P:\\Jvaqbjf\\flfgrz32\\pzq.rkr"), "C:\\Windows\\system32\\cmd.exe");
        assert_eq!(
            rot13("{6Q809377-6NS0-444O-8957-N3773S02200R}"),
            "{6D809377-6AF0-444B-8957-A3773F02200E}"
        );
        assert_eq!(rot13(&rot13("Mixed Case 123 %APPDATA%")), "Mixed Case 123 %APPDATA%");
    }

    #[test]
    fn session_and_aggregate_counters_are_not_programs() {
        assert_eq!(decode_entry_name(&rot13("UEME_CTLSESSION")), None);
        assert_eq!(decode_entry_name(&rot13("UEME_CTLCUACount:ctor")), None);
        assert_eq!(decode_entry_name(&rot13("UEME_RUNPATH")), None);
        assert_eq!(decode_entry_name(""), None);
        assert_eq!(decode_entry_name("   "), None);
    }

    #[test]
    fn xp_style_names_keep_only_the_program() {
        let decoded = decode_entry_name(&rot13("UEME_RUNPATH:C:\\WINDOWS\\system32\\notepad.exe"));
        assert_eq!(decoded.as_deref(), Some("C:\\WINDOWS\\system32\\notepad.exe"));
    }

    #[test]
    fn known_folder_guids_resolve_to_paths_that_join() {
        let entry = "{6D809377-6AF0-444B-8957-A3773F02200E}\\PuTTY\\putty.exe";
        let resolved = resolve_known_folder(entry, "bob");
        let path = NormalizedPath::parse(&resolved).unwrap();
        assert_eq!(path.key(), "\\program files\\putty\\putty.exe");

        let entry = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe";
        let path = NormalizedPath::parse(&resolve_known_folder(entry, "bob")).unwrap();
        assert_eq!(path.key(), "\\windows\\system32\\cmd.exe");

        let entry = "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\\Thing\\t.exe";
        let path = NormalizedPath::parse(&resolve_known_folder(entry, "bob")).unwrap();
        assert_eq!(path.key(), "\\program files (x86)\\thing\\t.exe");
    }

    #[test]
    fn per_user_folders_use_the_profile_we_were_handed() {
        let entry = "{374DE290-123F-4565-9164-39C4925E467B}\\invoice.exe";
        let path = NormalizedPath::parse(&resolve_known_folder(entry, "bob")).unwrap();
        assert_eq!(path.key(), "\\users\\bob\\downloads\\invoice.exe");

        let path = NormalizedPath::parse(&resolve_known_folder(entry, "")).unwrap();
        assert_eq!(path.key(), "\\%userprofile%\\downloads\\invoice.exe");
    }

    #[test]
    fn unknown_guids_survive_unresolved() {
        let entry = "{DEADBEEF-0000-0000-0000-000000000000}\\x.exe";
        assert_eq!(resolve_known_folder(entry, "bob"), entry);
        assert!(NormalizedPath::parse(entry).is_some());

        let lower = "{6d809377-6af0-444b-8957-a3773f02200e}\\a.exe";
        assert_eq!(resolve_known_folder(lower, "bob"), "%ProgramFiles%\\a.exe");
    }

    #[test]
    fn guid_shaped_junk_is_not_mistaken_for_a_guid() {
        assert_eq!(guid_prefix_len("{6D809377-6AF0-444B-8957-A3773F02200E}"), Some(38));
        assert_eq!(guid_prefix_len("{not-a-guid}"), None);
        assert_eq!(guid_prefix_len("{6D809377-6AF0-444B-8957-A3773F02200}"), None);
        assert_eq!(guid_prefix_len("{6D8093776AF0X444B-8957-A3773F02200E}"), None);
        assert_eq!(guid_prefix_len(""), None);
        assert_eq!(
            resolve_known_folder("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", ""),
            "%SystemRoot%"
        );
    }

    #[test]
    fn guid_resolution_never_splits_a_character() {
        for entry in [
            "{6D809377-6AF0-444B-8957-A3773F02200E}é\\a.exe",
            "é{6D809377-6AF0-444B-8957-A3773F02200E}",
            "{éD809377-6AF0-444B-8957-A3773F02200E}",
            "ééééééééééééééééééééééééééééééééééééééééé",
            "€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€",
        ] {
            let _ = resolve_known_folder(entry, "bob");
            let _ = guid_prefix_len(entry);
        }
    }

    #[test]
    fn both_record_layouts_yield_their_timestamp() {
        let v5 = v5_record(7, filetime(JAN_2024));
        assert_eq!(run_count(&v5), Some(7));
        assert_eq!(mm_core::filetime::format(last_run(&v5).unwrap()), "2024-01-01 00:00:00Z");

        let v3 = v3_record(4, filetime(JAN_2024));
        assert_eq!(run_count(&v3), Some(4));
        assert_eq!(mm_core::filetime::format(last_run(&v3).unwrap()), "2024-01-01 00:00:00Z");
    }

    #[test]
    fn short_records_do_not_read_past_their_end() {
        assert_eq!(last_run(&[]), None);
        assert_eq!(last_run(&[0u8; 8]), None);
        assert_eq!(last_run(&[0u8; 15]), None);
        assert_eq!(last_run(&[0xffu8; 71]), None);
        assert_eq!(last_run(&v5_record(1, 0)), None);
        assert_eq!(last_run(&v3_record(1, 0)), None);
    }

    #[test]
    fn a_record_of_an_undocumented_length_yields_no_fields() {
        for length in [1usize, 4, 8, 12, 15, 17, 24, 40, 60, 71] {
            let data = vec![0x7fu8; length];
            assert_eq!(read_record(&data), (None, None), "length {length}");
        }
        assert_eq!(run_count(&[1u8; V3_LEN]), Some(0x0101_0101));
        assert_eq!(run_count(&[1u8; V5_LEN]), Some(0x0101_0101));
        assert_eq!(run_count(&vec![1u8; 4096]), Some(0x0101_0101));
    }

    #[test]
    fn absurd_timestamps_are_rejected_rather_than_printed() {
        assert_eq!(last_run(&v5_record(1, u64::MAX)), None);
        assert_eq!(last_run(&v3_record(u32::MAX, 1)), None);
    }

    #[test]
    fn a_well_formed_userassist_entry_becomes_an_execution() {
        let name = rot13("{6D809377-6AF0-444B-8957-A3773F02200E}\\PuTTY\\putty.exe");
        let hive = ntuser_hive(
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            vec![Val::binary(&name, v5_record(9, filetime(JAN_2024)))],
        );

        let found = harvest(&hive, &ntuser("bob"));
        assert_eq!(found.len(), 1, "{found:?}");
        let o = &found[0];
        assert_eq!(o.source, ArtifactSource::UserAssist);
        assert_eq!(o.path.as_ref().unwrap().key(), "\\program files\\putty\\putty.exe");
        match o.kind {
            ObservationKind::Executed { when, run_count } => {
                assert_eq!(run_count, Some(9));
                assert_eq!(mm_core::filetime::format(when.unwrap()), "2024-01-01 00:00:00Z");
            }
            ref other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn a_corrupt_record_costs_only_itself() {
        let good = rot13("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe");
        let stubby = rot13("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\short.exe");
        let hive = ntuser_hive(
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            vec![
                Val::binary(&rot13("UEME_CTLSESSION"), vec![0u8; 1612]),
                Val::binary(&stubby, vec![0xaa; 3]),
                Val::binary(&good, v5_record(2, filetime(JAN_2024))),
            ],
        );

        let found = harvest(&hive, &ntuser("bob"));
        let keys = keys(&found);
        assert!(keys.contains(&"\\windows\\system32\\cmd.exe".to_string()), "{keys:?}");
        assert!(keys.contains(&"\\windows\\system32\\short.exe".to_string()), "{keys:?}");
        assert_eq!(found.len(), 2, "{found:?}");
        let short =
            found.iter().find(|o| o.path.as_ref().unwrap().key().ends_with("short.exe")).unwrap();
        assert!(matches!(short.kind, ObservationKind::Executed { when: None, run_count: None }));
    }

    #[test]
    fn a_version_3_hive_parses_with_the_16_byte_layout() {
        let name = rot13("UEME_RUNPATH:C:\\WINDOWS\\system32\\notepad.exe");
        let hive = ntuser_hive(
            "{75048700-EF1F-11D0-9888-006097DEACF9}",
            vec![Val::binary(&name, v3_record(11, filetime(JAN_2024)))],
        );

        let found = harvest(&hive, &ntuser("bob"));
        assert_eq!(keys(&found), vec!["\\windows\\system32\\notepad.exe"]);
        match found[0].kind {
            ObservationKind::Executed { when, run_count } => {
                assert_eq!(run_count, Some(11));
                assert_eq!(mm_core::filetime::format(when.unwrap()), "2024-01-01 00:00:00Z");
            }
            ref other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn entries_that_are_not_paths_are_still_reported() {
        let hive = ntuser_hive(
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            vec![Val::binary(
                &rot13("Microsoft.Windows.Explorer"),
                v5_record(3, filetime(JAN_2024)),
            )],
        );
        assert_eq!(keys(&harvest(&hive, &ntuser("bob"))), vec!["\\microsoft.windows.explorer"]);
    }

    #[test]
    fn a_value_of_the_wrong_type_still_reports_the_program() {
        let hive = ntuser_hive(
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            vec![Val::string(&rot13("C:\\Users\\bob\\evil.exe"), "not a record")],
        );
        let found = harvest(&hive, &ntuser("bob"));
        assert_eq!(keys(&found), vec!["\\users\\bob\\evil.exe"]);
        assert!(matches!(found[0].kind, ObservationKind::Executed { when: None, run_count: None }));
    }

    #[test]
    fn the_default_value_of_a_count_key_is_not_a_program() {
        let hive = ntuser_hive(
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            vec![
                Val::binary("", v5_record(1, filetime(JAN_2024))),
                Val::binary(&rot13("C:\\a.exe"), v5_record(1, filetime(JAN_2024))),
            ],
        );
        assert_eq!(keys(&harvest(&hive, &ntuser("bob"))), vec!["\\a.exe"]);
    }

    #[test]
    fn a_hive_without_the_userassist_key_yields_nothing() {
        let hive = Key::new("ROOT").sub(Key::new("Software")).build();
        assert!(harvest(&hive, &ntuser("bob")).is_empty());
    }

    #[test]
    fn a_well_formed_bam_entry_becomes_an_execution() {
        let mut record = vec![0u8; 24];
        record[..8].copy_from_slice(&filetime(JAN_2024).to_le_bytes());
        let hive = system_hive(
            "ControlSet001",
            "State\\UserSettings",
            "S-1-5-21-1-2-3-1001",
            vec![
                Val::binary(
                    "\\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Roaming\\x.exe",
                    record,
                ),
                Val::dword("SequenceNumber", 7),
                Val::dword("Version", 1),
            ],
        );

        let found = harvest(&hive, &HiveSource::System);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].source, ArtifactSource::BamDam);
        assert_eq!(found[0].path.as_ref().unwrap().key(), "\\users\\bob\\appdata\\roaming\\x.exe");
        match found[0].kind {
            ObservationKind::Executed { when, run_count } => {
                assert_eq!(run_count, None);
                assert_eq!(mm_core::filetime::format(when.unwrap()), "2024-01-01 00:00:00Z");
            }
            ref other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn the_older_bam_key_layout_is_read_too() {
        let mut record = vec![0u8; 24];
        record[..8].copy_from_slice(&filetime(JAN_2024).to_le_bytes());
        let hive = system_hive(
            "ControlSet002",
            "UserSettings",
            "S-1-5-18",
            vec![Val::binary("\\Device\\HarddiskVolume2\\Windows\\Temp\\a.exe", record)],
        );
        assert_eq!(keys(&harvest(&hive, &HiveSource::System)), vec!["\\windows\\temp\\a.exe"]);
    }

    #[test]
    fn dam_is_read_alongside_bam() {
        let mut record = vec![0u8; 24];
        record[..8].copy_from_slice(&filetime(JAN_2024).to_le_bytes());
        let settings = |exe: &str| {
            Key::new("State").sub(
                Key::new("UserSettings")
                    .sub(Key::new("S-1-5-18").vals(vec![Val::binary(exe, record.clone())])),
            )
        };
        let hive = Key::new("ROOT")
            .sub(
                Key::new("ControlSet001").sub(
                    Key::new("Services")
                        .sub(Key::new("bam").sub(settings("\\Device\\HarddiskVolume1\\b.exe")))
                        .sub(Key::new("dam").sub(settings("\\Device\\HarddiskVolume1\\d.exe"))),
                ),
            )
            .build();

        let mut found = keys(&harvest(&hive, &HiveSource::System));
        found.sort();
        assert_eq!(found, vec!["\\b.exe", "\\d.exe"]);
    }

    #[test]
    fn identical_rows_in_two_control_sets_are_one_observation() {
        let mut record = vec![0u8; 24];
        record[..8].copy_from_slice(&filetime(JAN_2024).to_le_bytes());
        let control_set =
            |name: &str, exe: &str| {
                Key::new(name).sub(Key::new("Services").sub(
                    Key::new("bam").sub(
                        Key::new("State").sub(Key::new("UserSettings").sub(
                            Key::new("S-1-5-18").vals(vec![Val::binary(exe, record.clone())]),
                        )),
                    ),
                ))
            };
        let hive = Key::new("ROOT")
            .sub(control_set("ControlSet001", "\\Device\\HarddiskVolume1\\a.exe"))
            .sub(control_set("ControlSet002", "\\Device\\HarddiskVolume1\\a.exe"))
            .sub(control_set("Select", "\\Device\\HarddiskVolume1\\ignored.exe"))
            .build();

        assert_eq!(keys(&harvest(&hive, &HiveSource::System)), vec!["\\a.exe"]);
    }

    #[test]
    fn bam_records_too_short_for_a_filetime_are_skipped() {
        let hive = system_hive(
            "ControlSet001",
            "State\\UserSettings",
            "S-1-5-18",
            vec![Val::binary("\\Device\\HarddiskVolume1\\a.exe", vec![0u8; 7])],
        );
        assert!(harvest(&hive, &HiveSource::System).is_empty());
    }

    #[test]
    fn control_set_names_are_recognised_without_being_guessed_at() {
        assert!(is_control_set("ControlSet001"));
        assert!(is_control_set("controlset002"));
        assert!(is_control_set("CurrentControlSet"));
        assert!(!is_control_set("ControlSet"));
        assert!(!is_control_set("ControlSetFoo"));
        assert!(!is_control_set("Select"));
        assert!(!is_control_set(""));
        assert!(!is_control_set("ControlSeté"));
        assert!(!is_control_set("ééééééééééé"));
    }

    #[test]
    fn names_decode_in_both_storage_forms() {
        assert_eq!(decode_name(b"Count", true), "Count");
        assert_eq!(decode_name(b"C\0o\0u\0n\0t\0", false), "Count");
        assert_eq!(decode_name(b"C\0o\0u\0n\0t\0x", false), "Count");
        assert_eq!(decode_name(&[0x00, 0xd8], false), "\u{fffd}");
        assert_eq!(decode_name(&[], false), "");
        assert_eq!(decode_name(&[], true), "");
        assert_eq!(decode_name(&[0xe9], true), "é");
    }

    #[test]
    fn a_declared_name_longer_than_its_cell_is_clipped() {
        let cell = b"nk\x20\x00";
        assert_eq!(clamped(cell, 2, 999), &cell[2..]);
        assert_eq!(clamped(cell, 4, 999), b"");
        assert_eq!(clamped(cell, 99, 1), b"");
        assert_eq!(clamped(cell, 0, 2), b"nk");
    }

    #[test]
    fn bounded_reads_reject_what_they_cannot_reach() {
        assert_eq!(read_u16(&[0u8; 1], 0), None);
        assert_eq!(read_u16(&[0u8; 2], usize::MAX), None);
        assert_eq!(read_u32(&[0u8; 4], usize::MAX), None);
        assert_eq!(read_u64(&[0u8; 8], usize::MAX), None);
        assert_eq!(read_u32(&[0u8; 3], 0), None);
        assert_eq!(read_u64(&[0u8; 7], 0), None);
        assert_eq!(read_u32(&[], 0), None);
        assert_eq!(read_i32(&[0xff, 0xff, 0xff, 0xff], 0), Some(-1));
    }

    #[test]
    fn a_hive_whose_checksum_is_wrong_is_refused_before_it_is_walked() {
        let mut hive = ntuser_hive(
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            vec![Val::binary(&rot13("C:\\a.exe"), v5_record(1, filetime(JAN_2024)))],
        );
        assert!(looks_like_a_hive(&hive));
        hive[0x1fc] ^= 0xff;
        assert!(!looks_like_a_hive(&hive));
        assert!(harvest(&hive, &ntuser("bob")).is_empty());
    }

    #[test]
    fn the_wrong_hive_for_an_artifact_is_not_searched_for_it() {
        let user = ntuser_hive(
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            vec![Val::binary(&rot13("C:\\a.exe"), v5_record(1, filetime(JAN_2024)))],
        );
        assert!(harvest(&user, &HiveSource::System).is_empty());
        assert!(harvest(&user, &HiveSource::Software).is_empty());
        assert!(!harvest(&user, &ntuser("bob")).is_empty());
    }

    mod hostile {
        use super::*;

        fn survives(bytes: &[u8]) -> bool {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let user = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                user_assist(bytes, "bob").len()
            }));
            let system =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bam_dam(bytes).len()));
            std::panic::set_hook(previous);
            user.is_ok() && system.is_ok()
        }

        fn check(label: &str, bytes: &[u8], failures: &mut Vec<String>) {
            if !survives(bytes) {
                failures.push(label.to_string());
            }
        }

        fn assert_all_survived(failures: Vec<String>) {
            assert!(
                failures.is_empty(),
                "{} fixture(s) took the parser down: {:?}",
                failures.len(),
                &failures[..failures.len().min(20)]
            );
        }

        fn sample() -> Vec<u8> {
            ntuser_hive(
                "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
                vec![Val::binary(&rot13("C:\\a.exe"), v5_record(1, filetime(JAN_2024)))],
            )
        }

        fn system_fixture() -> Vec<u8> {
            let mut record = vec![0u8; 24];
            record[..8].copy_from_slice(&filetime(JAN_2024).to_le_bytes());
            system_hive(
                "ControlSet001",
                "State\\UserSettings",
                "S-1-5-18",
                vec![
                    Val::binary("\\Device\\HarddiskVolume1\\a.exe", record),
                    Val::dword("SequenceNumber", 3),
                ],
            )
        }

        fn root_cell(hive: &[u8]) -> usize {
            read_u32(hive, 0x24).unwrap() as usize + BASE_BLOCK
        }

        fn first_vk(hive: &[u8]) -> usize {
            (BASE_BLOCK..hive.len() - 2)
                .find(|&i| &hive[i..i + 2] == b"vk")
                .expect("fixture has a vk cell")
        }

        #[test]
        fn degenerate_buffers_yield_nothing() {
            let sources = [
                HiveSource::System,
                ntuser("bob"),
                HiveSource::Software,
                HiveSource::UsrClass { user: "bob".into() },
            ];
            let fixtures: Vec<Vec<u8>> = vec![
                Vec::new(),
                vec![0u8; 1],
                vec![0u8; 7],
                vec![0u8; 4095],
                vec![0u8; 4096],
                vec![0u8; 4127],
                vec![0xff; 8192],
                b"regf".to_vec(),
                b"regf".iter().copied().cycle().take(16384).collect(),
            ];
            let mut failures = Vec::new();
            for (index, fixture) in fixtures.iter().enumerate() {
                check(&format!("degenerate #{index}"), fixture, &mut failures);
                for source in &sources {
                    assert!(harvest(fixture, source).is_empty(), "degenerate #{index}");
                }
            }
            assert_all_survived(failures);
        }

        #[test]
        fn truncation_at_every_structure_boundary() {
            let mut failures = Vec::new();
            for hive in [sample(), system_fixture()] {
                let cuts = (0..hive.len())
                    .step_by(4)
                    .chain(BASE_BLOCK..(BASE_BLOCK + 512).min(hive.len()))
                    .chain([hive.len() - 1, hive.len()]);
                for cut in cuts {
                    check(&format!("cut at {cut}"), &hive[..cut], &mut failures);
                }
            }
            assert_all_survived(failures);
        }

        #[test]
        fn root_cell_offsets_that_point_nowhere() {
            let mut failures = Vec::new();
            for offset in [
                0u32,
                1,
                3,
                4,
                7,
                8,
                0x20,
                0x1000,
                100_000,
                0x7fff_ffff,
                0x8000_0000,
                0xffff_fff8,
                0xffff_ffff,
            ] {
                let mut hive = sample();
                hive[0x24..0x28].copy_from_slice(&offset.to_le_bytes());
                hive_builder::checksum(&mut hive);
                check(&format!("root offset {offset:#x}"), &hive, &mut failures);
                assert!(harvest(&hive, &ntuser("bob")).is_empty(), "root offset {offset:#x}");
            }
            assert_all_survived(failures);
        }

        #[test]
        fn cell_sizes_that_cannot_be_trusted() {
            let base = sample();
            let root = root_cell(&base);
            let mut failures = Vec::new();
            for size in [
                0i32,
                1,
                4,
                7,
                8,
                24,
                -1,
                -4,
                -7,
                -8,
                i32::MIN,
                i32::MAX,
                0x7fff_fff8,
                -0x7fff_fff8,
            ] {
                let mut hive = base.clone();
                hive[root..root + 4].copy_from_slice(&size.to_le_bytes());
                check(&format!("root cell size {size}"), &hive, &mut failures);
            }
            assert_all_survived(failures);
        }

        #[test]
        fn undefined_key_node_flags() {
            let base = sample();
            let root = root_cell(&base);
            let mut failures = Vec::new();
            for flags in [0u16, 0x0400, 0x8000, 0xfc00, 0xffff, 0x002c, 0x0004] {
                let mut hive = base.clone();
                hive[root + 4 + 2..root + 4 + 4].copy_from_slice(&flags.to_le_bytes());
                check(&format!("nk flags {flags:#06x}"), &hive, &mut failures);
            }
            assert_all_survived(failures);
        }

        #[test]
        fn every_key_node_field_set_hostile() {
            let base = sample();
            let nk = root_cell(&base) + 4;
            let mut failures = Vec::new();
            for field in (0..NK_MIN).step_by(2) {
                for value in [0u32, 1, 8, 0x8000_0000, 0xffff_fff8, 0x7fff_ffff, 0xffff_ffff] {
                    if nk + field + 4 > base.len() {
                        continue;
                    }
                    let mut hive = base.clone();
                    hive[nk + field..nk + field + 4].copy_from_slice(&value.to_le_bytes());
                    check(&format!("nk+{field} = {value:#x}"), &hive, &mut failures);
                }
            }
            assert_all_survived(failures);
        }

        #[test]
        fn every_word_in_the_bins_set_hostile() {
            let base = sample();
            let mut failures = Vec::new();
            for at in (BASE_BLOCK..base.len().saturating_sub(4)).step_by(2) {
                for value in [0u32, 0x8000_0004, 0xffff_ffff, 0x7fff_ffff, 0xffff_fff8] {
                    let mut hive = base.clone();
                    hive[at..at + 4].copy_from_slice(&value.to_le_bytes());
                    check(&format!("word at {at} = {value:#x}"), &hive, &mut failures);
                }
            }
            assert_all_survived(failures);
        }

        #[test]
        fn single_byte_corruption_anywhere() {
            let mut failures = Vec::new();
            for hive in [sample(), system_fixture()] {
                for index in BASE_BLOCK..hive.len() {
                    for byte in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                        if hive[index] == byte {
                            continue;
                        }
                        let mut mutated = hive.clone();
                        mutated[index] = byte;
                        check(&format!("byte {index} = {byte:#04x}"), &mutated, &mut failures);
                    }
                }
            }
            assert_all_survived(failures);
        }

        #[test]
        fn a_valid_header_over_garbage() {
            let base = sample();
            let mut failures = Vec::new();
            for fill in [0x00u8, 0x01, 0x41, 0x6b, 0x6e, 0x80, 0xff] {
                let mut hive = base.clone();
                for byte in hive.iter_mut().skip(BASE_BLOCK) {
                    *byte = fill;
                }
                check(&format!("body of {fill:#04x}"), &hive, &mut failures);

                let mut hive = base.clone();
                for byte in hive.iter_mut().skip(BASE_BLOCK + HBIN_HEADER) {
                    *byte = fill;
                }
                check(&format!("cells of {fill:#04x}"), &hive, &mut failures);
            }
            assert_all_survived(failures);
        }

        #[test]
        fn self_referential_and_circular_structures() {
            let base = sample();
            let root_offset = read_u32(&base, 0x24).unwrap();
            let nk = root_cell(&base) + 4;
            let list_offset = read_u32(&base, nk + 28).unwrap();
            let list = list_offset as usize + BASE_BLOCK + 4;
            let mut failures = Vec::new();

            let mut hive = base.clone();
            hive[nk + 28..nk + 32].copy_from_slice(&root_offset.to_le_bytes());
            check("subkey list -> own nk", &hive, &mut failures);

            let mut hive = base.clone();
            hive[list + 4..list + 8].copy_from_slice(&root_offset.to_le_bytes());
            check("lh entry -> root nk", &hive, &mut failures);

            let mut hive = base.clone();
            hive[list..list + 2].copy_from_slice(b"ri");
            hive[list + 4..list + 8].copy_from_slice(&list_offset.to_le_bytes());
            check("ri -> itself", &hive, &mut failures);

            let mut hive = base.clone();
            hive[list..list + 2].copy_from_slice(b"ri");
            hive[list + 2..list + 4].copy_from_slice(&0xffffu16.to_le_bytes());
            check("ri ring at max count", &hive, &mut failures);

            let values_list = read_u32(&base, nk + 40).unwrap();
            if values_list != NIL {
                let mut hive = base;
                let at = values_list as usize + BASE_BLOCK + 4;
                hive[at..at + 4].copy_from_slice(&root_offset.to_le_bytes());
                check("value list -> nk", &hive, &mut failures);
            }
            assert_all_survived(failures);
        }

        #[test]
        fn counts_larger_than_the_buffer_could_hold() {
            let base = sample();
            let nk = root_cell(&base) + 4;
            let mut failures = Vec::new();
            for value in [0xffff_ffffu32, 0x7fff_ffff, 0x00ff_ffff, 1_000_000, 0x10_0000] {
                for field in [20usize, 36] {
                    let mut hive = base.clone();
                    hive[nk + field..nk + field + 4].copy_from_slice(&value.to_le_bytes());
                    check(&format!("nk field {field} = {value:#x}"), &hive, &mut failures);
                }
            }
            let list = read_u32(&base, nk + 28).unwrap() as usize + BASE_BLOCK + 4;
            for count in [0u16, 1, 0x7fff, 0xffff] {
                let mut hive = base.clone();
                hive[list + 2..list + 4].copy_from_slice(&count.to_le_bytes());
                check(&format!("list count {count}"), &hive, &mut failures);
            }
            assert_all_survived(failures);
        }

        #[test]
        fn value_payloads_that_lie_about_their_size() {
            let base = sample();
            let vk = first_vk(&base);
            let mut failures = Vec::new();
            for size in [
                0u32,
                1,
                4,
                0x0000_4000,
                0x0000_ffff,
                0x7fff_ffff,
                0xffff_ffff,
                0x8000_0000,
                0x8000_0004,
                0x8000_00ff,
            ] {
                for offset in [None, Some(0u32), Some(4), Some(0xffff_ffff), Some(0x1000)] {
                    let mut hive = base.clone();
                    hive[vk + 4..vk + 8].copy_from_slice(&size.to_le_bytes());
                    if let Some(offset) = offset {
                        hive[vk + 8..vk + 12].copy_from_slice(&offset.to_le_bytes());
                    }
                    check(&format!("vk size {size:#x} offset {offset:?}"), &hive, &mut failures);
                }
            }
            for name_len in [0u16, 1, 0x7fff, 0xffff] {
                let mut hive = base.clone();
                hive[vk + 2..vk + 4].copy_from_slice(&name_len.to_le_bytes());
                check(&format!("vk name length {name_len}"), &hive, &mut failures);
            }
            assert_all_survived(failures);
        }

        #[test]
        fn a_big_data_bomb_is_bounded() {
            let base = sample();
            let vk = first_vk(&base);
            let data_offset = read_u32(&base, vk + 8).unwrap();
            let data = data_offset as usize + BASE_BLOCK + 4;

            let mut hive = base;
            hive[vk + 4..vk + 8].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
            hive[data..data + 2].copy_from_slice(b"db");
            hive[data + 2..data + 4].copy_from_slice(&0xffffu16.to_le_bytes());
            hive[data + 4..data + 8].copy_from_slice(&data_offset.to_le_bytes());

            let mut failures = Vec::new();
            check("big data bomb", &hive, &mut failures);
            assert_all_survived(failures);
            for observation in harvest(&hive, &ntuser("bob")) {
                assert!(observation.path.is_some());
            }
        }

        #[test]
        fn a_declared_size_that_disagrees_with_the_buffer() {
            let base = sample();
            let mut failures = Vec::new();
            for declared in [0u32, 4096, 8192, 0x0010_0000, 0x7fff_f000, 0xffff_f000] {
                let mut hive = base.clone();
                hive[0x28..0x2c].copy_from_slice(&declared.to_le_bytes());
                hive_builder::checksum(&mut hive);
                check(&format!("declared size {declared:#x}"), &hive, &mut failures);
            }
            assert_all_survived(failures);
        }

        #[test]
        fn names_in_the_wrong_encoding() {
            let base = sample();
            let root = root_cell(&base);
            let vk = first_vk(&base);
            let mut failures = Vec::new();

            let mut hive = base.clone();
            hive[root + 4 + 2..root + 4 + 4].copy_from_slice(&0x0004u16.to_le_bytes());
            check("nk name read as UTF-16", &hive, &mut failures);

            let mut hive = base;
            hive[vk + 16..vk + 18].copy_from_slice(&0u16.to_le_bytes());
            hive[vk + 20] = 0x00;
            hive[vk + 21] = 0xd8;
            check("vk name read as UTF-16", &hive, &mut failures);
            assert_all_survived(failures);
        }

        #[test]
        fn randomised_corruption() {
            let mut state = 0x2545_f491_4f6c_dd1du64;
            let mut next = move || {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                state.wrapping_mul(0x2545_f491_4f6c_dd1d)
            };
            let fixtures = [sample(), system_fixture()];
            let mut failures = Vec::new();
            for round in 0..FUZZ_ROUNDS {
                let base = &fixtures[(next() as usize) % fixtures.len()];
                let mut hive = base.clone();
                let edits = 1 + (next() as usize) % 16;
                for _ in 0..edits {
                    let at = BASE_BLOCK + (next() as usize) % (hive.len() - BASE_BLOCK);
                    hive[at] = next() as u8;
                }
                if next() % 4 == 0 {
                    let cut = BASE_BLOCK + (next() as usize) % (hive.len() - BASE_BLOCK);
                    hive.truncate(cut);
                }
                if next() % 8 == 0 {
                    let at = (next() as usize) % 0x1fc;
                    hive[at] = next() as u8;
                    hive_builder::checksum(&mut hive);
                }
                if !survives(&hive) {
                    failures.push(format!("round {round}"));
                    if failures.len() > 8 {
                        break;
                    }
                }
            }
            assert_all_survived(failures);
        }

        const FUZZ_ROUNDS: usize = 20_000;

        #[test]
        fn the_hostile_harness_can_see_a_panic() {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let caught = std::panic::catch_unwind(|| panic!("deliberate")).is_err();
            std::panic::set_hook(previous);
            assert!(caught, "this suite cannot detect panics; its results mean nothing");
        }

        #[test]
        fn a_wide_hive_finishes() {
            let mut services = Key::new("Services");
            for index in 0..2_000 {
                services = services.sub(Key::new(&format!("service{index}")));
            }
            let hive = Key::new("ROOT").sub(Key::new("ControlSet001").sub(services)).build();
            let start = std::time::Instant::now();
            assert!(harvest(&hive, &HiveSource::System).is_empty());
            assert!(start.elapsed().as_secs() < 20, "took {:?}", start.elapsed());
        }

        #[test]
        fn the_cell_budget_is_finite() {
            let hive = sample();
            let (parsed, root) = Hive::open(&hive).expect("fixture opens");
            let after_open = parsed.budget.get();
            assert!(after_open < CELL_BUDGET, "opening a hive costs at least one cell");
            for _ in 0..10 {
                let _ = parsed.subkeys(&root);
            }
            assert!(parsed.budget.get() < after_open, "walking must charge the budget");

            parsed.budget.set(0);
            assert!(parsed.subkeys(&root).is_empty());
            assert!(parsed.subpath(&root, USERASSIST_KEY).is_none());
        }
    }
}
