use std::io::{Read, Seek, Write};

use ntfs_core::{AttributeBody, MftRecordHeader};

use crate::Volume;

const ROOT_RECORD: u64 = 5;
const NAMESPACE_DOS: u8 = 2;
const MAX_DEPTH: usize = 64;
const MAX_LIST_ENTRIES: usize = 64;
const MAX_CHILDREN: usize = 4096;
const MAX_BROKEN_NAMED: usize = 64;
const MAX_ATTRIBUTE_LIST_BYTES: u64 = 1 << 20;

fn attribute_name(type_code: u32) -> &'static str {
    match type_code {
        0x10 => "$STANDARD_INFORMATION",
        0x20 => "$ATTRIBUTE_LIST",
        0x30 => "$FILE_NAME",
        0x40 => "$OBJECT_ID",
        0x50 => "$SECURITY_DESCRIPTOR",
        0x60 => "$VOLUME_NAME",
        0x70 => "$VOLUME_INFORMATION",
        0x80 => "$DATA",
        0x90 => "$INDEX_ROOT",
        0xA0 => "$INDEX_ALLOCATION",
        0xB0 => "$BITMAP",
        0xC0 => "$REPARSE_POINT",
        0xD0 => "$EA_INFORMATION",
        0xE0 => "$EA",
        0x100 => "$LOGGED_UTILITY_STREAM",
        _ => "(unknown)",
    }
}

#[derive(Clone, Debug, Default)]
pub struct MftQuery<'a> {
    pub path: Option<&'a str>,
    pub record: Option<u64>,
    pub children: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MftFindings {
    pub target: Option<u64>,
    pub stopped_at: Option<String>,
    pub chain: Vec<u64>,
    pub reaches_root: bool,
    pub current_parents: usize,
    pub stale_parents: usize,
    pub records_the_walk_loses: usize,
    pub children_placed: usize,
    pub children_lost: usize,
}

impl MftFindings {
    pub fn found_a_fault(&self) -> bool {
        self.records_the_walk_loses > 0
            || self.stale_parents > 0
            || self.children_lost > 0
            || self.stopped_at.is_some()
            || (self.target.is_some() && !self.reaches_root)
    }
}

struct AsTheWalkSeesIt {
    parsed: bool,
    name: Option<String>,
    parent: Option<u64>,
    parent_sequence: Option<u16>,
    all_parents: Vec<(u64, u16, String, u8)>,
    is_directory: bool,
    names_in_base: usize,
}

impl AsTheWalkSeesIt {
    fn unreadable(is_directory: bool) -> Self {
        AsTheWalkSeesIt {
            parsed: false,
            name: None,
            parent: None,
            parent_sequence: None,
            all_parents: Vec::new(),
            is_directory,
            names_in_base: 0,
        }
    }
}

fn as_the_walk_sees_it(bytes: &[u8]) -> AsTheWalkSeesIt {
    let Ok(header) = MftRecordHeader::parse(bytes) else {
        return AsTheWalkSeesIt::unreadable(false);
    };
    if &header.signature != b"FILE" {
        return AsTheWalkSeesIt::unreadable(header.is_directory());
    }
    let Ok(attributes) = ntfs_core::parse_attributes(bytes, header.first_attribute_offset as usize)
    else {
        return AsTheWalkSeesIt::unreadable(header.is_directory());
    };

    let mut best = u8::MAX;
    let mut name = None;
    let mut parent = None;
    let mut names = 0usize;
    let mut parent_sequence = None;
    let mut all_parents = Vec::new();
    for attribute in &attributes {
        if attribute.type_code != 0x30 {
            continue;
        }
        let Some(content) = attribute.resident_content(bytes) else { continue };
        let Ok(file_name) = ntfs_core::FileName::parse(content) else { continue };
        names += 1;
        all_parents.push((
            file_name.parent.record_number,
            file_name.parent.sequence,
            file_name.name.clone(),
            file_name.namespace,
        ));
        let better =
            file_name.namespace != NAMESPACE_DOS && (name.is_none() || file_name.namespace < best);
        if better || name.is_none() {
            best = file_name.namespace;
            name = Some(file_name.name.clone());
            parent = Some(file_name.parent.record_number);
            parent_sequence = Some(file_name.parent.sequence);
        }
    }
    AsTheWalkSeesIt {
        parsed: true,
        name,
        parent,
        parent_sequence,
        all_parents,
        is_directory: header.is_directory(),
        names_in_base: names,
    }
}

fn describe_record<R: Read + Seek, W: Write>(
    volume: &Volume<R>,
    record: u64,
    label: &str,
    out: &mut W,
    findings: &mut MftFindings,
) -> std::io::Result<Option<u64>> {
    writeln!(out, "\n=== record {record}  {label}")?;

    let bytes = match volume.fs().read_record(record) {
        Ok(bytes) => bytes,
        Err(err) => {
            writeln!(out, "  THE RECORD WOULD NOT READ: {err}")?;
            writeln!(out, "  the walk counts this as unreadable and drops every file under it")?;
            findings.records_the_walk_loses += 1;
            return Ok(None);
        }
    };
    writeln!(out, "  read {} bytes", bytes.len())?;

    let signature = String::from_utf8_lossy(bytes.get(0..4).unwrap_or(b"????")).to_string();
    let header = match MftRecordHeader::parse(&bytes) {
        Ok(header) => header,
        Err(err) => {
            writeln!(out, "  THE HEADER WOULD NOT PARSE: {err} (signature {signature:?})")?;
            findings.records_the_walk_loses += 1;
            return Ok(None);
        }
    };
    writeln!(
        out,
        "  signature {signature:?}  {}  {}  {}",
        if header.is_in_use() { "in use" } else { "FREE" },
        if header.is_directory() { "directory" } else { "file" },
        if header.is_base_record() {
            "base record".to_string()
        } else {
            format!("EXTENSION of record {}", header.base_record & 0x0000_FFFF_FFFF_FFFF)
        }
    )?;
    writeln!(
        out,
        "  sequence {}  hard links {}  used {} of {} bytes  first attribute at +{}",
        header.sequence_number,
        header.hard_link_count,
        header.used_size,
        header.allocated_size,
        header.first_attribute_offset
    )?;

    let attributes =
        match ntfs_core::parse_attributes(&bytes, header.first_attribute_offset as usize) {
            Ok(attributes) => attributes,
            Err(err) => {
                writeln!(out, "  THE ATTRIBUTES WOULD NOT PARSE: {err}")?;
                writeln!(out, "  -> the walk gets nothing here: index[{record}] == None")?;
                findings.records_the_walk_loses += 1;
                return Ok(None);
            }
        };
    writeln!(out, "  {} attribute(s):", attributes.len())?;
    for attribute in &attributes {
        let residency = match &attribute.body {
            AttributeBody::Resident { content_length, .. } => {
                format!("resident, {content_length} bytes")
            }
            AttributeBody::NonResident { real_size, start_vcn, .. } => {
                format!("NON-RESIDENT, real size {real_size}, from VCN {start_vcn}")
            }
        };
        writeln!(
            out,
            "    0x{:03x} {:<24} {:<28} name {:?}",
            attribute.type_code,
            attribute_name(attribute.type_code),
            residency,
            attribute.name
        )?;
    }

    let walk = as_the_walk_sees_it(&bytes);
    writeln!(
        out,
        "  as the $MFT walk sees it: parsed {}, {} $FILE_NAME in the base record, \
         name {:?}, parent {:?} sequence {:?}, directory {}",
        walk.parsed,
        walk.names_in_base,
        walk.name,
        walk.parent,
        walk.parent_sequence,
        walk.is_directory
    )?;

    for (parent, sequence, name, namespace) in &walk.all_parents {
        let now = volume
            .fs()
            .read_record(*parent)
            .ok()
            .and_then(|other| MftRecordHeader::parse(&other).ok());
        let verdict = match &now {
            None => "the parent record would not read".to_string(),
            Some(header) => {
                let what =
                    if header.is_directory() { "directory" } else { "FILE, not a directory" };
                let state = if header.is_in_use() { "in use" } else { "FREE" };
                if header.sequence_number == *sequence {
                    findings.current_parents += 1;
                    format!(
                        "the record carries sequence {} too -> CURRENT ({what}, {state})",
                        header.sequence_number
                    )
                } else {
                    findings.stale_parents += 1;
                    format!(
                        "the record carries sequence {} -> STALE by {} reallocation(s) \
                         ({what}, {state})",
                        header.sequence_number,
                        header.sequence_number.saturating_sub(*sequence)
                    )
                }
            }
        };
        writeln!(
            out,
            "    name {name:?} (namespace {namespace}) -> parent record {parent}, \
             reference sequence {sequence}: {verdict}"
        )?;
    }
    if !walk.parsed || walk.name.is_none() {
        findings.records_the_walk_loses += 1;
        writeln!(
            out,
            "  *** THIS IS THE FAILURE. index[{record}] == None, so every file in this \
             directory and every directory below it was dropped from the run, silently."
        )?;
    }

    if let Some(list) = attributes.iter().find(|a| a.type_code == 0x20) {
        writeln!(out, "  $ATTRIBUTE_LIST is present:")?;
        let content = volume.attribute_value(&bytes, list, MAX_ATTRIBUTE_LIST_BYTES);
        match content.as_deref().map(ntfs_core::parse_attribute_list) {
            Some(Ok(entries)) => {
                writeln!(out, "    {} entries", entries.len())?;
                for entry in entries.iter().take(MAX_LIST_ENTRIES) {
                    let target = entry.base_reference.record_number;
                    let (reads, claims) = match volume.fs().read_record(target) {
                        Ok(other) => {
                            let base = MftRecordHeader::parse(&other)
                                .map(|h| h.base_record & 0x0000_FFFF_FFFF_FFFF)
                                .unwrap_or(u64::MAX);
                            (true, base == record || (base == 0 && target == record))
                        }
                        Err(_) => (false, false),
                    };
                    writeln!(
                        out,
                        "      0x{:03x} {:<24} in record {:<10} start VCN {:<6} name {:?}  {}  {}",
                        entry.type_code,
                        attribute_name(entry.type_code),
                        target,
                        entry.start_vcn,
                        entry.name,
                        if reads { "record reads" } else { "RECORD WILL NOT READ" },
                        if claims { "claims this base" } else { "DOES NOT CLAIM THIS BASE" }
                    )?;
                }
                if entries.len() > MAX_LIST_ENTRIES {
                    writeln!(out, "      ... {} more", entries.len() - MAX_LIST_ENTRIES)?;
                }
                let names_elsewhere = entries
                    .iter()
                    .filter(|e| e.type_code == 0x30 && e.base_reference.record_number != record)
                    .count();
                if names_elsewhere > 0 && walk.names_in_base == 0 {
                    writeln!(
                        out,
                        "    *** {names_elsewhere} $FILE_NAME live in extension records and \
                         NONE in the base. This is exactly the layout the walk cannot read: it \
                         never follows an $ATTRIBUTE_LIST when looking for a name."
                    )?;
                }
            }
            Some(Err(err)) => writeln!(out, "    it would not parse: {err}")?,
            None => writeln!(out, "    its value could not be read")?,
        }
    } else {
        writeln!(out, "  no $ATTRIBUTE_LIST: every attribute this file has is in this record")?;
    }

    if header.is_directory() {
        let root = attributes.iter().any(|a| a.type_code == 0x90);
        let allocation = attributes.iter().any(|a| a.type_code == 0xA0);
        writeln!(
            out,
            "  index: $INDEX_ROOT {}, $INDEX_ALLOCATION {} -> {}",
            if root { "present" } else { "ABSENT" },
            if allocation { "present" } else { "absent" },
            if allocation { "entries live in INDX buffers" } else { "entries are resident" }
        )?;
        match volume.fs().directory_entries(&bytes) {
            Ok(entries) => {
                let real = entries
                    .iter()
                    .filter(|e| {
                        e.file_name
                            .as_ref()
                            .is_some_and(|n| n.namespace != NAMESPACE_DOS && n.name != ".")
                    })
                    .count();
                writeln!(
                    out,
                    "  directory_entries on THIS record alone: {} entries ({real} non-8.3)",
                    entries.len()
                )?;
            }
            Err(err) => {
                writeln!(out, "  directory_entries on THIS record alone FAILED: {err}")?;
            }
        }
    }

    Ok(walk.parent.filter(|parent| *parent != record))
}

pub fn mft<R: Read + Seek, W: Write>(
    volume: &Volume<R>,
    query: &MftQuery<'_>,
    out: &mut W,
) -> std::io::Result<MftFindings> {
    let mut findings = MftFindings::default();

    writeln!(
        out,
        "{} byte clusters, {} byte MFT records, windows install: {}",
        volume.cluster_size(),
        volume.fs().boot().mft_record_size,
        volume.is_windows_install()
    )?;

    let target = match (query.path, query.record) {
        (Some(path), _) => {
            writeln!(out, "\nresolving {path} one component at a time:")?;
            let mut current = ROOT_RECORD;
            let mut reached = String::new();
            let mut stopped = false;
            for component in path.split(['\\', '/']).filter(|c| !c.is_empty()) {
                let folded = component.to_lowercase();
                let next = volume
                    .list_directory_entries(&reached)
                    .into_iter()
                    .find(|e| e.name.to_lowercase() == folded)
                    .map(|e| e.record);
                match next {
                    Some(next) => {
                        current = next;
                        reached.push('\\');
                        reached.push_str(component);
                        writeln!(out, "  {reached:<70} record {current}")?;
                    }
                    None => {
                        writeln!(
                            out,
                            "  {reached}\\ does not list an entry named `{component}` \
                             ({} entries listed) — resolution stops here",
                            volume.list_directory_entries(&reached).len()
                        )?;
                        writeln!(
                            out,
                            "\nNote: this is the DIRECTORY-INDEX path, which follows \
                             $ATTRIBUTE_LIST. The $MFT walk does not. A path that resolves \
                             here and is still missing from the report is the interesting case."
                        )?;
                        findings.stopped_at = Some(component.to_string());
                        stopped = true;
                        break;
                    }
                }
            }
            if stopped {
                return Ok(findings);
            }
            current
        }
        (None, Some(record)) => record,
        (None, None) => {
            writeln!(out, "nothing asked about: give a path, or --record <n>")?;
            return Ok(findings);
        }
    };
    findings.target = Some(target);

    let mut current = Some(target);
    let mut depth = 0;
    while let Some(record) = current {
        findings.chain.push(record);
        if record == ROOT_RECORD || depth >= MAX_DEPTH {
            break;
        }
        depth += 1;
        let label = if record == target { "the directory asked about" } else { "ancestor" };
        current = describe_record(volume, record, label, out, &mut findings)?;
        if current.is_some_and(|parent| findings.chain.contains(&parent)) {
            writeln!(out, "\n  the parent chain cycles at record {current:?}; stopping")?;
            break;
        }
    }
    findings.reaches_root = findings.chain.last() == Some(&ROOT_RECORD);
    writeln!(out, "\nparent chain as the walk would climb it: {:?}", findings.chain)?;
    if findings.reaches_root {
        writeln!(out, "  it reaches the root, so path reconstruction is not what failed here.")?;
    } else {
        writeln!(
            out,
            "  it does NOT reach the root (record 5). That is why every file under this \
             directory was dropped: resolve_directory returns None and the walk counts them \
             as unresolved without naming them."
        )?;
    }

    if !query.children {
        return Ok(findings);
    }
    let Ok(bytes) = volume.fs().read_record(target) else { return Ok(findings) };
    let Ok(entries) = volume.fs().directory_entries(&bytes) else {
        writeln!(out, "\n--children: the directory would not list")?;
        return Ok(findings);
    };
    writeln!(out, "\n--children: {} index entries", entries.len())?;
    let mut broken = Vec::new();
    for entry in entries.iter().take(MAX_CHILDREN) {
        let Some(name) = entry.file_name.as_ref() else { continue };
        if name.namespace == NAMESPACE_DOS || name.name == "." {
            continue;
        }
        let child = entry.file_reference.record_number;
        match volume.fs().read_record(child) {
            Ok(bytes) => {
                let walk = as_the_walk_sees_it(&bytes);
                if walk.parsed && walk.name.is_some() && walk.parent == Some(target) {
                    findings.children_placed += 1;
                } else {
                    if broken.len() < MAX_BROKEN_NAMED {
                        broken.push((child, name.name.clone(), walk));
                    }
                    findings.children_lost += 1;
                }
            }
            Err(err) => {
                findings.children_lost += 1;
                writeln!(out, "  record {child} ({}) would not read: {err}", name.name)?;
            }
        }
    }
    writeln!(out, "  {} child record(s) the walk would place correctly", findings.children_placed)?;
    writeln!(out, "  {} child record(s) it would not:", findings.children_lost)?;
    for (child, name, walk) in &broken {
        writeln!(
            out,
            "    record {child:<10} {name:<48} parsed {} names {} parent {:?} (expected {target})",
            walk.parsed, walk.names_in_base, walk.parent
        )?;
    }
    if findings.children_lost > broken.len() {
        writeln!(out, "    ... {} more", findings.children_lost - broken.len())?;
    }
    if findings.children_lost == 0 {
        writeln!(
            out,
            "  Every child places. If the report still holds nothing from this directory, the \
             failure is the DIRECTORY record above, not its files."
        )?;
    }
    Ok(findings)
}

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_REPARSE_POINT: u32 = 0xC0;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListCensus {
    pub records_read: u64,
    pub base_records: u64,
    pub extension_records: u64,
    pub reparse_attribute_in_base: u64,
    pub standard_information_says_reparse: u64,
    pub with_list: u64,
    pub with_list_unnamed: u64,
    pub with_list_no_reparse_attribute: u64,
    pub with_list_si_reparse: u64,
    pub with_list_si_reparse_no_attribute: u64,
    pub named_and_would_follow: u64,
    pub extension_records_read: u64,
    pub extension_bytes_read: u64,
}

pub fn attribute_lists<R: Read + Seek, W: Write>(
    volume: &Volume<R>,
    follow: bool,
    out: &mut W,
) -> std::io::Result<ListCensus> {
    let mut census = ListCensus::default();

    let record_size = {
        let declared = volume.fs().boot().mft_record_size;
        if (256..=65_536).contains(&declared) {
            declared
        } else {
            1024
        }
    };
    let cluster = volume.cluster_size().max(1);
    let runs = volume.fs().runs_by_record(0, None).unwrap_or_default();
    let clusters: u64 = runs.iter().map(|r| r.length).sum();
    let record_count = clusters.saturating_mul(cluster) / record_size.max(1);
    writeln!(out, "record size {record_size}, {clusters} $MFT clusters, {record_count} records")?;

    let started = std::time::Instant::now();
    for number in 0..record_count {
        let Ok(bytes) = volume.fs().read_record(number) else { continue };
        if !matches!(bytes.get(0..4), Some(b"FILE") | Some(b"BAAD")) {
            continue;
        }
        census.records_read += 1;
        let Ok(header) = MftRecordHeader::parse(&bytes) else { continue };
        if !header.is_base_record() {
            census.extension_records += 1;
            continue;
        }
        census.base_records += 1;
        let Ok(attrs) = ntfs_core::parse_attributes(&bytes, header.first_attribute_offset as usize)
        else {
            continue;
        };

        let has_list = attrs.iter().any(|a| a.type_code == ATTR_ATTRIBUTE_LIST);
        let has_reparse_attr = attrs.iter().any(|a| a.type_code == ATTR_REPARSE_POINT);
        let has_name = attrs.iter().any(|a| a.type_code == ATTR_FILE_NAME);
        let si_reparse = attrs
            .iter()
            .find(|a| a.type_code == ATTR_STANDARD_INFORMATION)
            .and_then(|a| a.resident_content(&bytes))
            .and_then(|c| ntfs_core::StandardInformation::parse(c).ok())
            .is_some_and(|si| si.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0);

        if has_reparse_attr {
            census.reparse_attribute_in_base += 1;
        }
        if si_reparse {
            census.standard_information_says_reparse += 1;
        }
        if !has_list {
            continue;
        }
        census.with_list += 1;
        if !has_name {
            census.with_list_unnamed += 1;
        }
        if !has_reparse_attr {
            census.with_list_no_reparse_attribute += 1;
        }
        if si_reparse {
            census.with_list_si_reparse += 1;
        }
        if si_reparse && !has_reparse_attr {
            census.with_list_si_reparse_no_attribute += 1;
            if has_name {
                census.named_and_would_follow += 1;
            }
            if follow {
                let wanted = [ATTR_FILE_NAME, ATTR_DATA, ATTR_REPARSE_POINT];
                for extension in volume.extension_records(number, &wanted).into_records() {
                    census.extension_records_read += 1;
                    census.extension_bytes_read += extension.len() as u64;
                }
            }
        }
    }
    let elapsed = started.elapsed();

    writeln!(out, "records read              {}", census.records_read)?;
    writeln!(out, "  base records            {}", census.base_records)?;
    writeln!(out, "  extension records       {}", census.extension_records)?;
    writeln!(out, "$REPARSE_POINT in base    {}", census.reparse_attribute_in_base)?;
    writeln!(out, "$SI says REPARSE_POINT    {}", census.standard_information_says_reparse)?;
    writeln!(out, "$ATTRIBUTE_LIST present   {}   <- widest gate", census.with_list)?;
    writeln!(out, "  ... and no name in base {}   <- today's gate", census.with_list_unnamed)?;
    writeln!(out, "  ... and no $REPARSE_PT  {}", census.with_list_no_reparse_attribute)?;
    writeln!(out, "  ... and $SI says rp     {}", census.with_list_si_reparse)?;
    writeln!(
        out,
        "  ... and $SI rp, no attr {}   <- narrow gate",
        census.with_list_si_reparse_no_attribute
    )?;
    writeln!(
        out,
        "      of those, named     {}   <- invisible today",
        census.named_and_would_follow
    )?;
    if follow {
        writeln!(
            out,
            "extension records read    {} ({} bytes)",
            census.extension_records_read, census.extension_bytes_read
        )?;
    }
    writeln!(out, "walk wall clock           {:.3} s (follow={follow})", elapsed.as_secs_f64())?;
    writeln!(
        out,
        "\nCross-check `$ATTRIBUTE_LIST present` against the run's own\n\
         `$MFT records with an $ATTRIBUTE_LIST` coverage line. They should agree;\n\
         if they do not, one of the two is counting something else."
    )?;
    Ok(census)
}
