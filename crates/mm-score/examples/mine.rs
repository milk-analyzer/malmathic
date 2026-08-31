use std::collections::{BTreeMap, HashMap, HashSet};

use mm_core::{ArtifactSource, Candidate, ObservationKind};
use mm_score::zone::{classify, Zone};

const SELF_FRAGMENTS: &[&str] = &[r"appdata\local\temp\claude", r"documents\malmathic\target"];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exclude_self = args.iter().any(|a| a == "--exclude-self");
    let reports: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();

    for path in reports {
        let text = std::fs::read_to_string(path).expect("report readable");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        let mut candidates: Vec<Candidate> =
            serde_json::from_value(value["candidates"].clone()).expect("candidates");
        if exclude_self {
            candidates.retain(|c| {
                let Some(p) = &c.path else { return true };
                !SELF_FRAGMENTS.iter().any(|f| p.key().contains(f))
            });
        }
        println!("\n================ {path}  ({} candidates)", candidates.len());

        digests(&candidates);
        executions(&candidates);
        deletions(&candidates);
        unscored_kinds(&candidates);
    }
}

fn digests(candidates: &[Candidate]) {
    let contradicted: HashSet<u32> = candidates
        .iter()
        .filter(|c| c.hash_checks.iter().any(|k| !k.agrees))
        .map(|c| c.id.0)
        .collect();

    let live: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| !contradicted.contains(&c.id.0))
        .filter(|c| !c.hash.is_empty())
        .collect();
    let with_digest = live.len();
    let mut parent: Vec<usize> = (0..live.len()).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut index: HashMap<(&'static str, String), usize> = HashMap::new();
    for (i, c) in live.iter().enumerate() {
        let mut keys: Vec<(&'static str, String)> = Vec::new();
        if let Some(h) = c.hash.sha256 {
            keys.push(("sha256", hex(&h)));
        }
        if let Some(h) = c.hash.sha1 {
            keys.push(("sha1", hex(&h)));
        }
        if let Some(h) = c.hash.md5 {
            keys.push(("md5", hex(&h)));
        }
        for k in keys {
            match index.get(&k) {
                Some(&j) => {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    if a != b {
                        parent[a] = b;
                    }
                }
                None => {
                    index.insert(k, i);
                }
            }
        }
    }
    let mut groups: HashMap<usize, Vec<&Candidate>> = HashMap::new();
    for (i, candidate) in live.iter().enumerate() {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(candidate);
    }

    let mut dup: Vec<(&usize, &Vec<&Candidate>)> = groups
        .iter()
        .filter(|(_, v)| {
            let paths: HashSet<&str> =
                v.iter().filter_map(|c| c.path.as_ref()).map(|p| p.key()).collect();
            paths.len() >= 2
        })
        .collect();
    dup.sort_by_key(|(k, _)| **k);

    let mut cross_zone = 0usize;
    let mut conv_to_writable = 0usize;
    let mut interesting: Vec<String> = Vec::new();
    for (_, v) in &dup {
        let zones: HashSet<Zone> = v.iter().filter_map(|c| c.path.as_ref()).map(classify).collect();
        if zones.len() >= 2 {
            cross_zone += 1;
        }
        let has_conv = zones.iter().any(|z| z.is_conventional_for_executables());
        let has_writable = zones.iter().any(|z| {
            matches!(
                z,
                Zone::UserTemp
                    | Zone::UserAppData
                    | Zone::UserDownloads
                    | Zone::UserProfile
                    | Zone::ProgramData
                    | Zone::WindowsTemp
                    | Zone::VolumeRoot
                    | Zone::Other
            )
        });
        if has_conv && has_writable {
            conv_to_writable += 1;
            let names: Vec<String> = v
                .iter()
                .filter_map(|c| c.path.as_ref())
                .map(|p| format!("{} [{}]", p.key(), classify(p).label()))
                .collect();
            interesting.push(names.join("  ||  "));
        }
    }

    let (mut r1, mut r2, mut r3) = (0usize, 0usize, 0usize);
    let (mut r4, mut r5, mut r4_members, mut r5_members) = (0usize, 0usize, 0usize, 0usize);
    let mut r4_rows: Vec<String> = Vec::new();
    let mut r2_rows: Vec<String> = Vec::new();
    for (_, v) in &dup {
        let located: Vec<&&Candidate> =
            v.iter().filter(|c| c.path.as_ref().is_some_and(|p| p.is_located())).collect();
        let dirs: HashSet<String> = located
            .iter()
            .filter_map(|c| c.path.as_ref())
            .map(|p| {
                let k = p.key();
                k.rsplit_once('\\').map(|(d, _)| d.to_string()).unwrap_or_default()
            })
            .collect();
        if located.len() < 2 || dirs.len() < 2 {
            continue;
        }
        r1 += 1;
        let zones: HashSet<Zone> =
            located.iter().filter_map(|c| c.path.as_ref()).map(classify).collect();
        if zones.len() < 2 {
            continue;
        }
        r2 += 1;
        r2_rows.push(
            located
                .iter()
                .map(|c| {
                    format!(
                        "p={:.4} {}[{}]",
                        c.probability(),
                        c.path.as_ref().unwrap().key(),
                        classify(c.path.as_ref().unwrap()).label()
                    )
                })
                .collect::<Vec<_>>()
                .join("  ||  "),
        );
        if zones.iter().any(|z| {
            matches!(
                z,
                Zone::UserTemp
                    | Zone::UserAppData
                    | Zone::UserDownloads
                    | Zone::UserProfile
                    | Zone::ProgramData
                    | Zone::WindowsTemp
                    | Zone::VolumeRoot
                    | Zone::RecycleBin
                    | Zone::Other
            )
        }) {
            r3 += 1;
        }
        let names: HashSet<String> = located
            .iter()
            .filter_map(|c| c.path.as_ref())
            .filter_map(|p| p.file_name().map(str::to_string))
            .collect();
        if names.len() >= 2 {
            r4 += 1;
            r4_members += located.len();
            r4_rows.push(
                located
                    .iter()
                    .map(|c| {
                        format!(
                            "p={:.4} {}[{}]",
                            c.probability(),
                            c.path.as_ref().unwrap().key(),
                            classify(c.path.as_ref().unwrap()).label()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("  ||  "),
            );
            if located.len() <= 3 {
                r5 += 1;
                r5_members += located.len();
            }
        }
    }

    println!("-- digest duplicate groups --");
    println!("   candidates with a usable digest : {with_digest}");
    println!("   R1 located, >=2 directories                 : {r1}");
    println!("   R2 R1 and >=2 zones                         : {r2}");
    println!("   R3 R2 and >=1 user-writable zone            : {r3}");
    println!(
        "   R4 R2 and >=2 distinct file names            : {r4} groups, {r4_members} candidates"
    );
    println!(
        "   R5 R4 and group size <= 3                    : {r5} groups, {r5_members} candidates"
    );
    for row in r4_rows.iter().take(30) {
        println!("       R4: {row}");
    }
    for row in r2_rows.iter().take(30) {
        println!("       R2: {row}");
    }
    println!("   duplicate-digest groups (>=2 distinct paths) : {}", dup.len());
    println!("   ... of which span >=2 zones     : {cross_zone}");
    println!(
        "   ... of which span a conventional zone AND a user-writable one : {conv_to_writable}"
    );
    for line in interesting.iter().take(40) {
        println!("       {line}");
    }
    let mut shown = 0;
    println!("   -- every cross-zone group (cap 60) --");
    for (_, v) in &dup {
        let zones: HashSet<Zone> = v.iter().filter_map(|c| c.path.as_ref()).map(classify).collect();
        if zones.len() < 2 {
            continue;
        }
        if shown >= 60 {
            println!("       ... more not shown");
            break;
        }
        shown += 1;
        let names: Vec<String> = v
            .iter()
            .filter_map(|c| c.path.as_ref())
            .map(|p| format!("{}[{}]", p.key(), classify(p).label()))
            .collect();
        println!("       {}", names.join("  ||  "));
    }
    println!("   -- cross-zone groups, annotated (cap 60) --");
    let mut ann = 0;
    for (_, v) in &dup {
        let zones: HashSet<Zone> = v.iter().filter_map(|c| c.path.as_ref()).map(classify).collect();
        if zones.len() < 2 || ann >= 60 {
            continue;
        }
        ann += 1;
        println!("       group of {}:", v.len());
        for c in v.iter() {
            let read = if c.acquired_hash.as_ref().is_some_and(|h| !h.is_empty()) {
                "read"
            } else {
                "remembered"
            };
            let ran =
                c.observations.iter().any(|o| matches!(o.kind, ObservationKind::Executed { .. }));
            println!(
                "          p={:.4} {:<10} ran={} {} [{}]",
                c.probability(),
                read,
                ran,
                c.path.as_ref().map(|p| p.key().to_string()).unwrap_or_default(),
                c.path.as_ref().map(|p| classify(p).label()).unwrap_or("?")
            );
        }
    }
    let mut same_zone_names: BTreeMap<String, usize> = BTreeMap::new();
    for (_, v) in &dup {
        let zones: HashSet<Zone> = v.iter().filter_map(|c| c.path.as_ref()).map(classify).collect();
        if zones.len() >= 2 {
            continue;
        }
        let mut names: Vec<String> = v
            .iter()
            .filter_map(|c| c.path.as_ref())
            .filter_map(|p| p.file_name().map(|s| s.to_string()))
            .collect();
        names.sort();
        names.dedup();
        *same_zone_names.entry(names.join(",")).or_default() += 1;
    }
    println!("   -- same-zone groups by name set (cap 40) --");
    for (k, n) in same_zone_names.iter().take(40) {
        println!("       x{n}  {k}");
    }
}

fn executions(candidates: &[Candidate]) {
    let mut runcount_hist: BTreeMap<u32, usize> = BTreeMap::new();
    let mut with_runcount = 0usize;
    let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut executed = 0usize;
    let mut spread_hist: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut sources_per_candidate: BTreeMap<usize, usize> = BTreeMap::new();

    for c in candidates {
        let mut any = false;
        let mut srcs: HashSet<String> = HashSet::new();
        let mut times: Vec<chrono::DateTime<chrono::Utc>> = Vec::new();
        let mut best_rc: Option<u32> = None;
        for o in &c.observations {
            if let ObservationKind::Executed { when, run_count } = &o.kind {
                any = true;
                let s = format!("{:?}", o.source);
                let s = s.split(' ').next().unwrap().to_string();
                srcs.insert(s.clone());
                *by_source.entry(s).or_default() += 1;
                if let Some(t) = when {
                    times.push(*t);
                }
                if let Some(rc) = run_count {
                    best_rc = Some(best_rc.map_or(*rc, |b: u32| b.max(*rc)));
                }
            }
        }
        if !any {
            continue;
        }
        executed += 1;
        *sources_per_candidate.entry(srcs.len()).or_default() += 1;
        if let Some(rc) = best_rc {
            with_runcount += 1;
            *runcount_hist.entry(rc.min(50)).or_default() += 1;
        }
        if times.len() >= 2 {
            times.sort();
            let gap = *times.last().unwrap() - *times.first().unwrap();
            let bucket = if gap.num_seconds() < 60 {
                "<1min"
            } else if gap.num_hours() < 1 {
                "<1h"
            } else if gap.num_days() < 1 {
                "<1d"
            } else if gap.num_days() < 30 {
                "<30d"
            } else {
                ">=30d"
            };
            *spread_hist.entry(bucket).or_default() += 1;
        }
    }

    let mut rc_by_source: BTreeMap<String, BTreeMap<&'static str, usize>> = BTreeMap::new();
    for c in candidates {
        for o in &c.observations {
            if let ObservationKind::Executed { run_count: Some(rc), .. } = &o.kind {
                let s = format!("{:?}", o.source);
                let bucket = match rc {
                    0 => "0",
                    1 => "1",
                    2..=4 => "2-4",
                    5..=20 => "5-20",
                    _ => "21+",
                };
                *rc_by_source
                    .entry(s.split(' ').next().unwrap().to_string())
                    .or_default()
                    .entry(bucket)
                    .or_default() += 1;
            }
        }
    }
    println!("-- execution --");
    println!("   run_count by source and size: {rc_by_source:?}");
    println!("   candidates with any Executed observation : {executed}");
    println!("   ... with a run_count                     : {with_runcount}");
    println!("   run_count histogram (capped at 50): {runcount_hist:?}");
    println!("   Executed observations by source: {by_source:?}");
    println!("   distinct execution artifacts per executed candidate: {sources_per_candidate:?}");
    println!("   first->last execution spread: {spread_hist:?}");
}

fn deletions(candidates: &[Candidate]) {
    let mut both = 0usize;
    let mut rows: Vec<String> = Vec::new();
    let mut deleted_any = 0usize;
    let mut deleted_by_source: BTreeMap<String, usize> = BTreeMap::new();
    for c in candidates {
        let mut ran: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut ran_shim: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut del: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut del_recycle = false;
        let mut has_del = false;
        for o in &c.observations {
            match &o.kind {
                ObservationKind::Executed { when: Some(t), .. } => {
                    if o.source == ArtifactSource::ShimCache {
                        ran_shim =
                            Some(ran_shim.map_or(*t, |e: chrono::DateTime<chrono::Utc>| e.max(*t)));
                    } else {
                        ran = Some(ran.map_or(*t, |e: chrono::DateTime<chrono::Utc>| e.max(*t)));
                    }
                }
                ObservationKind::FileDeleted { when, .. } => {
                    has_del = true;
                    let s = format!("{:?}", o.source);
                    *deleted_by_source
                        .entry(s.split(' ').next().unwrap().to_string())
                        .or_default() += 1;
                    if o.source == ArtifactSource::RecycleBin {
                        del_recycle = true;
                    } else if let Some(t) = when {
                        del = Some(del.map_or(*t, |e: chrono::DateTime<chrono::Utc>| e.min(*t)));
                    }
                }
                _ => {}
            }
        }
        if has_del {
            deleted_any += 1;
        }
        let r = ran.or(ran_shim);
        if let (Some(r), Some(d)) = (r, del) {
            both += 1;
            let gap = d - r;
            rows.push(format!(
                "{:>12}s  {}  {}",
                gap.num_seconds(),
                if del_recycle { "(also recycle)" } else { "              " },
                c.path.as_ref().map(|p| p.key().to_string()).unwrap_or_default()
            ));
        }
    }
    let (mut del_obs, mut del_obs_timed) = (0usize, 0usize);
    let mut timed_by_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut cand_timed = 0usize;
    let mut cand_timed_nonrecycle = 0usize;
    let mut cand_executed_and_timed_del = 0usize;
    for c in candidates {
        let mut any_timed = false;
        let mut any_timed_nonrecycle = false;
        for o in &c.observations {
            if let ObservationKind::FileDeleted { when, .. } = &o.kind {
                del_obs += 1;
                if when.is_some() {
                    del_obs_timed += 1;
                    any_timed = true;
                    if o.source != ArtifactSource::RecycleBin {
                        any_timed_nonrecycle = true;
                    }
                    let s = format!("{:?}", o.source);
                    *timed_by_source
                        .entry(s.split(' ').next().unwrap().to_string())
                        .or_default() += 1;
                }
            }
        }
        if any_timed {
            cand_timed += 1;
        }
        if any_timed_nonrecycle {
            cand_timed_nonrecycle += 1;
            if c.observations.iter().any(|o| matches!(o.kind, ObservationKind::Executed { .. })) {
                cand_executed_and_timed_del += 1;
            }
        }
    }
    println!("-- deletion --");
    println!(
        "   candidates with any FileDeleted   : {deleted_any}  by source {deleted_by_source:?}"
    );
    println!("   FileDeleted observations: {del_obs}, of which carry a moment: {del_obs_timed} {timed_by_source:?}");
    println!("   candidates with a TIMED deletion: {cand_timed}; non-recycle: {cand_timed_nonrecycle}; of those also executed: {cand_executed_and_timed_del}");
    println!("   with BOTH an execution time and a non-recycle deletion time : {both}");
    rows.sort();
    for r in rows.iter().take(40) {
        println!("       {r}");
    }
}

fn unscored_kinds(candidates: &[Candidate]) {
    let mut kinds: BTreeMap<&'static str, usize> = BTreeMap::new();
    for c in candidates {
        for o in &c.observations {
            let k = match &o.kind {
                ObservationKind::FileExists { .. } => "FileExists",
                ObservationKind::FileDeleted { .. } => "FileDeleted",
                ObservationKind::DeletedRegistryValue { .. } => "DeletedRegistryValue",
                ObservationKind::Executed { .. } => "Executed",
                ObservationKind::Persistence { .. } => "Persistence",
                ObservationKind::DownloadedFrom { .. } => "DownloadedFrom",
                ObservationKind::HashRecovered => "HashRecovered",
                ObservationKind::Signature(_) => "Signature",
                ObservationKind::ManagedAssembly => "ManagedAssembly",
                ObservationKind::Quarantined { .. } => "Quarantined",
                ObservationKind::AvDetected { .. } => "AvDetected",
                ObservationKind::ArrivedOutOfBand(_) => "ArrivedOutOfBand",
                ObservationKind::CompactOsCompressed { .. } => "CompactOsCompressed",
                ObservationKind::NoVersionResource => "NoVersionResource",
                ObservationKind::SharedDigestElsewhere { .. } => "SharedDigestElsewhere",
                ObservationKind::YaraMatch { .. } => "YaraMatch",
                ObservationKind::PeAnomaly { .. } => "PeAnomaly",
                ObservationKind::RichHeaderChecksumInvalid { .. } => "RichHeaderChecksumInvalid",
                ObservationKind::ProcessRunning { .. } => "ProcessRunning",
                ObservationKind::UnbackedExecutableMemory { .. } => "UnbackedExecutableMemory",
            };
            *kinds.entry(k).or_default() += 1;
        }
    }
    println!("-- observation kinds present --");
    for (k, n) in &kinds {
        println!("       {n:>7}  {k}");
    }
}
