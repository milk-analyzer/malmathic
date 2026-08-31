use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;

use mm_core::{Candidate, NormalizedPath, ObservationKind};
use mm_score::zone::{classify, Zone};

const SELF_FRAGMENTS: &[&str] = &[r"appdata\local\temp\claude", r"documents\malmathic\target"];

fn writable_zone(z: Zone) -> bool {
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
}

fn dir_of(p: &NormalizedPath) -> String {
    p.key().rsplit_once('\\').map(|(d, _)| d.to_string()).unwrap_or_default()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exclude_self = args.iter().any(|a| a == "--exclude-self");
    let report = args.iter().find(|a| !a.starts_with("--")).expect("a report path");

    let text = std::fs::read_to_string(report).expect("report readable");
    let value: serde_json::Value = serde_json::from_str(&text).expect("json");
    let mut candidates: Vec<Candidate> =
        serde_json::from_value(value["candidates"].clone()).expect("candidates");
    if exclude_self {
        candidates.retain(|c| {
            let Some(p) = &c.path else { return true };
            !SELF_FRAGMENTS.iter().any(|f| p.key().contains(f))
        });
    }

    println!("== {report}: {} candidates", candidates.len());

    let mut recorded: HashMap<usize, String> = HashMap::new();
    for (i, c) in candidates.iter().enumerate() {
        if let Some(h) = c.hash.sha1 {
            recorded.insert(i, format!("sha1:{}", hex(&h)));
        }
    }

    let mut computed: HashMap<usize, String> = HashMap::new();
    let (mut tried, mut read_ok, mut missing, mut denied) = (0usize, 0usize, 0usize, 0usize);
    let mut buf = Vec::new();
    for (i, c) in candidates.iter().enumerate() {
        let Some(p) = &c.path else { continue };
        if !p.is_located() {
            continue;
        }
        let exists =
            c.observations.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. }));
        if !exists {
            continue;
        }
        tried += 1;
        let raw = p.raw();
        match std::fs::File::open(raw) {
            Ok(mut f) => {
                buf.clear();
                match f.read_to_end(&mut buf) {
                    Ok(_) => {
                        read_ok += 1;
                        let h = mm_core::FileHash::compute(&buf);
                        computed.insert(i, format!("sha256:{}", hex(&h.sha256.unwrap())));
                    }
                    Err(_) => denied += 1,
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing += 1,
            Err(_) => denied += 1,
        }
    }
    println!(
        "   on-disk candidates: {tried}; hashed now {read_ok}; gone since {missing}; unreadable {denied}"
    );

    let mut parent: Vec<usize> = (0..candidates.len()).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut has_digest: HashSet<usize> = HashSet::new();
    for i in 0..candidates.len() {
        let mut keys: Vec<String> = Vec::new();
        if let Some(k) = recorded.get(&i) {
            keys.push(k.clone());
        }
        if let Some(k) = computed.get(&i) {
            keys.push(k.clone());
        }
        if keys.is_empty() {
            continue;
        }
        has_digest.insert(i);
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
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in has_digest.iter().copied() {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }

    let (mut r1, mut r2, mut r3) = (0usize, 0usize, 0usize);
    let (mut r4, mut r5) = (0usize, 0usize);
    let (mut r4_members, mut r5_members) = (0usize, 0usize);
    let mut r4_rows: Vec<String> = Vec::new();
    let mut rows: Vec<String> = Vec::new();
    let mut r1_rows: Vec<String> = Vec::new();
    for members in groups.values() {
        let located: Vec<usize> = members
            .iter()
            .copied()
            .filter(|&i| candidates[i].path.as_ref().is_some_and(|p| p.is_located()))
            .collect();
        let dirs: HashSet<String> =
            located.iter().map(|&i| dir_of(candidates[i].path.as_ref().unwrap())).collect();
        if located.len() < 2 || dirs.len() < 2 {
            continue;
        }
        r1 += 1;
        let describe = || {
            located
                .iter()
                .map(|&i| {
                    let p = candidates[i].path.as_ref().unwrap();
                    format!(
                        "p={:.3} {}[{}]",
                        candidates[i].probability(),
                        p.key(),
                        classify(p).label()
                    )
                })
                .collect::<Vec<_>>()
                .join("  ||  ")
        };
        r1_rows.push(describe());
        let zones: HashSet<Zone> =
            located.iter().map(|&i| classify(candidates[i].path.as_ref().unwrap())).collect();
        if zones.len() < 2 {
            continue;
        }
        r2 += 1;
        rows.push(describe());
        if zones.iter().copied().any(writable_zone) {
            r3 += 1;
        }
        let names: HashSet<String> = located
            .iter()
            .filter_map(|&i| candidates[i].path.as_ref().unwrap().file_name().map(str::to_string))
            .collect();
        if names.len() >= 2 {
            r4 += 1;
            r4_members += located.len();
            r4_rows.push(describe());
            if located.len() <= 3 {
                r5 += 1;
                r5_members += located.len();
            }
        }
    }

    println!("   candidates carrying a digest (recorded or computed): {}", has_digest.len());
    println!("   R1 located, >=2 directories      : {r1}");
    println!("   R2 R1 and >=2 zones              : {r2}");
    println!("   R3 R2 and >=1 user-writable zone : {r3}");
    println!("   R4 R2 and >=2 distinct file names : {r4} groups, {r4_members} candidates");
    println!("   R5 R4 and group size <= 3         : {r5} groups, {r5_members} candidates");
    println!("   -- R4 groups (cap 60) --");
    for r in r4_rows.iter().take(60) {
        println!("       {r}");
    }
    println!("   -- R1 groups (cap 60) --");
    for r in r1_rows.iter().take(60) {
        println!("       {r}");
    }
    println!("   -- R2 groups (cap 60) --");
    for r in rows.iter().take(60) {
        println!("       {r}");
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
