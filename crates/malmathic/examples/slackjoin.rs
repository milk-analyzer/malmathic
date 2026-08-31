use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};
use std::time::Instant;

use mm_raw::{Bounds, Fate, Volume};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(image) = args.first() else {
        eprintln!("usage: slackjoin <image> --paths <file> [--carve CLUSTERS] [--list N]");
        std::process::exit(2);
    };
    let list: usize = flag(&args, "--list").and_then(|v| v.parse().ok()).unwrap_or(30);
    let carve: Option<u64> = flag(&args, "--carve").and_then(|v| v.parse().ok());
    let paths: Vec<String> = match flag(&args, "--paths") {
        Some(file) => std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("reading {file}: {e}"))
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        None => Vec::new(),
    };

    let partitions = mm_env::find_ntfs_partitions(std::path::Path::new(image))
        .expect("scanning the image for NTFS");
    let mut chosen = None;
    for partition in &partitions {
        if let Ok(volume) = mm_env::open_partition(std::path::Path::new(image), *partition) {
            if volume.is_windows_install() {
                chosen = Some(volume);
                break;
            }
            if chosen.is_none() {
                chosen = Some(volume);
            }
        }
    }
    let Some(volume) = chosen else {
        eprintln!("no readable NTFS in {image}");
        std::process::exit(1);
    };
    let bounds = volume.slack_bounds();
    println!("{image}");
    println!(
        "  cluster {} B, {} $MFT records, volume {} B",
        bounds.cluster, bounds.records, bounds.volume_bytes
    );
    println!("  {} vanished candidate paths", paths.len());

    targeted(&volume, &bounds, &paths, list);
    if args.iter().any(|a| a == "--full") {
        full(&volume, &bounds, &paths, list);
    }
    if let Some(max) = carve {
        carved(&volume, &bounds, &paths, max, list);
    }
}

fn full<R: Read + Seek>(volume: &Volume<R>, bounds: &Bounds, paths: &[String], list: usize) {
    let started = Instant::now();
    let mut wanted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in paths {
        if let Some((dir, leaf)) = split(p) {
            wanted.entry(dir).or_default().insert(leaf);
        }
    }
    let mut dir_of_record: BTreeMap<u64, String> = BTreeMap::new();
    for dir in wanted.keys() {
        if let Some(r) = volume.resolve(dir) {
            dir_of_record.insert(r, dir.clone());
        }
    }

    let mut swept = 0u64;
    let mut recovered = 0u64;
    let mut dirs_giving = 0u64;
    let mut executables = 0u64;
    let mut by_fate: BTreeMap<&str, u64> = BTreeMap::new();
    let mut free_executables: Vec<mm_raw::DeletedIndexEntry> = Vec::new();
    let mut joined = 0u64;
    let mut live_shortfall = 0u64;

    for record in 0..bounds.records {
        let found = volume.deleted_index_entries(record, bounds);
        swept += found.stats.slack_bytes;
        recovered += found.stats.recovered;
        live_shortfall += found.stats.live_seen - found.stats.live_accepted;
        if !found.entries.is_empty() {
            dirs_giving += 1;
        }
        for entry in found.entries {
            let name = entry.name.to_lowercase();
            let exe = name.ends_with(".exe") || name.ends_with(".dll") || name.ends_with(".sys");
            if exe {
                executables += 1;
            }
            let fate = volume.record_fate(entry.record, entry.sequence);
            let key = match fate {
                Fate::Free => "Free (the record is still this file's: CARVEABLE)",
                Fate::FreedAgain { .. } => "FreedAgain",
                Fate::StillThere => "StillThere",
                Fate::Reallocated { .. } => "Reallocated",
                Fate::Unknown => "Unknown",
            };
            *by_fate.entry(key).or_default() += 1;
            if let Some(dir) = dir_of_record.get(&entry.parent_record) {
                if wanted.get(dir).is_some_and(|l| l.contains(&name)) {
                    joined += 1;
                }
            }
            if exe && fate.is_gone() {
                free_executables.push(entry);
            }
        }
    }

    println!("\n== whole-volume sweep: every $MFT record's directory slack");
    println!("  records swept                   {}", bounds.records);
    println!("  ...that gave up an entry        {dirs_giving}");
    println!("  slack swept                     {swept} B");
    println!("  entries recovered               {recovered}");
    println!("  live entries this refused       {live_shortfall}");
    println!("  naming an executable            {executables}");
    for (k, n) in &by_fate {
        println!("    {k:<50} {n}");
    }
    println!("  entries joining a vanished candidate  {joined}");
    println!("  wall clock                      {:.2} s", started.elapsed().as_secs_f64());
    for entry in free_executables.iter().take(list) {
        println!(
            "    FREE {:<44} {:>12} B  record {}/{}  parent {}  {}",
            entry.name,
            entry.real_size,
            entry.record,
            entry.sequence,
            entry.parent_record,
            entry.found_in
        );
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1).cloned()
}

fn split(path: &str) -> Option<(String, String)> {
    let at = path.rfind('\\')?;
    let (dir, leaf) = path.split_at(at);
    Some((dir.to_string(), leaf[1..].to_lowercase()))
}

fn targeted<R: Read + Seek>(volume: &Volume<R>, bounds: &Bounds, paths: &[String], list: usize) {
    let started = Instant::now();
    let mut wanted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut no_parent = 0usize;
    for p in paths {
        match split(p) {
            Some((dir, leaf)) => {
                wanted.entry(dir).or_default().insert(leaf);
            }
            None => no_parent += 1,
        }
    }

    let mut dirs_resolved = 0usize;
    let mut dirs_missing = 0usize;
    let mut swept_bytes = 0u64;
    let mut recovered = 0u64;
    let mut matched: Vec<(String, mm_raw::DeletedIndexEntry, Fate)> = Vec::new();
    let mut live_shortfall = 0u64;

    for (dir, leaves) in &wanted {
        let Some(record) = volume.resolve(dir) else {
            dirs_missing += 1;
            continue;
        };
        dirs_resolved += 1;
        let found = volume.deleted_index_entries(record, bounds);
        swept_bytes += found.stats.slack_bytes;
        recovered += found.stats.recovered;
        live_shortfall += found.stats.live_seen - found.stats.live_accepted;
        for entry in &found.entries {
            if entry.is_dos_name() {
                continue;
            }
            if leaves.contains(&entry.name.to_lowercase()) {
                let fate = volume.record_fate(entry.record, entry.sequence);
                matched.push((format!("{dir}\\{}", entry.name), entry.clone(), fate));
            }
        }
    }

    let elapsed = started.elapsed();
    println!("\n== targeted sweep: the parent directory of every vanished candidate");
    println!("  paths with no parent            {no_parent}");
    println!("  distinct parent directories     {}", wanted.len());
    println!("  ...that resolve on this volume  {dirs_resolved}");
    println!("  ...that do not                  {dirs_missing}");
    println!("  slack swept                     {swept_bytes} B");
    println!("  entries recovered               {recovered}");
    println!("  live entries this refused       {live_shortfall}");
    println!("  entries matching a vanished candidate  {}", matched.len());

    let mut by_fate: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, _, fate) in &matched {
        let key = match fate {
            Fate::Free => "Free (carveable: the record is still this file's)",
            Fate::FreedAgain { .. } => "FreedAgain (reallocated then freed again)",
            Fate::StillThere => "StillThere (the record is in use, same sequence)",
            Fate::Reallocated { .. } => "Reallocated (another file has the record)",
            Fate::Unknown => "Unknown",
        };
        *by_fate.entry(key).or_default() += 1;
    }
    for (k, n) in &by_fate {
        println!("    {k:<52} {n}");
    }
    let unique: BTreeSet<&String> = matched.iter().map(|(p, _, _)| p).collect();
    println!("  distinct candidate paths given an entry  {}", unique.len());
    println!("  wall clock                      {:.2} s", elapsed.as_secs_f64());
    for (path, entry, fate) in matched.iter().take(list) {
        println!(
            "    {path}\n      {} B, record {}/{}, {}, {}",
            entry.real_size, entry.record, entry.sequence, fate, entry.found_in
        );
    }
}

fn carved<R: Read + Seek>(
    volume: &Volume<R>,
    bounds: &Bounds,
    paths: &[String],
    max_clusters: u64,
    list: usize,
) {
    let started = Instant::now();
    let Ok(bitmap) = volume.read("\\$Bitmap") else {
        println!("\n== unallocated INDX carve: $Bitmap could not be read, so not attempted");
        return;
    };
    let read_bitmap = started.elapsed();
    let found = volume.carved_index_entries(&bitmap, bounds, max_clusters);
    let elapsed = started.elapsed();

    println!("\n== unallocated INDX carve");
    println!("  $Bitmap read in                 {:.2} s", read_bitmap.as_secs_f64());
    println!("  free clusters scanned           {}", found.scanned_clusters);
    println!("  bytes read                      {}", found.bytes_read);
    println!("  pages signed INDX               {}", found.buffers);
    println!("  ...whose fixup verified         {}", found.fixed_up);
    println!("  pages dropped, parents disagree {}", found.disagreeing_pages);
    println!("  entries recovered               {}", found.entries.len());
    println!("  duplicates dropped              {}", found.stats.duplicates);
    if let Some(stopped) = &found.stopped {
        println!("  STOPPED: {stopped}");
    }
    let executables = found
        .entries
        .iter()
        .filter(|e| {
            let n = e.name.to_lowercase();
            n.ends_with(".exe") || n.ends_with(".dll") || n.ends_with(".sys")
        })
        .count();
    println!("  naming an executable            {executables}");

    let mut leaf_to_dirs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in paths {
        if let Some((dir, leaf)) = split(p) {
            leaf_to_dirs.entry(leaf).or_default().insert(dir);
        }
    }
    let mut name_hits = 0usize;
    let mut parent_confirmed = 0usize;
    let mut shown = 0usize;
    for entry in &found.entries {
        let leaf = entry.name.to_lowercase();
        let Some(dirs) = leaf_to_dirs.get(&leaf) else { continue };
        name_hits += 1;
        for dir in dirs {
            if volume.resolve(dir) == Some(entry.parent_record) {
                parent_confirmed += 1;
                if shown < list {
                    shown += 1;
                    let fate = volume.record_fate(entry.record, entry.sequence);
                    println!(
                        "    PARENT-CONFIRMED {dir}\\{}\n      {} B, record {}/{}, {}, {}",
                        entry.name,
                        entry.real_size,
                        entry.record,
                        entry.sequence,
                        fate,
                        entry.found_in
                    );
                }
            }
        }
    }
    println!("  carved entries naming a vanished candidate leaf   {name_hits}");
    println!("  ...whose parent reference is that candidate's dir {parent_confirmed}");
    println!("  wall clock                      {:.2} s", elapsed.as_secs_f64());
}
