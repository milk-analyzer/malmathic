use std::collections::BTreeMap;
use std::io::{Read, Seek};

use mm_raw::{Bounds, Fate, Slack, SweepStats, Volume};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(image) = args.first() else {
        eprintln!("usage: slackstudy <image> [--dir PATH] [--list N] [--max N]");
        std::process::exit(2);
    };
    let dir = flag(&args, "--dir");
    let list: usize = flag(&args, "--list").and_then(|v| v.parse().ok()).unwrap_or(25);
    let max: u64 = flag(&args, "--max").and_then(|v| v.parse().ok()).unwrap_or(u64::MAX);

    let partitions = mm_env::find_ntfs_partitions(std::path::Path::new(image))
        .expect("scanning the image for NTFS");
    let mut chosen = None;
    for partition in &partitions {
        if let Ok(volume) = mm_env::open_partition(std::path::Path::new(image), *partition) {
            if volume.is_windows_install() {
                println!("volume at offset {} carries Windows", partition.offset);
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
    println!(
        "cluster {} bytes, {} $MFT records, volume {} bytes\n",
        bounds.cluster, bounds.records, bounds.volume_bytes
    );

    if let Some(record) = flag(&args, "--probe").and_then(|v| v.parse::<u64>().ok()) {
        println!("record {record} is {:?}", volume.record_identity(record).map(|i| i.name));
        match volume.list_directory_entries_of_record(record) {
            Ok(children) => {
                for child in children.iter().take(list.max(40)) {
                    println!("  child {:<40} record {}", child.name, child.record);
                }
                println!("  {} children", children.len());
            }
            Err(e) => println!("  not listable: {e}"),
        }
        return;
    }
    if args.iter().any(|a| a == "--carve") {
        carve(&volume, &bounds, list, max);
        return;
    }
    match dir {
        Some(path) => one_directory(&volume, &bounds, &path, list),
        None => whole_volume(&volume, &bounds, list, max),
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1).cloned()
}

fn one_directory<R: Read + Seek>(volume: &Volume<R>, bounds: &Bounds, path: &str, list: usize) {
    let Some(record) = volume.resolve(path) else {
        eprintln!("{path} does not resolve on this volume");
        return;
    };
    println!("{path} is $MFT record {record}");
    match &volume.list_directory_entries_checked(path) {
        Ok(entries) => println!("  {} live children", entries.len()),
        Err(e) => println!("  live listing refused: {e}"),
    }

    let found = volume.deleted_index_entries(record, bounds);
    report_stats("  ", &found.stats);
    let mut why: BTreeMap<&str, u64> = BTreeMap::new();
    for reason in &found.refused_live {
        *why.entry(reason).or_default() += 1;
    }
    for (reason, n) in &why {
        println!("    live entry refused: {reason:<58} {n}");
    }
    for entry in found.entries.iter().take(list) {
        let fate = volume.record_fate(entry.record, entry.sequence);
        println!(
            "  {:<44} {:>12} bytes  record {}/{}  {}  [{}]  {}",
            entry.name,
            entry.real_size,
            entry.record,
            entry.sequence,
            mm_core::from_filetime(entry.created)
                .map(mm_core::filetime::format)
                .unwrap_or_default(),
            entry.found_in,
            fate
        );
    }
    if found.entries.len() > list {
        println!("  ... and {} more", found.entries.len() - list);
    }
}

fn whole_volume<R: Read + Seek>(volume: &Volume<R>, bounds: &Bounds, list: usize, max: u64) {
    let mut stats = SweepStats::default();
    let mut directories = 0u64;
    let mut directories_with_slack = 0u64;
    let mut by_source: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut fates: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut executables = 0u64;
    let mut gone_executables = 0u64;
    let mut interesting: Vec<String> = Vec::new();
    let mut refusals: BTreeMap<&'static str, u64> = BTreeMap::new();
    let started = std::time::Instant::now();

    let ceiling = bounds.records.min(max);
    for record in 0..ceiling {
        let Ok(bytes) = volume.fs().read_record(record) else { continue };
        let Ok(header) = ntfs_core::MftRecordHeader::parse(&bytes) else { continue };
        if &header.signature != b"FILE"
            || !header.is_in_use()
            || !header.is_base_record()
            || !header.is_directory()
        {
            continue;
        }
        directories += 1;
        let found = volume.deleted_index_entries(record, bounds);
        stats.add(found.stats);
        for reason in &found.refused_live {
            *refusals.entry(reason).or_default() += 1;
            if std::env::var_os("MM_SLACK_WHERE").is_some() {
                println!("    refusal in record {record}: {reason}");
            }
        }
        if !found.entries.is_empty() {
            directories_with_slack += 1;
        }
        for entry in &found.entries {
            *by_source.entry(source_name(entry.found_in)).or_default() += 1;
            let fate = volume.record_fate(entry.record, entry.sequence);
            *fates.entry(fate_name(&fate)).or_default() += 1;
            let executable = entry.name.to_ascii_lowercase().ends_with(".exe")
                || entry.name.to_ascii_lowercase().ends_with(".dll")
                || entry.name.to_ascii_lowercase().ends_with(".sys")
                || entry.name.to_ascii_lowercase().ends_with(".scr");
            if executable {
                executables += 1;
                if fate.is_gone() {
                    gone_executables += 1;
                    if interesting.len() < list {
                        interesting.push(format!(
                            "{:<40} {:>11} bytes  record {}/{}  [{}]  {}",
                            entry.name,
                            entry.real_size,
                            entry.record,
                            entry.sequence,
                            entry.found_in,
                            fate
                        ));
                    }
                }
            }
        }
    }

    println!("swept {directories} directories in {:.1}s", started.elapsed().as_secs_f64());
    println!("  {directories_with_slack} of them gave up at least one entry");
    report_stats("  ", &stats);
    if refusals.is_empty() {
        println!("\n  the validator refused no live entry anywhere on this volume");
    } else {
        println!("\n  live entries this validator refused, by rule:");
        for (reason, n) in &refusals {
            println!("    {reason:<62} {n}");
        }
    }
    println!("\n  by source:");
    for (source, n) in &by_source {
        println!("    {source:<24} {n}");
    }
    println!("\n  what became of the record each entry names:");
    for (fate, n) in &fates {
        println!("    {fate:<24} {n}");
    }
    println!("\n  {executables} entries name an executable; {gone_executables} of those are gone");
    for line in &interesting {
        println!("    {line}");
    }
}

fn carve<R: Read + Seek>(volume: &Volume<R>, bounds: &Bounds, list: usize, max: u64) {
    let Ok(bitmap) = volume.read_record_capped(6, 64 * 1024 * 1024) else {
        eprintln!("$Bitmap could not be read; a carve of free space is refused");
        return;
    };
    let started = std::time::Instant::now();
    let found = volume.carved_index_entries(&bitmap, bounds, max);
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "read {} free clusters ({:.1} MB) in {seconds:.1}s = {:.0} MB/s",
        found.scanned_clusters,
        found.bytes_read as f64 / 1e6,
        found.bytes_read as f64 / 1e6 / seconds.max(1e-9)
    );
    println!(
        "  {} cluster-aligned INDX pages, {} verified their update-sequence array, {}          disagreed on their parent",
        found.buffers, found.fixed_up, found.disagreeing_pages
    );
    println!("  {} entries recovered", found.entries.len());
    if let Some(why) = &found.stopped {
        println!("  stopped: {why}");
    }
    let mut parents: BTreeMap<u64, u64> = BTreeMap::new();
    let mut gone = 0u64;
    let mut executables = 0u64;
    for entry in &found.entries {
        *parents.entry(entry.parent_record).or_default() += 1;
        let fate = volume.record_fate(entry.record, entry.sequence);
        if fate.is_gone() {
            gone += 1;
        }
        let lower = entry.name.to_ascii_lowercase();
        if [".exe", ".dll", ".sys", ".scr"].iter().any(|e| lower.ends_with(e)) {
            executables += 1;
            if executables as usize <= list {
                println!(
                    "    {:<44} {:>11} bytes  parent {}  record {}/{}  {fate}",
                    entry.name, entry.real_size, entry.parent_record, entry.record, entry.sequence
                );
            }
        }
    }
    for entry in found.entries.iter().take(list) {
        println!(
            "    {:<52} {:>11} bytes  parent {}  record {}/{}",
            entry.name, entry.real_size, entry.parent_record, entry.record, entry.sequence
        );
    }
    println!("  {} distinct parent directories", parents.len());
    for (parent, n) in &parents {
        println!(
            "    parent {parent:<8} {n:>5} entries  now: {:?}",
            volume.record_identity(*parent).map(|i| (i.name, i.in_use))
        );
    }
    println!("  {gone} name a record that is gone; {executables} name an executable");
    let mut orphaned = 0u64;
    for parent in parents.keys() {
        if volume.list_directory_entries_of_record(*parent).is_err() {
            orphaned += 1;
        }
    }
    println!("  {orphaned} of those parents are no longer readable directories");
}

fn report_stats(indent: &str, stats: &SweepStats) {
    println!(
        "{indent}{} bytes of slack swept, {} entries recovered, {} duplicates dropped",
        stats.slack_bytes, stats.recovered, stats.duplicates
    );
    println!(
        "{indent}validator self-check: {} of {} live entries accepted{}",
        stats.live_accepted,
        stats.live_seen,
        if stats.live_seen == stats.live_accepted { "" } else { "   <-- MISMATCH" }
    );
}

fn source_name(slack: Slack) -> &'static str {
    match slack {
        Slack::IndexRoot => "$INDEX_ROOT slack",
        Slack::Record => "MFT record slack",
        Slack::IndexBuffer { .. } => "INDX buffer slack",
        Slack::FreeIndexBuffer { .. } => "free INDX buffer",
        Slack::Unallocated { .. } => "carved INDX buffer",
    }
}

fn fate_name(fate: &Fate) -> &'static str {
    match fate {
        Fate::Free => "record free",
        Fate::FreedAgain { .. } => "record freed again",
        Fate::StillThere => "file still there",
        Fate::Reallocated { .. } => "record REALLOCATED",
        Fate::Unknown => "unknown",
    }
}
