use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use mm_core::NormalizedPath;
use mm_score::baseline::BaselineBuilder;
use mm_score::zone::{classify, Zone};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new) };
        if !q.is_null() {
            if new >= layout.size() {
                LIVE.fetch_add(new - layout.size(), Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

const MIB: f64 = 1024.0 * 1024.0;

#[derive(Default)]
struct NameFacts {
    total: u32,
    conventional: u32,
    winsxs: u32,
    system_dir: u32,
    zones: Vec<Zone>,
    dirs: Vec<u64>,
    executable: bool,
    example: String,
}

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: namestudy <census.txt>   (from mm-env's filecensus)");
            std::process::exit(2);
        }
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("could not read {path}: {err}");
            std::process::exit(2);
        }
    };

    let before = live();
    let mut builder = BaselineBuilder::new();
    let mut parsed = 0u64;
    let mut unparsed = 0u64;
    for line in text.lines() {
        match NormalizedPath::parse(line) {
            Some(p) => {
                builder.observe(&p);
                parsed += 1;
            }
            None => unparsed += 1,
        }
    }
    let baseline = builder.build();
    let baseline_bytes = live().saturating_sub(before);

    println!("CENSUS  {path}");
    println!("  lines parsed          {parsed}");
    println!("  lines unparsable      {unparsed}");
    println!("  total_files           {}", baseline.total_files());
    println!("  total_executables     {}", baseline.total_executables());
    println!("  is_usable             {}", baseline.is_usable());
    println!();
    println!("BASELINE MEMORY, counted by a global allocator over the whole volume");
    println!(
        "  Baseline holds        {:.1} MiB   ({baseline_bytes} bytes)",
        baseline_bytes as f64 / MIB
    );
    println!("  per file              {:.1} bytes", baseline_bytes as f64 / parsed.max(1) as f64);
    println!(
        "  name entry (u64,u32)  {} bytes    (u64,u32,u32) {} bytes",
        std::mem::size_of::<(u64, u32)>(),
        std::mem::size_of::<(u64, (u32, u32))>()
    );
    println!();

    let mut names: HashMap<u64, NameFacts> = HashMap::new();
    for line in text.lines() {
        let Some(p) = NormalizedPath::parse(line) else { continue };
        let Some(name) = p.file_name() else { continue };
        let zone = classify(&p);
        let facts = names.entry(fnv(name)).or_default();
        if facts.total == 0 {
            facts.example = name.to_string();
            facts.executable = p.is_executable_extension();
        }
        facts.total = facts.total.saturating_add(1);
        if zone.is_conventional_for_executables() {
            facts.conventional = facts.conventional.saturating_add(1);
        }
        if zone == Zone::WinSxs {
            facts.winsxs = facts.winsxs.saturating_add(1);
        }
        if zone == Zone::SystemDir {
            facts.system_dir = facts.system_dir.saturating_add(1);
        }
        if !facts.zones.contains(&zone) {
            facts.zones.push(zone);
        }
        if let Some(parent) = p.parent() {
            let d = fnv(parent);
            if facts.dirs.len() < 64 && !facts.dirs.contains(&d) {
                facts.dirs.push(d);
            }
        }
    }

    println!("NAME RECURRENCE, over every file on the volume");
    let mut unique = 0u64;
    let mut twice = 0u64;
    let mut recurs = 0u64;
    for f in names.values() {
        match f.total {
            0 | 1 => unique += 1,
            2 => twice += 1,
            _ => recurs += 1,
        }
    }
    println!("  distinct names        {}", names.len());
    println!("  seen once             {unique}");
    println!("  seen twice            {twice}");
    println!("  seen 3+ times         {recurs}");
    println!();

    let mut files_unique = 0u64;
    let mut files_recurs = 0u64;
    let mut exe_unique = 0u64;
    let mut exe_recurs = 0u64;
    let mut exe_total = 0u64;
    for f in names.values() {
        let n = u64::from(f.total);
        if f.total <= 1 {
            files_unique += n;
            if f.executable {
                exe_unique += n;
            }
        } else if f.total >= 3 {
            files_recurs += n;
            if f.executable {
                exe_recurs += n;
            }
        }
        if f.executable {
            exe_total += n;
        }
    }
    let pct = |a: u64, b: u64| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
    println!("BENIGN RATE ON THE VOLUME  (the population the feature is computed against)");
    println!(
        "  name_unique_on_machine   +1.0   {files_unique} of {parsed} files ({:.1}%)   \
         {exe_unique} of {exe_total} executables ({:.1}%)",
        pct(files_unique, parsed),
        pct(exe_unique, exe_total)
    );
    println!(
        "  name_recurs_on_machine   -1.2   {files_recurs} of {parsed} files ({:.1}%)   \
         {exe_recurs} of {exe_total} executables ({:.1}%)",
        pct(files_recurs, parsed),
        pct(exe_recurs, exe_total)
    );

    let mut lone = 0u64;
    let mut rare = 0u64;
    for line in text.lines() {
        let Some(p) = NormalizedPath::parse(line) else { continue };
        if !p.is_executable_extension() {
            continue;
        }
        if baseline.is_lone_executable(&p, 10) {
            lone += 1;
        }
        let zone = classify(&p);
        let count = baseline.zone_rarity(zone);
        if zone != Zone::Unlocated
            && count > 0
            && count <= 5
            && !zone.is_conventional_for_executables()
        {
            rare += 1;
        }
    }
    println!(
        "  lone_executable_...      +4.1   {lone} of {exe_total} executables ({:.4}%)",
        pct(lone, exe_total)
    );
    println!(
        "  executable_rare_for_zone +2.2   {rare} of {exe_total} executables ({:.4}%)",
        pct(rare, exe_total)
    );
    println!();

    println!("WHERE RECURRING NAMES LIVE  (names seen 3+ times)");
    let mut with_conventional = 0u64;
    let mut without_conventional = 0u64;
    let mut with_winsxs = 0u64;
    let mut files_with_conventional = 0u64;
    let mut files_without_conventional = 0u64;
    let mut exe_with_conventional = 0u64;
    let mut exe_without_conventional = 0u64;
    let mut exactly_one_conventional = 0u64;
    let mut two_or_more_conventional = 0u64;
    let mut exe_exactly_one_conventional = 0u64;
    let mut offenders: Vec<(&NameFacts, u32)> = Vec::new();
    for f in names.values() {
        if f.total < 3 {
            continue;
        }
        if f.conventional == 1 {
            exactly_one_conventional += 1;
            exe_exactly_one_conventional += u64::from(f.total) * u64::from(f.executable);
        } else if f.conventional >= 2 {
            two_or_more_conventional += 1;
        }
        if f.conventional > 0 {
            with_conventional += 1;
            files_with_conventional += u64::from(f.total);
            if f.executable {
                exe_with_conventional += u64::from(f.total);
            }
        } else {
            without_conventional += 1;
            files_without_conventional += u64::from(f.total);
            if f.executable {
                exe_without_conventional += u64::from(f.total);
                offenders.push((f, f.total));
            }
        }
        if f.winsxs > 0 {
            with_winsxs += 1;
        }
    }
    println!("  names with an occurrence in a conventional zone    {with_conventional}");
    println!("    ... exactly one such occurrence                  {exactly_one_conventional}");
    println!("    ... two or more                                  {two_or_more_conventional}");
    println!("  names with NO occurrence in a conventional zone    {without_conventional}");
    println!("  names with an occurrence in WinSxS                 {with_winsxs}");
    println!();
    println!("  files covered, conventional present                {files_with_conventional}");
    println!("  files covered, no conventional occurrence          {files_without_conventional}");
    println!("  EXECUTABLES, conventional present                  {exe_with_conventional}");
    println!("  EXECUTABLES, no conventional occurrence            {exe_without_conventional}");
    println!();
    println!("  -> the shipped rule withdraws -1.2 from the last line and leaves the rest.");
    println!(
        "  -> requiring TWO conventional copies instead of one would additionally withdraw it \
         from {exe_exactly_one_conventional} executable occurrences, which is why one is the bar."
    );
    println!();

    offenders.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.example.cmp(&b.0.example)));
    println!("  the 40 most-recurring EXECUTABLE names with no conventional-zone copy:");
    for (f, n) in offenders.iter().take(40) {
        println!(
            "    {n:>5}x  {:<44} {} zone(s), {} dir(s)",
            f.example,
            f.zones.len(),
            f.dirs.len()
        );
    }
    println!();

    let mut sysdir_names = 0u64;
    let mut sysdir_recurring = 0u64;
    for f in names.values() {
        if f.system_dir > 0 && f.executable {
            sysdir_names += 1;
            if f.total >= 3 {
                sysdir_recurring += 1;
            }
        }
    }
    println!("SYSTEM-DIRECTORY EXECUTABLE NAMES  (the population -1.2 claims to describe)");
    println!("  distinct                {sysdir_names}");
    println!(
        "  of which recur 3+ times {sysdir_recurring} ({:.1}%)",
        pct(sysdir_recurring, sysdir_names)
    );
}

fn fnv(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
