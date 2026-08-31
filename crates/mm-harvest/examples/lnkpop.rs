use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mm_harvest::startup::{self, Entry, Location};

fn main() {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut truth_file: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--truth" {
            truth_file = args.next().map(PathBuf::from);
        } else {
            dirs.push(PathBuf::from(arg));
        }
    }
    if dirs.is_empty() {
        eprintln!("usage: lnkpop <dir> [<dir>...] [--truth truth.tsv]");
        std::process::exit(2);
    }

    let truth: HashMap<String, String> = truth_file
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|text| {
            text.lines()
                .filter_map(|line| line.split_once('\t'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut links = Vec::new();
    for dir in &dirs {
        collect(dir, 0, &mut links);
    }
    links.sort();

    let mut resolved = 0usize;
    let mut unreadable = 0usize;
    let mut with_arguments = 0usize;
    let mut by_origin: HashMap<&'static str, usize> = HashMap::new();
    let mut agree = 0usize;
    let mut disagree = 0usize;
    let mut checked = 0usize;

    for file in &links {
        let bytes = match std::fs::read(file) {
            Ok(b) => b,
            Err(e) => {
                println!("UNREADABLE FILE  {}  {e}", file.display());
                continue;
            }
        };
        let at = Location {
            directory: strip_drive(file.parent().unwrap_or(Path::new("\\"))),
            name: file.file_name().unwrap_or_default().to_string_lossy().to_string(),
            profile: profile_of(file),
        };
        match startup::harvest(&at, &bytes) {
            Entry::Link { target, arguments, origin, .. } => {
                resolved += 1;
                *by_origin.entry(origin.label()).or_default() += 1;
                if arguments.is_some() {
                    with_arguments += 1;
                }
                let key = file.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
                if let Some(expected) = truth.get(&key) {
                    if !expected.is_empty() {
                        checked += 1;
                        let ours = target.key().to_string();
                        let theirs = strip_drive(Path::new(expected)).to_ascii_lowercase();
                        if ours == theirs {
                            agree += 1;
                        } else {
                            disagree += 1;
                            println!(
                                "DISAGREE  {}\n    ours   {ours}\n    shell  {theirs}",
                                file.display()
                            );
                        }
                    }
                }
                println!(
                    "{:<9} {}\n          -> {}{}",
                    origin.label(),
                    file.display(),
                    target.key(),
                    arguments.map(|a| format!("   args: {a}")).unwrap_or_default()
                );
            }
            Entry::UnreadableLink { reason } => {
                unreadable += 1;
                println!("UNKNOWN   {}  ({reason})", file.display());
            }
            Entry::File { path, .. } => println!("FILE      {}", path.key()),
            Entry::Ignored => {}
        }
    }

    println!();
    println!("links seen        {}", links.len());
    println!("resolved          {resolved}");
    println!("UNKNOWN           {unreadable}");
    println!("with arguments    {with_arguments}");
    for (origin, n) in by_origin {
        println!("  via {origin:<22} {n}");
    }
    if checked > 0 {
        println!("checked vs shell  {checked}   agree {agree}   DISAGREE {disagree}");
    }
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, depth + 1, out);
        } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk")) {
            out.push(path);
        }
    }
}

fn strip_drive(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    if s.len() >= 2 && s.as_bytes()[1] == b':' {
        s[2..].to_string()
    } else {
        s
    }
}

fn profile_of(file: &Path) -> Option<String> {
    let s = strip_drive(file);
    let lower = s.to_ascii_lowercase();
    let rest = lower.strip_prefix("\\users\\")?;
    let end = rest.find('\\')?;
    Some(format!("\\Users\\{}", &s[7..7 + end]))
}
