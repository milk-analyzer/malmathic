use std::fs;
use std::os::windows::fs::MetadataExt;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;

#[derive(Default)]
struct Census {
    entries: u64,
    files: u64,
    directories: u64,
    reparse_files: u64,
    reparse_directories: u64,
    denied: u64,
}

fn walk(dir: &std::path::Path, census: &mut Census, depth: usize) {
    const MAX_DEPTH: usize = 128;
    if depth >= MAX_DEPTH {
        return;
    }
    let iter = match fs::read_dir(dir) {
        Ok(iter) => iter,
        Err(_) => {
            census.denied += 1;
            return;
        }
    };
    for entry in iter {
        let Ok(entry) = entry else { continue };
        let Ok(meta) = entry.path().symlink_metadata() else {
            census.denied += 1;
            continue;
        };
        let attrs = meta.file_attributes();
        let is_dir = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
        let is_reparse = attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        census.entries += 1;
        if is_dir {
            census.directories += 1;
            if is_reparse {
                census.reparse_directories += 1;
                continue;
            }
            walk(&entry.path(), census, depth + 1);
        } else {
            census.files += 1;
            if is_reparse {
                census.reparse_files += 1;
            }
        }
        if census.entries.is_multiple_of(200_000) {
            eprintln!("  {} entries...", census.entries);
        }
    }
}

fn main() {
    let root = std::env::args().nth(1).unwrap_or_else(|| r"C:\".to_string());
    let start = std::time::Instant::now();
    let mut census = Census::default();
    walk(std::path::Path::new(&root), &mut census, 0);
    println!("root                       {root}");
    println!("entries seen               {}", census.entries);
    println!("  files                    {}", census.files);
    println!("  directories              {}", census.directories);
    println!("reparse-point files        {}", census.reparse_files);
    println!("reparse-point directories  {}", census.reparse_directories);
    println!("unreadable places          {}", census.denied);
    println!("elapsed                    {:.1} s", start.elapsed().as_secs_f64());
}
