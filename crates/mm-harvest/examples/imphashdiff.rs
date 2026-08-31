use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let root = args.next().unwrap_or_else(|| "C:\\Windows\\System32".to_string());
    let limit: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(400);

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect(Path::new(&root), &mut files, limit);
    files.sort();

    for path in files {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let imports = mm_harvest::imphash::import_strings(&bytes).unwrap_or_default();
        let imphash = mm_harvest::imphash::imphash(&bytes).unwrap_or_default();
        let rich = mm_harvest::imphash::rich_header(&bytes);
        let rich_hash = rich.as_ref().map(|r| r.hash.as_str()).unwrap_or("");
        let valid = rich.as_ref().map(|r| r.checksum_valid).unwrap_or(false);
        let links = rich.as_ref().map(|r| r.entries.len()).unwrap_or(0);
        println!(
            "{}\t{imphash}\t{rich_hash}\t{valid}\t{}\t{links}\t{}",
            path.display(),
            imports.len(),
            bytes.len()
        );
    }
}

fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>, limit: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut directories = Vec::new();
    for entry in entries.flatten() {
        if out.len() >= limit {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            directories.push(path);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "exe" | "dll" | "sys"))
        {
            out.push(path);
        }
    }
    for dir in directories {
        if out.len() >= limit {
            return;
        }
        collect(&dir, out, limit);
    }
}
