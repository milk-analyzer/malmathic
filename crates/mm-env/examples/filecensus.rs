use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

fn main() {
    let mut roots: Vec<String> = Vec::new();
    let mut out: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = args.next(),
            _ => roots.push(arg),
        }
    }
    if roots.is_empty() {
        roots.push("C:\\".to_string());
    }

    let mut sink: Box<dyn Write> = match &out {
        Some(path) => match File::create(path) {
            Ok(file) => Box::new(BufWriter::with_capacity(1 << 20, file)),
            Err(err) => {
                eprintln!("could not create {path}: {err}");
                std::process::exit(2);
            }
        },
        None => Box::new(BufWriter::with_capacity(1 << 20, std::io::stdout())),
    };

    let started = std::time::Instant::now();
    let mut files = 0u64;
    let mut directories = 0u64;
    let mut refused = 0u64;
    let mut reparse = 0u64;

    for root in &roots {
        let mut stack = vec![PathBuf::from(root)];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => {
                    refused += 1;
                    continue;
                }
            };
            directories += 1;
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata_no_follow() else {
                    refused += 1;
                    continue;
                };
                let path = entry.path();
                if meta.is_symlink() {
                    reparse += 1;
                    continue;
                }
                if meta.is_dir() {
                    stack.push(path);
                } else {
                    files += 1;
                    write_path(&mut sink, &path);
                }
            }
        }
    }

    let _ = sink.flush();
    eprintln!("roots                {}", roots.join(", "));
    eprintln!("files                {files}");
    eprintln!("directories          {directories}");
    eprintln!("reparse points       {reparse}   (not followed)");
    eprintln!("could not be opened  {refused}");
    eprintln!("elapsed              {:.1}s", started.elapsed().as_secs_f64());
}

fn write_path(sink: &mut Box<dyn Write>, path: &Path) {
    let text = path.to_string_lossy();
    let _ = sink.write_all(text.as_bytes());
    let _ = sink.write_all(b"\n");
}

trait NoFollow {
    fn metadata_no_follow(&self) -> std::io::Result<std::fs::Metadata>;
}

impl NoFollow for std::fs::DirEntry {
    fn metadata_no_follow(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::symlink_metadata(self.path())
    }
}
