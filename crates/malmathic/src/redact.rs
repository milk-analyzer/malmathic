use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mm_report::redact::{redact, Options};
use mm_report::Report;

use crate::casedir::{guard_file, Location};

pub fn run(report: &Path, out: Option<&Path>, overwrite: bool, keep_urls: bool) -> ExitCode {
    let text = match std::fs::read_to_string(report) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("could not read {}: {e}", report.display());
            return ExitCode::from(2);
        }
    };
    let parsed = match Report::from_json(&text) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{} is not a malmathic report.json: {e}", report.display());
            return ExitCode::from(2);
        }
    };
    let (redacted, done) = match redact(&parsed, Options { keep_urls }) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("could not redact {}: {e}", report.display());
            return ExitCode::FAILURE;
        }
    };

    let json_path = out.map(Path::to_path_buf).unwrap_or_else(|| beside(report));
    let text_path = json_path.with_extension("txt");
    let location = Location::detect();
    let mut targets = Vec::new();
    for path in [json_path, text_path] {
        match guard_file(&path, &location, "redacted report", overwrite) {
            Ok(path) => targets.push(path),
            Err(refusal) => {
                eprintln!("\n{refusal}");
                return ExitCode::from(2);
            }
        }
    }
    let contents = [redacted.to_json(), mm_report::text::render(&redacted)];
    for (path, contents) in targets.iter().zip(contents) {
        if let Err(e) = std::fs::write(path, contents) {
            eprintln!("could not write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    }

    eprintln!("Redacted {}:\n{}", report.display(), done.describe());
    for path in &targets {
        eprintln!("wrote {}", path.display());
    }
    eprintln!(
        "Read the .txt before sharing it: the pseudonyms are consistent, the judgement is yours."
    );
    ExitCode::SUCCESS
}

fn beside(report: &Path) -> PathBuf {
    let stem = report.file_stem().and_then(|s| s.to_str()).unwrap_or("report");
    report.with_file_name(format!("{stem}.redacted.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_output_sits_beside_the_input_with_a_redacted_stem() {
        assert_eq!(
            beside(Path::new(r"E:\case\report.json")),
            PathBuf::from(r"E:\case\report.redacted.json")
        );
        assert_eq!(beside(Path::new("report.json")), PathBuf::from("report.redacted.json"));
        assert_eq!(
            beside(Path::new(r"E:\case\report.redacted.json")).with_extension("txt"),
            PathBuf::from(r"E:\case\report.redacted.redacted.txt")
        );
    }

    #[test]
    fn a_file_that_is_not_a_report_is_refused_in_words() {
        let dir = std::env::temp_dir().join(format!("malmathic-redact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let not_json = dir.join("report.json");
        std::fs::write(&not_json, b"not json").expect("a scratch file");
        assert_eq!(run(&not_json, None, false, false), ExitCode::from(2));
        assert_eq!(run(&dir.join("missing.json"), None, false, false), ExitCode::from(2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
