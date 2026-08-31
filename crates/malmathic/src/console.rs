use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use mm_report::Report;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Console {
    pub attached_processes: Option<u32>,
    pub stdin_is_terminal: bool,
    pub stdout_is_terminal: bool,
    pub stderr_is_terminal: bool,
}

impl Console {
    pub(crate) fn detect() -> Console {
        Console {
            attached_processes: mm_env::console_process_count(),
            stdin_is_terminal: std::io::stdin().is_terminal(),
            stdout_is_terminal: std::io::stdout().is_terminal(),
            stderr_is_terminal: std::io::stderr().is_terminal(),
        }
    }
}

pub(crate) fn owns_the_window(console: Console) -> bool {
    console.attached_processes == Some(1)
        && console.stdin_is_terminal
        && console.stdout_is_terminal
        && console.stderr_is_terminal
}

pub(crate) fn should_pause(requested: Option<bool>, console: Console) -> bool {
    match requested {
        Some(explicit) => explicit,
        None => owns_the_window(console),
    }
}

pub(crate) fn should_ask(requested: Option<bool>, console: Console) -> bool {
    requested != Some(false) && owns_the_window(console)
}

pub(crate) fn ask_case_directory(suggested: Option<&Path>) -> Option<PathBuf> {
    let mut err = std::io::stderr().lock();
    let _ = match suggested {
        Some(path) => write!(
            err,
            "Case directory: {}\nPress Enter to accept it, or type another path: ",
            path.display()
        ),
        None => write!(err, "Case directory (Enter to give up): "),
    };
    let _ = err.flush();

    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    answer(&line, suggested)
}

fn answer(line: &str, suggested: Option<&Path>) -> Option<PathBuf> {
    let typed = line.trim().trim_matches('"').trim();
    if typed.is_empty() {
        suggested.map(Path::to_path_buf)
    } else {
        Some(PathBuf::from(typed))
    }
}

pub(crate) fn closing_summary(report: &Report) {
    let mut out = std::io::stderr().lock();
    let _ = write!(out, "{}", closing_summary_text(report));
    let _ = out.flush();
}

fn closing_summary_text(report: &Report) -> String {
    mm_report::text::console(report)
}

pub(crate) fn pause_if_the_window_will_close(requested: Option<bool>) {
    if !should_pause(requested, Console::detect()) {
        return;
    }
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "Press Enter to close this window. ");
    let _ = err.flush();

    let mut discard = String::new();
    let _ = std::io::stdin().lock().read_line(&mut discard);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(attached: Option<u32>) -> Console {
        Console {
            attached_processes: attached,
            stdin_is_terminal: true,
            stdout_is_terminal: true,
            stderr_is_terminal: true,
        }
    }

    #[test]
    fn a_console_we_own_alone_is_paused_for() {
        assert!(should_pause(None, owned(Some(1))));
    }

    #[test]
    fn a_console_someone_else_is_attached_to_is_not() {
        assert!(!should_pause(None, owned(Some(2))));
        assert!(!should_pause(None, owned(Some(7))));
    }

    #[test]
    fn an_unknown_console_is_never_paused_for() {
        assert!(!should_pause(None, owned(None)));
    }

    #[test]
    fn a_redirected_run_is_never_paused_for() {
        for redirect in [
            Console { stdout_is_terminal: false, ..owned(Some(1)) },
            Console { stderr_is_terminal: false, ..owned(Some(1)) },
            Console { stdin_is_terminal: false, ..owned(Some(1)) },
        ] {
            assert!(!should_pause(None, redirect), "{redirect:?}");
        }
    }

    #[test]
    fn an_empty_answer_accepts_the_suggestion() {
        let suggested = Path::new(r"D:\cases\C-20260830-164205");
        for line in ["", "\n", "\r\n", "   \r\n", "\"\"\n"] {
            assert_eq!(answer(line, Some(suggested)).as_deref(), Some(suggested), "{line:?}");
        }
    }

    #[test]
    fn with_nothing_to_offer_an_empty_answer_gives_up() {
        assert_eq!(answer("\r\n", None), None);
        assert_eq!(answer(r"E:\cases\x", None), Some(PathBuf::from(r"E:\cases\x")));
    }

    #[test]
    fn a_typed_path_replaces_it_with_the_quotes_explorer_pastes_stripped() {
        let suggested = Some(Path::new(r"D:\cases\C-20260830-164205"));
        assert_eq!(
            answer("E:\\evidence\\pc7\r\n", suggested),
            Some(PathBuf::from(r"E:\evidence\pc7"))
        );
        assert_eq!(
            answer("\"E:\\my cases\\pc 7\"\n", suggested),
            Some(PathBuf::from(r"E:\my cases\pc 7"))
        );
        assert_eq!(answer("  cases\\x  ", suggested), Some(PathBuf::from(r"cases\x")));
    }

    #[test]
    fn no_pause_also_silences_the_case_directory_question() {
        assert!(should_ask(None, owned(Some(1))));
        assert!(!should_ask(Some(false), owned(Some(1))));
        assert!(!should_ask(Some(true), owned(Some(2))));
        assert!(!should_ask(None, Console { stdin_is_terminal: false, ..owned(Some(1)) }));
    }

    #[test]
    fn the_prompt_and_the_pause_share_one_notion_of_owning_the_window() {
        assert!(owns_the_window(owned(Some(1))));
        assert!(!owns_the_window(owned(Some(2))));
        assert!(!owns_the_window(Console { stdin_is_terminal: false, ..owned(Some(1)) }));
        assert_eq!(owns_the_window(owned(Some(1))), should_pause(None, owned(Some(1))));
    }

    #[test]
    fn the_command_line_overrides_the_detection() {
        assert!(should_pause(Some(true), owned(Some(9))));
        assert!(should_pause(Some(true), owned(None)));
        assert!(should_pause(Some(true), Console { stdout_is_terminal: false, ..owned(Some(1)) }));
        assert!(!should_pause(Some(false), owned(Some(1))));
    }

    fn empty_report() -> mm_report::Report {
        mm_report::Report::new(
            "0.1.0",
            "live Windows",
            mm_report::Target {
                display_name: "C:".into(),
                device_path: "\\\\?\\Volume{a}".into(),
                volume_serial: "0".into(),
            },
            Vec::new(),
            mm_report::Coverage::default(),
            false,
        )
    }

    #[test]
    fn the_closing_verdict_is_the_report_s_own_verdict() {
        let report = empty_report();
        let summary = closing_summary_text(&report);
        let rendered = mm_report::text::render(&report);
        for line in mm_report::text::headline(&report).lines() {
            assert!(summary.contains(line), "the summary does not carry {line:?}:\n{summary}");
            assert!(
                rendered.contains(line),
                "the summary would say {line:?}, which the report does not:\n{rendered}"
            );
        }
    }

    #[test]
    fn the_summary_says_where_the_report_is_and_what_the_run_cost() {
        let mut report = empty_report();
        report.set_case_directory(r"C:\cases\mal\malmathic-case");
        report.set_wall_clock(54.9);

        let summary = closing_summary_text(&report);
        assert!(summary.contains(r"C:\cases\mal\malmathic-case"), "{summary}");
        assert!(summary.contains("report.txt"), "{summary}");
        assert!(summary.contains("report.json"), "{summary}");
        assert!(summary.contains("Ran in "), "{summary}");

        let lines = summary.lines().count();
        assert!(lines <= 20, "the closing block is {lines} lines:\n{summary}");
    }

    #[test]
    fn nothing_of_a_fixed_length_wraps_on_an_80_column_console() {
        let mut report = empty_report();
        let long = format!(r"C:\{}\case", "d".repeat(200));
        report.set_case_directory(long.clone());
        report.set_wall_clock(1234.5);

        for line in closing_summary_text(&report).lines() {
            if line.contains(&long) {
                continue;
            }
            assert!(
                line.chars().count() <= 78,
                "the closing summary wraps on an 80-column console: {line:?}"
            );
        }
    }

    #[test]
    fn a_run_that_recorded_neither_fact_invents_neither() {
        let summary = closing_summary_text(&empty_report());
        assert!(!summary.contains("Report:"), "{summary}");
        assert!(!summary.contains("Took:"), "{summary}");
    }
}
