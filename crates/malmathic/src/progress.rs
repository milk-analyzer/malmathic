use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

const REDRAW: Duration = Duration::from_millis(500);

const PLAIN_STEP_PERCENT: u64 = 10;

const PLAIN_HEARTBEAT: Duration = Duration::from_secs(30);

const LINE: usize = 76;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Console,
    Plain,
    Silent,
}

impl Style {
    pub fn detect() -> Style {
        if std::io::stderr().is_terminal() {
            Style::Console
        } else {
            Style::Plain
        }
    }
}

pub struct Stage {
    label: String,
    style: Style,
    started: Instant,
    last_emit: Instant,
    last_step: u64,
    open: bool,
    excluded: f64,
}

impl Stage {
    pub fn begin(label: impl Into<String>, style: Style) -> Stage {
        let label = label.into();
        let now = Instant::now();
        let mut stage = Stage {
            label,
            style,
            started: now,
            last_emit: now,
            last_step: 0,
            open: false,
            excluded: 0.0,
        };
        if stage.style == Style::Console {
            let line = format!("  {:<26} ...", stage.label);
            stage.write(&line, false);
            stage.open = true;
        }
        stage
    }

    pub fn exclude(&mut self, seconds: f64) {
        self.excluded += seconds;
    }

    pub fn tick(&mut self, done: u64, total: u64) {
        if self.style == Style::Silent {
            return;
        }
        let now = Instant::now();
        match self.style {
            Style::Console => {
                if now.duration_since(self.last_emit) < REDRAW {
                    return;
                }
                self.last_emit = now;
                let line = progress_line(&self.label, done, total, now - self.started);
                self.write(&line, false);
                self.open = true;
            }
            Style::Plain => {
                let step = (done * 100).checked_div(total).unwrap_or(0) / PLAIN_STEP_PERCENT;
                if step <= self.last_step && now.duration_since(self.last_emit) < PLAIN_HEARTBEAT {
                    return;
                }
                self.last_step = step;
                self.last_emit = now;
                let line = progress_line(&self.label, done, total, now - self.started);
                self.write(&line, true);
            }
            Style::Silent => {}
        }
    }

    #[must_use]
    pub fn finish_as(mut self, label: &str, detail: &str) -> f64 {
        let seconds = (self.started.elapsed().as_secs_f64() - self.excluded).max(0.0);
        if self.style != Style::Silent {
            let line = format!(
                "  {:<26} {:<32}{:>8}",
                label,
                detail,
                mm_report::text::format_seconds(seconds)
            );
            let trimmed = line.trim_end().to_string();
            self.write(&trimmed, true);
            self.open = false;
        }
        seconds
    }

    fn write(&mut self, text: &str, newline: bool) {
        let mut err = std::io::stderr().lock();
        let _ = if self.style == Style::Console {
            write!(err, "\r{text:<LINE$}")
        } else {
            write!(err, "{text}")
        };
        if newline {
            let _ = writeln!(err);
        }
        let _ = err.flush();
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if self.open {
            let _ = writeln!(std::io::stderr());
        }
    }
}

fn progress_line(label: &str, done: u64, total: u64, elapsed: Duration) -> String {
    let clock = clock(elapsed);
    if let Some(percent) = (done.min(total) * 100).checked_div(total) {
        format!("  {label:<26} {percent:>3}%  {}/{}  {clock}", thousands(done), thousands(total))
    } else {
        format!("  {label:<26} {}  {clock}", thousands(done))
    }
}

fn clock(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silent_stage_still_measures_time() {
        let stage = Stage::begin("$MFT", Style::Silent);
        let seconds = stage.finish_as("$MFT", "1 observation");
        assert!((0.0..5.0).contains(&seconds), "{seconds}");
    }

    #[test]
    fn the_progress_line_says_where_the_walk_is() {
        let line = progress_line("$MFT", 673_689, 1_684_224, Duration::from_secs(67));
        assert!(line.contains("39%"), "{line}");
        assert!(line.contains("673,689/1,684,224"), "{line}");
        assert!(line.contains("1:07"), "{line}");
    }

    #[test]
    fn a_stage_with_no_total_reports_a_count_and_a_clock() {
        let line = progress_line("catalogs", 4_719, 0, Duration::from_secs(9));
        assert!(line.contains("4,719"), "{line}");
        assert!(line.contains("0:09"), "{line}");
        assert!(!line.contains('%'), "{line}");
    }

    #[test]
    fn no_progress_output_contains_an_escape_sequence() {
        let line = progress_line("$MFT", 1, 2, Duration::from_secs(1));
        assert!(!line.contains('\x1b'), "ANSI in {line:?}");
        assert!(!line.contains('\r'), "the redraw belongs to the writer, not the line");
    }

    #[test]
    fn ticking_ten_million_times_is_free() {
        let mut stage = Stage::begin("$MFT", Style::Silent);
        let started = Instant::now();
        for i in 0..10_000_000u64 {
            stage.tick(i, 10_000_000);
        }
        let elapsed = started.elapsed();
        let _ = stage.finish_as("$MFT", "done");
        assert!(elapsed < Duration::from_secs(2), "ten million ticks took {elapsed:?}");
    }

    #[test]
    fn a_console_stage_rate_limits_before_it_formats() {
        let mut stage = Stage::begin("$MFT", Style::Silent);
        stage.style = Style::Console;
        stage.last_emit = Instant::now();
        let started = Instant::now();
        for i in 0..200_000u64 {
            stage.tick(i, 200_000);
        }
        let elapsed = started.elapsed();
        stage.style = Style::Silent;
        stage.open = false;
        let _ = stage.finish_as("$MFT", "done");
        assert!(elapsed < Duration::from_millis(400), "200k refused ticks took {elapsed:?}");
    }

    #[test]
    fn progress_past_the_end_is_clamped() {
        let line = progress_line("$MFT", 500, 400, Duration::from_secs(1));
        assert!(line.contains("100%"), "{line}");
    }

    #[test]
    fn the_clock_rolls_over_into_minutes() {
        assert_eq!(clock(Duration::from_secs(0)), "0:00");
        assert_eq!(clock(Duration::from_secs(59)), "0:59");
        assert_eq!(clock(Duration::from_secs(60)), "1:00");
        assert_eq!(clock(Duration::from_secs(3_601)), "60:01");
    }

    #[test]
    fn thousands_separates_every_three_digits() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_684_224), "1,684,224");
    }

    #[test]
    fn the_console_line_is_padded_so_a_redraw_erases() {
        let padded = format!("{:<LINE$}", progress_line("$MFT", 1, 10, Duration::ZERO));
        assert_eq!(padded.chars().count(), LINE);
    }

    #[test]
    fn a_nested_stage_is_not_counted_twice() {
        let mut outer = Stage::begin("code signatures", Style::Silent);
        std::thread::sleep(Duration::from_millis(30));
        outer.exclude(1_000.0);
        assert_eq!(outer.finish_as("code signatures", "done"), 0.0);
    }

    #[test]
    fn a_redirected_run_never_redraws_in_place() {
        let mut stage = Stage::begin("$MFT", Style::Plain);
        assert!(!stage.open, "a redirected stage leaves no open line");
        stage.style = Style::Silent;
        let _ = stage.finish_as("$MFT", "done");
    }
}
