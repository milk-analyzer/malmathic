use std::fmt::Write;
use std::process::ExitCode;

use mm_score::weights::FeatureWeight;
use mm_score::Weights;

const WIDTH: usize = 78;

const MOST_SUGGESTIONS: usize = 8;

pub fn run(features: &[String]) -> ExitCode {
    let weights = Weights::embedded();
    let (text, ok) = render(&weights, features);
    print!("{text}");
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub fn render(weights: &Weights, features: &[String]) -> (String, bool) {
    let mut out = String::with_capacity(4096);
    if features.is_empty() {
        index(weights, &mut out);
        return (out, true);
    }

    let mut ok = true;
    for (i, name) in features.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        match weights.get(name) {
            Some(weight) => one(name, weight, weights, &mut out),
            None => {
                ok = false;
                not_found(name, weights, &mut out);
            }
        }
    }
    (out, ok)
}

fn index(weights: &Weights, out: &mut String) {
    let mut rows: Vec<(&str, &FeatureWeight)> = weights.all().collect();
    rows.sort_by(|a, b| {
        b.1.log_lr.partial_cmp(&a.1.log_lr).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(b.0))
    });

    let _ = writeln!(
        out,
        "malmathic weight table v{} \u{b7} {} features \u{b7} {}",
        weights.version(),
        rows.len(),
        if weights.is_calibrated() {
            "fitted to a labelled corpus"
        } else {
            "NOT calibrated: expert estimates"
        }
    );
    out.push('\n');
    for line in wrap(
        "Every feature id printed beside an evidence row in a report is one of these. \
         `malmathic explain <id>` prints that row whole: what it means, why the number is \
         that number, and how often it fires on machines known to be clean. A weight is \
         ln(P(feature | malicious) / P(feature | benign)), added to the candidate's \
         log-odds; only the strongest feature in a group counts, so the group column is \
         what a row competes against.",
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    let _ = writeln!(out, "  log LR  group                 feature");
    for (name, weight) in rows {
        let _ = writeln!(out, "  {:+6.1}  {:<20}  {}", weight.log_lr, weight.group, name);
    }
    out.push('\n');
    let _ = writeln!(out, "The table itself is crates/mm-score/rules/weights.toml.");
}

fn one(name: &str, weight: &FeatureWeight, weights: &Weights, out: &mut String) {
    let bar = "\u{2500}".repeat(WIDTH);
    let _ = writeln!(out, "{bar}");
    let _ = writeln!(out, "{name}   {:+.1}   group `{}`", weight.log_lr, weight.group);
    let _ = writeln!(out, "{bar}");
    out.push('\n');

    section("what it means", weight.rationale.trim(), out);
    section("how often it fires on a machine known to be clean", weight.benign_rate.trim(), out);
    if let Some(why) = &weight.convicts_alone {
        section("why this may convict a file on its own", why.trim(), out);
    }

    let strongest = weights.max_log_lr_in_group(&weight.group);
    let mut arithmetic = format!(
        "{:+.1} is added to the candidate's log-odds when this fires. It is \
         ln(P(feature | malicious) / P(feature | benign)), so {:+.1} says the author judged \
         this feature about {:.1} times as likely on a malicious file as on a benign one.",
        weight.log_lr,
        weight.log_lr,
        weight.log_lr.exp()
    );
    if strongest > weight.log_lr {
        let _ = write!(
            arithmetic,
            " Only the strongest feature in group `{}` counts, and the strongest row in that \
             group is {:+.1}, so this one is superseded whenever they fire together \u{2014} its \
             explanation is kept and its score is dropped.",
            weight.group, strongest
        );
    }
    if !weights.is_calibrated() {
        arithmetic.push_str(
            " The weights are NOT fitted to a labelled corpus. The rationale above is the \
             part worth arguing with.",
        );
    }
    section("what the number does", &arithmetic, out);
}

fn section(heading: &str, body: &str, out: &mut String) {
    let _ = writeln!(out, "  {heading}");
    for paragraph in body.split("\n\n") {
        if paragraph.trim().is_empty() {
            continue;
        }
        for line in wrap(paragraph, WIDTH - 4) {
            let _ = writeln!(out, "    {line}");
        }
        out.push('\n');
    }
}

fn not_found(name: &str, weights: &Weights, out: &mut String) {
    let _ = writeln!(out, "There is no feature named `{name}` in the weight table.");
    let needle = name.to_lowercase();
    let mut near: Vec<&str> = weights
        .feature_names()
        .filter(|f| f.contains(&needle) || needle.contains(*f) || shares_a_word(f, &needle))
        .collect();
    near.sort_unstable();
    if near.is_empty() {
        let _ = writeln!(out, "Run `malmathic explain` with no argument for the whole table.");
        return;
    }
    let _ = writeln!(out, "\nDid you mean:");
    for f in near.iter().take(MOST_SUGGESTIONS) {
        let _ = writeln!(out, "  {f}");
    }
    if near.len() > MOST_SUGGESTIONS {
        let _ = writeln!(out, "  ...and {} more", near.len() - MOST_SUGGESTIONS);
    }
}

fn shares_a_word(feature: &str, needle: &str) -> bool {
    needle.split('_').filter(|w| w.len() >= 4).any(|w| feature.split('_').any(|part| part == w))
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_feature_prints_its_rationale_and_its_benign_rate() {
        let weights = Weights::embedded();
        let (text, ok) = render(&weights, &["persistence_run_key".to_string()]);
        assert!(ok);
        let row = weights.get("persistence_run_key").expect("the table has this row");

        for word in row.rationale.split_whitespace().take(6) {
            assert!(text.contains(word), "the rationale did not reach the output: {text}");
        }
        assert!(text.contains("how often it fires on a machine known to be clean"), "{text}");
        for word in row.benign_rate.split_whitespace().take(4) {
            assert!(text.contains(word), "the benign rate did not reach the output: {text}");
        }
        assert!(text.contains("+3.2"), "{text}");
    }

    #[test]
    fn every_row_in_the_table_renders_both_of_its_required_fields() {
        let weights = Weights::embedded();
        for (name, weight) in weights.all() {
            let (text, ok) = render(&weights, &[name.to_string()]);
            assert!(ok, "{name} is in the table but explain refused it");
            let first_rationale =
                weight.rationale.split_whitespace().next().expect("rationale is required");
            let first_rate =
                weight.benign_rate.split_whitespace().next().expect("benign_rate is required");
            assert!(text.contains(first_rationale), "{name}: no rationale in the output");
            assert!(text.contains(first_rate), "{name}: no benign rate in the output");
            if let Some(alone) = &weight.convicts_alone {
                let first = alone.split_whitespace().next().expect("non-empty when present");
                assert!(text.contains(first), "{name}: convicts_alone did not render");
            }
        }
    }

    #[test]
    fn the_index_lists_every_feature_and_fits_the_console_buffer() {
        let weights = Weights::embedded();
        let (text, ok) = render(&weights, &[]);
        assert!(ok);
        let count = weights.all().count();
        for (name, _) in weights.all() {
            assert!(text.contains(name), "{name} is missing from the index");
        }
        let lines = text.lines().count();
        assert!(
            lines < 300,
            "the index is {lines} lines over {count} features, past the 300-line console \
             buffer this report is written for"
        );
        assert!(text.lines().all(|l| l.chars().count() <= 80), "the index ran past 80 columns");
    }

    #[test]
    fn the_index_is_sorted_by_weight() {
        let weights = Weights::embedded();
        let (text, _) = render(&weights, &[]);
        let mut previous = f64::INFINITY;
        let mut seen = 0;
        for line in text.lines().skip_while(|l| !l.contains("log LR")).skip(1) {
            let Some(first) = line.split_whitespace().next() else { continue };
            let Ok(value) = first.parse::<f64>() else { continue };
            assert!(value <= previous, "{line} is out of order after {previous}");
            previous = value;
            seen += 1;
        }
        assert_eq!(seen, weights.all().count(), "the index lost rows");
    }

    #[test]
    fn an_unknown_feature_is_refused_and_suggests_the_rows_it_might_have_been() {
        let weights = Weights::embedded();
        let (text, ok) = render(&weights, &["persistence_run".to_string()]);
        assert!(!ok, "an unknown id must not report success");
        assert!(text.contains("no feature named"), "{text}");
        assert!(text.contains("persistence_run_key"), "{text}");
    }

    #[test]
    fn more_than_one_feature_can_be_explained_in_one_run() {
        let weights = Weights::embedded();
        let (text, ok) = render(
            &weights,
            &["persistence_run_key".to_string(), "name_unique_on_machine".to_string()],
        );
        assert!(ok);
        assert!(text.contains("persistence_run_key"), "{text}");
        assert!(text.contains("name_unique_on_machine"), "{text}");
    }
}
