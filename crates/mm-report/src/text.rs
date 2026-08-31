use std::fmt::Write;

use mm_core::{Acquisition, Candidate, ObservationKind, Recovery};

use crate::{
    break_even_population, evidence_log_odds, BreakEven, CloseCall, Coverage, CoverageStatus,
    Report,
};

const WIDTH: usize = 78;

pub fn render(report: &Report) -> String {
    let mut out = String::with_capacity(4096);

    let _ = writeln!(out, "malmathic {} · {}", report.tool_version, report.environment);
    let _ = writeln!(
        out,
        "Target: {}  serial {}",
        report.target.display_name, report.target.volume_serial
    );
    let _ = writeln!(out, "        {}", report.target.device_path);

    if let Some(dir) = &report.case_directory {
        let _ = writeln!(out, "Case:   {dir}");
    }
    out.push('\n');

    render_mass_encryption(report, &mut out);

    if report.found_anything() {
        render_findings(report, &mut out);
    } else {
        render_nothing_found(report, &mut out);
    }

    render_arrival_timeline(report, &mut out);

    render_other_volumes(&report.coverage, &mut out);
    render_coverage(&report.coverage, report.wall_clock_seconds, &mut out);
    render_trust(report, &mut out);

    defang(out)
}

fn defang(text: String) -> String {
    const BIDI: &[char] = &[
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}', '\u{200E}', '\u{200F}',
    ];

    if text.chars().all(|c| (!c.is_control() || c == '\n' || c == '\t') && !BIDI.contains(&c)) {
        return text;
    }
    text.chars()
        .map(|c| {
            if c == '\n' || c == '\t' {
                c
            } else if c.is_control() || BIDI.contains(&c) {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

fn rule(title: &str, out: &mut String) {
    out.push_str(&"─".repeat(WIDTH));
    out.push('\n');
    let _ = writeln!(out, "{title}");
    out.push_str(&"─".repeat(WIDTH));
    out.push_str("\n\n");
}

pub fn headline(report: &Report) -> String {
    if report.found_anything() {
        return findings_heading(report);
    }
    if !report.prior_established() {
        return NO_BASE_RATE_HEADING.to_string();
    }
    negative_heading(report.close_call().as_ref(), report.coverage.failed_stages().is_empty())
}

const NO_BASE_RATE_HEADING: &str =
    "NO RESULT — THIS RUN COULD NOT ESTABLISH THE SIZE OF THIS VOLUME";

fn findings_heading(report: &Report) -> String {
    let n = report.reportable_count();
    format!(
        "FINDINGS — {n} candidate{} above {:.2}",
        if n == 1 { "" } else { "s" },
        report.threshold
    )
}

fn render_findings(report: &Report, out: &mut String) {
    rule(&findings_heading(report), out);
    let n = report.reportable_count();

    render_could_not_look(&report.coverage.failed_stages(), out);

    for (rank, candidate) in report.reportable().enumerate() {
        render_candidate(rank + 1, candidate, report, report.case_directory.as_deref(), out);
    }

    let below = report.candidates.len().saturating_sub(n);
    if below > 0 {
        let _ = writeln!(
            out,
            "{below} further candidate{}.",
            if below == 1 {
                " scored below the threshold and is not listed".to_string()
            } else {
                "s scored below the threshold and are not listed".to_string()
            }
        );
        if let Some(next) = report.candidates.get(n) {
            let _ = writeln!(out, "The strongest of them scored {:.2}.", next.probability());
        }
        let findings: Vec<&Candidate> = report.reportable().collect();
        let twins: Vec<&Candidate> = report
            .candidates
            .iter()
            .filter(|c| c.probability() < report.threshold && !c.hash.is_empty())
            .filter(|c| findings.iter().any(|f| f.hash.same_file_as(&c.hash) == Some(true)))
            .collect();
        if !twins.is_empty() {
            out.push('\n');
            let names: Vec<String> = twins.iter().map(|c| c.label()).collect();
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            indented(
                &format!(
                    "{} of them is not merely low-scoring: {} carries the same digest, and \
                     therefore the same bytes, as a finding above. That is one file at two \
                     paths, and it is named in that finding's own block. Its score is what \
                     the evidence AT THAT PATH came to and is printed unchanged — an \
                     identity is not evidence and moved nothing.",
                    if twins.len() == 1 { "One".to_string() } else { twins.len().to_string() },
                    join_with_and(&refs),
                ),
                out,
            );
            out.push('\n');
        }
        let _ = writeln!(out, "Re-run with --json to get every candidate.\n");
    }
}

fn render_candidate(
    rank: usize,
    candidate: &Candidate,
    report: &Report,
    case_directory: Option<&str>,
    out: &mut String,
) {
    let _ = writeln!(out, "[{rank}]  p = {:.2}   {}", candidate.probability(), candidate.label());

    let families = candidate.corroboration();
    let _ = writeln!(
        out,
        "     {} · corroborated by {families} independent artifact famil{}",
        candidate.id,
        if families == 1 { "y" } else { "ies" }
    );

    if families <= 1 {
        let _ = writeln!(
            out,
            "     ! rests on a single artifact family — treat as a lead, not a conclusion"
        );
    }
    out.push('\n');

    render_mft_record(candidate, out);
    render_sample(candidate, case_directory, out);
    render_same_bytes(candidate, report, out);
    render_origin(candidate, out);
    render_deleted_registry_values(candidate, out);
    render_reasoning(candidate, out);

    let sentence = match break_even_population(evidence_log_odds(candidate), report.threshold) {
        BreakEven::AtMost(n) => Some(format!(
            "this much evidence reaches {:.2} on a volume of up to {} candidates; \
             this one holds {}",
            report.threshold,
            thousands(n),
            thousands(report.population())
        )),
        BreakEven::Always => Some(format!(
            "this much evidence reaches {:.2} on a volume of any size",
            report.threshold
        )),
        BreakEven::Never => None,
    };
    if let Some(sentence) = sentence {
        for (i, line) in wrap(&sentence, WIDTH - 7).into_iter().enumerate() {
            let _ = writeln!(out, "     {}{line}", if i == 0 { "→ " } else { "  " });
        }
    }
    out.push('\n');
}

fn render_same_bytes(candidate: &Candidate, report: &Report, out: &mut String) {
    const MOST: usize = 6;

    fn identity_is_contradicted(candidate: &Candidate) -> bool {
        candidate.hash_checks.iter().any(|check| !check.agrees)
    }

    if candidate.hash.is_empty() || identity_is_contradicted(candidate) {
        return;
    }
    let twins: Vec<&Candidate> = report
        .candidates
        .iter()
        .filter(|other| other.id != candidate.id)
        .filter(|other| !identity_is_contradicted(other))
        .filter(|other| candidate.hash.same_file_as(&other.hash) == Some(true))
        .collect();
    if twins.is_empty() {
        return;
    }

    let algorithm =
        twins.first().and_then(|t| candidate.hash.agreeing_algorithm(&t.hash)).unwrap_or("digest");
    let _ = writeln!(out, "     same     the same bytes are also on this volume at:");
    for twin in twins.iter().take(MOST) {
        let _ = writeln!(out, "              {}", twin.label());
        let mut note = format!("{}, p = {:.2}", twin.id, twin.probability());
        if twin.probability() < report.threshold {
            note.push_str(&format!(" — BELOW the {:.2} reporting threshold", report.threshold));
        }
        match twin.acquired_hash.as_ref().filter(|h| !h.is_empty()) {
            Some(_) => note.push_str(&format!(", identical {algorithm} computed from its bytes")),
            None => match twin.recorded_hash() {
                Some((source, _)) => note.push_str(&format!(
                    ", identical {algorithm} — as {} recorded it for that path; no bytes were                      read there this run, so this is that artifact's memory of the file rather                      than a reading of it",
                    source.label()
                )),
                None => note.push_str(&format!(", identical {algorithm}")),
            },
        }
        if let Some(ran) = executions(twin) {
            note.push_str(&format!(". {ran}"));
        }
        for line in wrap(&note, WIDTH - 16) {
            let _ = writeln!(out, "                {line}");
        }
    }
    if twins.len() > MOST {
        let _ = writeln!(
            out,
            "              and {} more — see --json for all of them",
            twins.len() - MOST
        );
    }
    let scored = candidate
        .evidence
        .iter()
        .find(|e| e.feature == "shared_digest_renamed_copy")
        .map(|e| e.log_lr);
    let duplicates = report
        .candidates
        .iter()
        .filter(|c| {
            c.observations
                .iter()
                .any(|o| matches!(o.kind, ObservationKind::SharedDigestElsewhere { .. }))
        })
        .count();
    let verdict = match scored {
        Some(weight) => format!(
            "One of these copies carries a name the other does not, in a different part \
             of the filesystem, and THAT was scored: {weight:+.1} log-odds, in the \
             `why:` block above under `shared_digest_renamed_copy`. Duplication on its \
             own is not evidence -- a Windows volume carries thousands of legitimate \
             duplicates, and this run found {duplicates} of them. A copy that was \
             RENAMED on the way is rarer: 14 of 17,847 candidates on the busiest clean \
             machine this tool has been measured on, none of them above 0.17, and they \
             were all one program vendoring another's executable under a new name."
        ),
        None => "This is an identity, not evidence: it carries no log-odds and moved no \
                 probability, above or below. Every copy here keeps the same name, or \
                 sits in the same part of the filesystem, which is what an installer's \
                 own second copy looks like."
            .to_string(),
    };
    for line in wrap(
        &format!(
            "Two paths with one digest are one file, copied. Which copy was written \
             first, and which was written from which, is NOT established here -- the \
             digest is identical and says nothing about direction. {verdict}"
        ),
        WIDTH - 14,
    ) {
        let _ = writeln!(out, "              {line}");
    }
    out.push('\n');
}

fn executions(candidate: &Candidate) -> Option<String> {
    let mut earliest: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut runs: Option<u32> = None;
    let mut sources: Vec<String> = Vec::new();
    for observation in &candidate.observations {
        if let ObservationKind::Executed { when, run_count } = &observation.kind {
            let label = observation.source.label();
            if !sources.contains(&label) {
                sources.push(label);
            }
            if let Some(when) = when {
                earliest = Some(earliest.map_or(*when, |e| e.min(*when)));
            }
            if let Some(count) = run_count {
                runs = Some(runs.map_or(*count, |r: u32| r.max(*count)));
            }
        }
    }
    if sources.is_empty() {
        return None;
    }
    let names: Vec<&str> = sources.iter().map(String::as_str).collect();
    let mut text = format!("That copy was executed: {}", join_with_and(&names));
    if let Some(when) = earliest {
        text.push_str(&format!(" recorded it, earliest {}", mm_core::filetime::format(when)));
    }
    if let Some(count) = runs {
        text.push_str(&format!(", run count {count}"));
    }
    Some(text)
}

fn render_deleted_registry_values(candidate: &Candidate, out: &mut String) {
    const MOST: usize = 4;

    let found: Vec<(&str, &str, &str)> = candidate
        .observations
        .iter()
        .filter_map(|o| match (&o.kind, &o.source) {
            (
                ObservationKind::DeletedRegistryValue { value_name, raw_value },
                mm_core::ArtifactSource::Registry { hive, .. },
            ) => Some((hive.as_str(), value_name.as_str(), raw_value.as_str())),
            _ => None,
        })
        .collect();
    if found.is_empty() {
        return;
    }

    let _ = writeln!(out, "     deleted  a registry value naming this file has been REMOVED");
    for (hive, name, raw) in found.iter().take(MOST) {
        let shown = if name.is_empty() { "(Default)" } else { name };
        for line in wrap(&format!("{hive} · {shown} = {raw}"), WIDTH - 14) {
            let _ = writeln!(out, "              {line}");
        }
    }
    if found.len() > MOST {
        let _ = writeln!(out, "              ...and {} more", found.len() - MOST);
    }
    for line in wrap(
        "The key each value was under could NOT be recovered — a freed cell carries no \
         parent pointer — so what the value meant is unknown and this scores nothing. \
         Recovering the key needs the hive's transaction logs, which this build does not \
         read.",
        WIDTH - 14,
    ) {
        let _ = writeln!(out, "              {line}");
    }
    out.push('\n');
}

fn render_origin(candidate: &Candidate, out: &mut String) {
    let Some((zone, host, referrer)) = candidate.observations.iter().find_map(|o| match &o.kind {
        ObservationKind::DownloadedFrom { zone, host_url, referrer_url } => {
            Some((*zone, host_url.clone(), referrer_url.clone()))
        }
        _ => None,
    }) else {
        return;
    };

    let _ = writeln!(out, "     origin   Mark of the Web — {} zone", zone.label());
    if let Some(url) = &host {
        render_url("from", url, out);
    }
    if let Some(url) = &referrer {
        if host.as_deref() != Some(url.as_str()) {
            render_url("via", url, out);
        }
    }
    if host.is_none() && referrer.is_none() {
        let _ = writeln!(out, "              no URL was recorded in the stream");
    }
    let _ =
        writeln!(out, "              (written by whatever downloaded the file — treat as a lead)");
    out.push('\n');
}

fn render_url(label: &str, url: &str, out: &mut String) {
    const CONTINUATION: &str = "                   ";
    let width = WIDTH.saturating_sub(CONTINUATION.len()).max(16);

    let chars: Vec<char> = url.chars().collect();
    for (i, chunk) in chars.chunks(width).enumerate() {
        let text: String = chunk.iter().collect();
        if i == 0 {
            let _ = writeln!(out, "              {label:<4} {text}");
        } else {
            let _ = writeln!(out, "{CONTINUATION}{text}");
        }
    }
}

fn render_recovery(recovery: &Recovery, out: &mut String) {
    match recovery {
        Recovery::Intact => {}
        Recovery::UnlinkedButPresent { detail } => {
            let _ = writeln!(out, "              IN PLACE, NOT IN ITS DIRECTORY —");
            for line in wrap(detail, WIDTH - 18) {
                let _ = writeln!(out, "                {line}");
            }
        }
        Recovery::Confirmed { against } => {
            let _ =
                writeln!(out, "              VERIFIED — hash matches the one {against} recorded");
        }
        Recovery::Unverified { basis } => {
            let _ = writeln!(out, "              UNVERIFIED —");
            for line in wrap(basis, WIDTH - 18) {
                let _ = writeln!(out, "                {line}");
            }
        }
        Recovery::Partial { detail } => {
            let _ = writeln!(out, "              PARTIAL — NOT the sample —");
            for line in wrap(detail, WIDTH - 18) {
                let _ = writeln!(out, "                {line}");
            }
        }
    }
}

fn render_mft_record(candidate: &Candidate, out: &mut String) {
    let live = candidate.observations.iter().find_map(|o| match &o.kind {
        ObservationKind::FileExists { record: Some(r), .. } => Some(*r),
        _ => None,
    });
    let deleted = candidate.observations.iter().find_map(|o| match &o.kind {
        ObservationKind::FileDeleted { record: Some(r), .. } => Some(*r),
        _ => None,
    });
    match (live, deleted) {
        (Some(r), _) => {
            let _ = writeln!(out, "     record   $MFT {r}, in use");
        }
        (None, Some(r)) => {
            let _ = writeln!(out, "     record   $MFT {r}, FREE — the record outlived the file");
        }
        (None, None) => {
            let _ = writeln!(out, "     record   $MFT UNKNOWN — no record was read for this path");
        }
    }
    out.push('\n');
}

fn mft_record_line(candidate: &Candidate) -> Option<String> {
    for o in &candidate.observations {
        match &o.kind {
            ObservationKind::FileExists { record: Some(r), .. } => {
                return Some(format!("$MFT record {r}, in use"))
            }
            ObservationKind::FileDeleted { record: Some(r), .. } => {
                return Some(format!(
                    "$MFT record {r}, FREE — `diag mft --record {r}` says whether it still is"
                ))
            }
            _ => {}
        }
    }
    None
}

fn render_sample(candidate: &Candidate, case_directory: Option<&str>, out: &mut String) {
    fn detail(text: &str, out: &mut String) {
        for line in wrap(text, WIDTH - 14) {
            let _ = writeln!(out, "              {line}");
        }
    }

    let bytes_were_read: bool = match &candidate.acquisition {
        Acquisition::Bytes { via, size, saved_as, recovery } => {
            let verb = if recovery.is_trustworthy() { "recovered" } else { "reconstructed" };
            let _ = writeln!(
                out,
                "     sample   {verb} from {} ({} bytes)",
                via.label(),
                thousands(*size)
            );
            match case_directory {
                Some(dir) => {
                    let _ = writeln!(out, "              → {}", join_case_path(dir, saved_as));
                }
                None => {
                    let _ = writeln!(out, "              → {saved_as}");
                    let _ = writeln!(out, "                (relative to the case directory)");
                }
            }
            render_recovery(recovery, out);
            true
        }
        Acquisition::Withheld { via, size, recovery } => {
            let verb = if recovery.is_trustworthy() { "recovered" } else { "reconstructed" };
            let _ = writeln!(
                out,
                "     sample   {verb} from {} ({} bytes) and WITHHELD",
                via.label(),
                thousands(*size)
            );
            detail(
                "The bytes were read and hashed but not written to the case directory, because \
                 this run was given --no-samples. The digests below are of those bytes. Re-run \
                 without --no-samples to keep the file itself — it is malware, unmodified.",
                out,
            );
            render_recovery(recovery, out);
            true
        }
        Acquisition::HashOnly { via } => {
            let _ = writeln!(out, "     sample   NO BYTES were written to the case directory.");
            detail(
                &format!(
                    "The file could not be read or carved back; its identity below comes from \
                     {} alone.",
                    via.label()
                ),
                out,
            );
            false
        }
        Acquisition::Failed { reason } => {
            let _ = writeln!(out, "     sample   NO BYTES — acquisition failed:");
            detail(reason, out);
            false
        }
        Acquisition::NotAttempted => {
            let _ = writeln!(out, "     sample   NOT ATTEMPTED for this candidate.");
            detail(
                "No bytes were sought and none were written. This is a fact about the run, not \
                 about the file: it says nothing either way about whether the file is still on \
                 the volume. Re-run with a larger --acquire-top to reach it.",
                out,
            );
            false
        }
    };

    let withheld = matches!(candidate.acquisition, Acquisition::Withheld { .. });

    let acquired = candidate.acquired_hash.as_ref().filter(|h| !h.is_empty());
    if candidate.hash.is_empty() && acquired.is_none() {
        let _ = writeln!(out, "     hash     UNKNOWN — none was computed and no artifact");
        let _ = writeln!(out, "              recorded one");
        out.push('\n');
        return;
    }

    let bytes_are_this_file = matches!(acquired, Some(a) if candidate.hash.agrees_with(a));

    render_digest_groups(candidate, acquired, bytes_are_this_file, bytes_were_read, withheld, out);
    render_hash_checks(candidate, bytes_are_this_file, out);
    out.push('\n');
}

fn render_digest_groups(
    candidate: &Candidate,
    acquired: Option<&mm_core::FileHash>,
    adopted: bool,
    bytes_were_read: bool,
    withheld: bool,
    out: &mut String,
) {
    let above = if withheld { "read above" } else { "saved above" };
    fn group(heading: &str, hashes: &mm_core::FileHash, out: &mut String) {
        let mut lines = wrap(heading, WIDTH - 14).into_iter();
        if let Some(first) = lines.next() {
            let _ = writeln!(out, "     hashes   {first}");
        }
        for rest in lines {
            let _ = writeln!(out, "              {rest}");
        }
        if let Some(h) = hashes.sha256_hex() {
            let _ = writeln!(out, "       sha256 {h}");
        }
        if let Some(h) = hashes.sha1_hex() {
            let _ = writeln!(out, "       sha1   {h}");
        }
        if let Some(h) = hashes.md5_hex() {
            let _ = writeln!(out, "       md5    {h}");
        }
    }

    if let Some(a) = acquired {
        if adopted {
            group(&format!("computed from the bytes {above}"), a, out);
        } else if withheld {
            group(
                "of the bytes read above — which the recovery line above says are NOT this \
                 file. Printed because they are the only record of what this run actually \
                 hashed, not as this file's identity",
                a,
                out,
            );
        } else {
            group(
                "of the bytes saved above — which the recovery line above says are NOT this \
                 file. Printed so the analyst can recognise what is in the case directory, not \
                 as this file's identity",
                a,
                out,
            );
        }
    }

    let mut claimed = candidate.hash.clone();
    if let Some(a) = acquired {
        if claimed.sha256 == a.sha256 {
            claimed.sha256 = None;
        }
        if claimed.sha1 == a.sha1 {
            claimed.sha1 = None;
        }
        if claimed.md5 == a.md5 {
            claimed.md5 = None;
        }
    }
    if claimed.is_empty() {
        return;
    }
    let by = candidate.recorded_hash().map(|(source, _)| source.label());
    let heading = match (by, bytes_were_read) {
        (Some(by), true) => format!(
            "as {by} recorded them for this file — NOT of the bytes {above}, and not \
             verified against them"
        ),
        (Some(by), false) => format!(
            "as {by} recorded them — NOT verified against any bytes, because none were read \
             this run"
        ),
        (None, false) => "as recorded by an artifact — NOT verified against any bytes".to_string(),
        (None, true) => format!(
            "PROVENANCE NOT RECORDED — this run did not record whether these are of the bytes \
             {above} or an artifact's claim about this file, so neither is asserted"
        ),
    };
    group(&heading, &claimed, out);
}

fn render_hash_checks(candidate: &Candidate, bytes_are_this_file: bool, out: &mut String) {
    for check in &candidate.hash_checks {
        let algorithm = check.algorithm.to_uppercase();
        if check.agrees {
            let _ = writeln!(
                out,
                "     matches  the {algorithm} {} recorded for this file — the bytes read",
                check.recorded_by
            );
            let _ = writeln!(out, "              this run are the file it saw");
            continue;
        }
        if bytes_are_this_file {
            let _ = writeln!(
                out,
                "     CHANGED  the {algorithm} {} recorded for this file is",
                check.recorded_by
            );
            let _ = writeln!(out, "              NOT the {algorithm} of the bytes read this run:");
            let _ = writeln!(out, "       was    {}", check.recorded);
            let _ = writeln!(out, "       is now {}", check.computed);
            detail_at_14(
                &format!(
                    "The file at this path was replaced or updated after {} recorded it, so \
                     that artifact's hash identifies something that is no longer here. On its \
                     own this is a lead and not a verdict, and it scores nothing: measured on \
                     the reference machine, 159 of the 2,911 Amcache-known files still present \
                     disagree the same way (5.5%) — Visual Studio, Edge, Docker, Firefox and \
                     other self-updating software.",
                    check.recorded_by
                ),
                out,
            );
            continue;
        }
        let _ =
            writeln!(out, "     MISMATCH the bytes recovered above do NOT hash to the {algorithm}");
        let _ = writeln!(out, "              {} recorded for this file:", check.recorded_by);
        let _ = writeln!(out, "       claim  {}", check.recorded);
        let _ = writeln!(out, "       bytes  {}", check.computed);
        detail_at_14(
            &format!(
                "Two explanations, and nothing here chooses between them: the recovery is \
                 incomplete — see what it rests on, above — or the file was replaced after {} \
                 recorded it. Neither is claimed, and this scores nothing.",
                check.recorded_by
            ),
            out,
        );
    }
}

fn detail_at_14(text: &str, out: &mut String) {
    for line in wrap(text, WIDTH - 14) {
        let _ = writeln!(out, "              {line}");
    }
}

fn join_case_path(dir: &str, relative: &str) -> String {
    let sep = if dir.contains('\\') || dir.contains(':') { '\\' } else { '/' };
    let dir = dir.trim_end_matches(['\\', '/']);
    let relative: String =
        relative.chars().map(|c| if c == '/' || c == '\\' { sep } else { c }).collect();
    format!("{dir}{sep}{relative}")
}

fn already_said(detail: &str, label: &str) -> bool {
    if detail.contains(label) {
        return true;
    }
    match label.split_once(' ') {
        Some((_, payload)) => payload.len() >= 8 && detail.contains(payload),
        None => false,
    }
}

const MOST_SOURCES_PER_ROW: usize = 3;

fn render_evidence_provenance(evidence: &mm_core::Evidence, out: &mut String) {
    let mut labels: Vec<String> = Vec::new();
    for source in &evidence.sources {
        let label = source.label();
        if !labels.contains(&label) && !already_said(&evidence.detail, &label) {
            labels.push(label);
        }
    }

    let line = if labels.is_empty() {
        evidence.feature.clone()
    } else {
        let shown: Vec<&str> =
            labels.iter().take(MOST_SOURCES_PER_ROW).map(String::as_str).collect();
        let more = labels.len().saturating_sub(MOST_SOURCES_PER_ROW);
        format!(
            "{} \u{b7} from {}{}",
            evidence.feature,
            shown.join(", "),
            if more > 0 { format!(", and {more} more") } else { String::new() }
        )
    };

    for l in wrap(&line, WIDTH - 18) {
        let _ = writeln!(out, "              {l}");
    }
}

fn render_reasoning(candidate: &Candidate, out: &mut String) {
    let _ = writeln!(out, "     why:");
    for evidence in &candidate.evidence {
        let wrapped = wrap(&evidence.detail, WIDTH - 18);
        let mut lines = wrapped.iter();
        if let Some(first) = lines.next() {
            let _ = writeln!(out, "       {:+5.1}  {first}", evidence.log_lr);
        }
        for rest in lines {
            let _ = writeln!(out, "              {rest}");
        }
        render_evidence_provenance(evidence, out);
    }

    let _ =
        writeln!(out, "       {:+5.1}  base rate before any evidence", candidate.prior_log_odds);
    let _ = writeln!(out, "       ─────");
    let _ = writeln!(
        out,
        "       {:+5.1}  total log-odds → p = {:.2}",
        candidate.logit(),
        candidate.probability()
    );
}

fn render_nothing_found(report: &Report, out: &mut String) {
    if !report.prior_established() {
        render_no_base_rate(report, out);
        return;
    }

    let failed = report.coverage.failed_stages();
    let close = report.close_call();
    rule(&negative_heading(close.as_ref(), failed.is_empty()), out);

    let _ = writeln!(
        out,
        "No file on this volume rose above the reporting threshold of {:.2}.",
        report.threshold
    );
    out.push('\n');

    if let Some(close) = &close {
        render_close_call(close, report, out);
    }
    render_could_not_look(&failed, out);

    if report.candidates.is_empty() {
        let _ = writeln!(out, "No candidates were formed at all: not one file on this volume drew");
        let _ = writeln!(out, "even a single observation. Read that against the coverage below —");
        let _ = writeln!(out, "it is far more often a sign of an unreadable volume than of a");
        let _ = writeln!(out, "clean one.\n");
        render_negative_result_caveat(&report.coverage, out);
        return;
    }

    render_base_rate(report, out);
    render_top_of_ranking(report, out);
    render_negative_result_caveat(&report.coverage, out);
}

fn negative_heading(close: Option<&CloseCall>, looked_everywhere: bool) -> String {
    match (close, looked_everywhere) {
        (None, true) => "NOTHING FOUND".to_string(),
        (None, false) => "NOTHING FOUND — BUT THIS RUN COULD NOT LOOK EVERYWHERE".to_string(),
        (Some(close), true) => {
            format!("NOTHING CLEARED THE THRESHOLD — {} CAME CLOSE", close_call_subject(close))
        }
        (Some(close), false) => format!(
            "NOTHING CLEARED THE THRESHOLD — {} CAME CLOSE,\n\
             AND THIS RUN COULD NOT LOOK EVERYWHERE",
            close_call_subject(close)
        ),
    }
}

fn close_call_subject(close: &CloseCall) -> String {
    if close.in_band == 1 {
        "ONE CANDIDATE".to_string()
    } else {
        format!("{} CANDIDATES", thousands(close.in_band as u64))
    }
}

fn render_close_call(close: &CloseCall, report: &Report, out: &mut String) {
    let subject = if close.in_band == 1 {
        "One candidate".to_string()
    } else {
        format!("{} candidates", thousands(close.in_band as u64))
    };
    let possessive = if close.in_band == 1 { "Its" } else { "The strongest one's" };
    let population = thousands(close.population);

    let mut para = String::new();
    match (close.break_even, close.times_too_large()) {
        (BreakEven::AtMost(n), Some(factor)) => {
            let _ = write!(
                para,
                "{subject} came within a factor of {factor:.2} in volume size of being reported. \
                 {possessive} evidence reaches {:.2} on any volume of up to {} candidates, and \
                 this volume holds {population}. On a volume {factor:.2} times smaller — the same \
                 file, the same evidence, nothing about it changed — this report would have \
                 called it a finding.",
                report.threshold,
                thousands(n),
            );
        }
        (BreakEven::AtMost(n), None) => {
            let _ = write!(
                para,
                "{subject} carries evidence that reaches {:.2} on any volume of up to {} \
                 candidates, and this volume holds {population}. What kept it below the line was \
                 the size of this machine as the base rate below counts it, and the two counts do \
                 not agree.",
                report.threshold,
                thousands(n),
            );
        }
        _ => {
            let _ = write!(
                para,
                "{subject} carries evidence that reaches {:.2} on a volume of any size, and is \
                 below the line here only because something else in the total is negative.",
                report.threshold,
            );
        }
    }
    for line in wrap(&para, WIDTH) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    let mut caveat = format!(
        "That is not a finding, and this tool is not calling {} malicious. It is a statement \
         about how narrowly the threshold decided this run, and about what decided it — the \
         amount of software on this machine, which is not a fact about any file on it.",
        if close.in_band == 1 { "that file" } else { "any of those files" },
    );
    if close.heads_the_ranking {
        caveat.push_str(if close.in_band == 1 {
            " It is [1] in the ranking below."
        } else {
            " The strongest of them is [1] in the ranking below."
        });
    }
    for line in wrap(&caveat, WIDTH) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');
}

fn render_could_not_look(failed: &[(&str, &str)], out: &mut String) {
    if failed.is_empty() {
        return;
    }

    let n = failed.len();
    for line in wrap(
        &format!(
            "{n} artifact{} this run tried to read could NOT be read. A sample whose only \
             trace was in {} would not appear above, and this verdict does not rule one out:",
            if n == 1 { "" } else { "s" },
            if n == 1 { "it" } else { "them" },
        ),
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    for (stage, reason) in failed {
        let _ = writeln!(out, "  ! {stage} — FAILED");
        for line in wrap(reason, WIDTH - 6) {
            let _ = writeln!(out, "      {line}");
        }
    }
    out.push('\n');
}

fn render_no_base_rate(report: &Report, out: &mut String) {
    rule(NO_BASE_RATE_HEADING, out);

    for line in wrap(
        "The $MFT walk did not enumerate this volume, so how many places a file could be \
         hiding on it is UNKNOWN. Every probability this tool prints is evidence weighed \
         against that number. Without it there is no threshold to clear, and nothing below \
         is a finding — this is not a negative result either.",
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    for line in wrap(
        "The error runs in the direction that accuses: a run that reads less of a volume \
         forms fewer candidates, and dividing by a smaller population would make every \
         candidate that survived look stronger for no reason having anything to do with the \
         file. This run refuses rather than reporting that.",
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    render_could_not_look(&report.coverage.failed_stages(), out);

    if report.candidates.is_empty() {
        let _ = writeln!(out, "No candidates were formed at all.\n");
        render_negative_result_caveat(&report.coverage, out);
        return;
    }

    let mut leads: Vec<&mm_core::Candidate> =
        report.candidates.iter().filter(|c| crate::evidence_log_odds(c) > 0.0).collect();
    leads.sort_by(|a, b| {
        crate::evidence_log_odds(b)
            .partial_cmp(&crate::evidence_log_odds(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });

    let _ = writeln!(
        out,
        "{} candidate(s) were formed from the artifacts that could be read.",
        thousands(report.candidates.len() as u64)
    );
    if leads.is_empty() {
        let _ = writeln!(out, "None of them carried any net evidence of maliciousness.\n");
        render_negative_result_caveat(&report.coverage, out);
        return;
    }
    let _ = writeln!(out, "The strongest by evidence carried — the part of the result that does");
    let _ = writeln!(out, "not depend on the size of the machine — are LEADS, not findings:\n");

    for (rank, candidate) in leads.iter().take(crate::NEAR_MISS_LIMIT).enumerate() {
        let _ = writeln!(
            out,
            "[{}]  evidence {:+.1}   {}",
            rank + 1,
            crate::evidence_log_odds(candidate),
            candidate.label()
        );
        for evidence in &candidate.evidence {
            let _ = writeln!(out, "        {:+5.1}  {}", evidence.log_lr, evidence.feature);
        }
        out.push('\n');
    }
    if leads.len() > crate::NEAR_MISS_LIMIT {
        let _ = writeln!(
            out,
            "{} further candidate(s) carried some evidence and are not listed.",
            leads.len() - crate::NEAR_MISS_LIMIT
        );
    }
    let _ = writeln!(out, "Re-run with --json to get every candidate.\n");

    render_negative_result_caveat(&report.coverage, out);
}

fn render_base_rate(report: &Report, out: &mut String) {
    let (Some(prior), Some(needed)) = (report.prior_log_odds(), report.evidence_needed()) else {
        return;
    };
    let n = report.candidates.len();

    let _ =
        writeln!(out, "That threshold depended on this machine, and on nothing about any file:");
    out.push('\n');
    let _ = writeln!(out, "   {:>9}   candidates were formed on this volume", thousands(n as u64));
    if let Some(enumeration) = &report.enumeration {
        if let Some(population) = enumeration.effective_population(n) {
            let added = (population - n as f64).max(0.0).round() as u64;
            if added > 0 {
                let _ = writeln!(
                    out,
                    "   {:>9}   files the walk could not place, counted as if each were one",
                    thousands(added)
                );
                let _ = writeln!(
                    out,
                    "               (it placed {} of the {} files it knew of)",
                    thousands(enumeration.files_placed),
                    thousands(enumeration.files_placed + enumeration.files_lost)
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "   {prior:>+9.2}   base rate every one of them started from — odds of one in {}",
        implied_population(prior)
    );
    let _ = writeln!(
        out,
        "   {needed:>+9.2}   of evidence a candidate therefore needed to reach {:.2} here",
        report.threshold
    );
    out.push('\n');

    for line in wrap(
        &format!(
            "That base rate is one constant added to every candidate's total, so it cannot \
             reorder them. The ranking below is unaffected by the size of this machine; the \
             {:.2} line is not. A file carrying exactly the evidence shown below, on a volume \
             holding fewer candidates, scores higher for no reason having anything to do with \
             the file.",
            report.threshold
        ),
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');
}

fn render_top_of_ranking(report: &Report, out: &mut String) {
    if report.ranked_below().next().is_none() {
        for line in wrap(
            "No candidate carried any net evidence of maliciousness at all — every one of \
             them was argued for by nothing, or argued against on balance. That is a \
             stronger statement than the threshold makes, because it does not depend on \
             the size of this machine: there is no volume, of any size, on which anything \
             seen here would have been reported.",
            WIDTH,
        ) {
            let _ = writeln!(out, "{line}");
        }
        out.push('\n');
        return;
    }

    rule("STRONGEST CANDIDATES — the top of the ranking, NOT findings", out);

    for line in wrap(
        "None of these cleared the threshold and the tool is not calling any of them \
         malicious. On a clean machine the top of this list is simply the least ordinary \
         software on it. It is printed because the order is the part of the result that \
         does not depend on how big this volume is — so it is the part worth reading when \
         the threshold has said nothing.",
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    let limit = crate::NEAR_MISS_LIMIT;
    let mut shown: Vec<(&Candidate, usize)> = Vec::new();
    for candidate in report.ranked_below() {
        let key = evidence_key(candidate);
        if let Some((_, twins)) = shown.iter_mut().find(|(c, _)| evidence_key(c) == key) {
            *twins += 1;
            continue;
        }
        if shown.len() == limit {
            if candidate.probability() < shown[limit - 1].0.probability() {
                break;
            }
            continue;
        }
        shown.push((candidate, 0));
    }

    for (rank, (candidate, twins)) in shown.iter().enumerate() {
        render_near_miss(rank + 1, candidate, *twins, report, out);
    }

    let listed: usize = shown.iter().map(|(_, twins)| twins + 1).sum();
    let rest = report.candidates.len().saturating_sub(listed);
    if rest > 0 {
        let _ = writeln!(
            out,
            "{} further candidate{} ranked below these. --json lists every one.",
            thousands(rest as u64),
            if rest == 1 { "" } else { "s" }
        );
        out.push('\n');
    }
}

fn evidence_key(candidate: &Candidate) -> Vec<(&str, i64)> {
    let mut key: Vec<(&str, i64)> = candidate
        .evidence
        .iter()
        .map(|e| (e.feature.as_str(), (e.log_lr * 1000.0).round() as i64))
        .collect();
    key.sort_unstable();
    key
}

fn implied_population(prior_log_odds: f64) -> String {
    let n = (-prior_log_odds).exp();
    if !n.is_finite() || n >= 1e18 {
        return "an unstated number".to_string();
    }
    thousands(n.round() as u64)
}

fn render_near_miss(
    rank: usize,
    candidate: &Candidate,
    twins: usize,
    report: &Report,
    out: &mut String,
) {
    let evidence = evidence_log_odds(candidate);
    let families = candidate.corroboration();

    let _ = writeln!(
        out,
        "[{rank}]  p = {:.2}   evidence {evidence:+.1}   {families} artifact famil{}   {}",
        candidate.probability(),
        if families == 1 { "y" } else { "ies" },
        candidate.id
    );
    let _ = writeln!(out, "     {}", candidate.label());

    for e in &candidate.evidence {
        let wrapped = wrap(&e.detail, WIDTH - 18);
        let mut lines = wrapped.iter();
        if let Some(first) = lines.next() {
            let _ = writeln!(out, "       {:+5.1}  {first}", e.log_lr);
        }
        for rest in lines {
            let _ = writeln!(out, "              {rest}");
        }
    }

    let sentence = match break_even_population(evidence, report.threshold) {
        BreakEven::AtMost(n) => format!(
            "this much evidence reaches {:.2} on a volume of up to {} candidates; \
             this one holds {}",
            report.threshold,
            thousands(n),
            thousands(report.population())
        ),
        BreakEven::Never => {
            format!(
                "this much evidence does not reach {:.2} on a volume of any size",
                report.threshold
            )
        }
        BreakEven::Always => format!(
            "this much evidence reaches {:.2} on a volume of any size — it is only \
             below the line here because something else in the total is negative",
            report.threshold
        ),
    };
    for (i, line) in wrap(&sentence, WIDTH - 7).into_iter().enumerate() {
        let _ = writeln!(out, "     {}{line}", if i == 0 { "→ " } else { "  " });
    }

    if let Some(line) = mft_record_line(candidate) {
        let _ = writeln!(out, "     {line}");
    }

    if twins > 0 {
        let _ = writeln!(
            out,
            "     + {twins} other file{} scored identically on the same features",
            if twins == 1 { "" } else { "s" }
        );
    }
    out.push('\n');
}

fn render_negative_result_caveat(coverage: &Coverage, out: &mut String) {
    if coverage.looked_everywhere() {
        let _ = writeln!(out, "This is a real result rather than a failure. Read it together with");
        let _ =
            writeln!(out, "what was and was not readable, below: a machine whose artifacts were");
        let _ = writeln!(out, "wiped looks the same as a machine that was never infected.\n");
        return;
    }

    for line in wrap(
        "This is NOT a clean bill of health. Parts of this machine could not be read, so \
         \"nothing found\" here means \"nothing found in what was readable\" — which is a \
         weaker statement, and WHAT WAS READ below is the part of this report that says how \
         much weaker. A machine whose artifacts were wiped looks the same as a machine that \
         was never infected, and so does a machine this tool could not finish reading.",
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    if !coverage.other_volumes.is_empty() {
        let volumes: Vec<&str> = coverage.other_volumes.iter().map(|v| v.volume.as_str()).collect();
        for line in wrap(
            &format!(
                "One of those parts is a different disk: artifacts here name files on {}, \
                 which this run did not open. See RECORDED ON A VOLUME THIS RUN DID NOT \
                 EXAMINE, below.",
                join_with_and(&volumes)
            ),
            WIDTH,
        ) {
            let _ = writeln!(out, "{line}");
        }
        out.push('\n');
    }
}

fn indented(text: &str, out: &mut String) {
    for (i, line) in wrap(text, WIDTH - 5).into_iter().enumerate() {
        let prefix = if i == 0 { "     " } else { "       " };
        let _ = writeln!(out, "{prefix}{line}");
    }
}

fn join_with_and(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

fn render_arrival_timeline(report: &Report, out: &mut String) {
    let Some(timeline) = &report.arrival_timeline else { return };
    if timeline.is_empty() {
        return;
    }

    rule("HOW THESE FILES ARRIVED", out);

    indented(
        &format!(
            "Every line below comes from this volume's NTFS change journal \
             ($Extend\\$UsnJrnl:$J), which the filesystem driver writes as things happen and \
             which SetFileTime does not reach. {} of its {} rows are shown, naming {} file(s).",
            thousands(timeline.rows_admitted as u64),
            thousands(timeline.rows_in_journal as u64),
            timeline.files_named,
        ),
        out,
    );
    out.push('\n');
    indented(
        "Nothing here is scored, and nothing here says that one file produced another. \
         A journal row records that a NAMED FILE was created, renamed, written or deleted \
         at a MOMENT, in a DIRECTORY — it has no verb whose subject is another file. \
         Reading a sequence of those as cause and effect is the analyst's call and not \
         this tool's. The intervals are subtraction over the two timestamps either side \
         of them.",
        out,
    );
    out.push('\n');
    let mut admission = format!(
        "A file is listed here when it is one of the findings above, when it is a candidate \
         whose arrival falls inside the incident window, or when it arrived in the same \
         directory within {} s of one of those. Each one says which, on its own line.",
        timeline.radius_seconds
    );
    if let Some(oldest) = timeline.oldest_record {
        admission.push_str(&format!(
            " The oldest row this journal still holds is {}: a file that arrived before that \
             has no arrival here, and its absence is UNKNOWN rather than evidence.",
            mm_core::filetime::format(oldest)
        ));
    }
    indented(&admission, out);
    out.push('\n');

    let ranks: Vec<mm_core::CandidateId> = report.reportable().map(|c| c.id).collect();
    let label = |candidate: mm_core::CandidateId| match ranks.iter().position(|id| *id == candidate)
    {
        Some(i) => format!("[{}]", i + 1),
        None => "[ ]".to_string(),
    };
    let anchored: Vec<mm_core::CandidateId> =
        timeline.anchors.iter().map(|a| a.candidate).collect();

    render_arrival_order(timeline, report, out);

    for arrival in &timeline.anchors {
        let _ = writeln!(out, "  {}  {}", label(arrival.candidate), arrival.display_path);

        let admission = match arrival.admission {
            mm_core::Admission::Finding => format!(
                "{} · p = {:.2} · above the {:.2} reporting threshold, so it anchors",
                arrival.candidate, arrival.probability, report.threshold
            ),
            mm_core::Admission::InIncidentWindow => format!(
                "{} · p = {:.2} — BELOW the {:.2} reporting threshold, and NOT a finding. \
                 It anchors a block because the journal puts its arrival inside the incident \
                 window, and for no other reason. That is a moment, not evidence, and it \
                 moved no score",
                arrival.candidate, arrival.probability, report.threshold
            ),
        };
        for line in wrap(&admission, WIDTH - 7) {
            let _ = writeln!(out, "       {line}");
        }

        let where_ = match (&arrival.directory, arrival.sequence) {
            (Some(directory), Some(sequence)) => Some(format!(
                "$MFT record {} sequence {sequence}, which the journal places in {directory}",
                arrival.record
            )),
            (None, Some(sequence)) => Some(format!(
                "$MFT record {} sequence {sequence}. The directory the journal names as this \
                 file's parent is not one this run could place, or is not the directory the \
                 $MFT walk placed the file in, so nothing that arrived beside it is listed — \
                 a path this run cannot stand behind is not printed",
                arrival.record
            )),
            _ => None,
        };
        if let Some(where_) = where_ {
            for line in wrap(&where_, WIDTH - 7) {
                let _ = writeln!(out, "       {line}");
            }
        }
        out.push('\n');

        if arrival.files.is_empty() {
            for line in wrap(
                &format!(
                    "The change journal holds no row for $MFT record {} at the sequence this \
                     file occupies. How it arrived is UNKNOWN — it arrived before the \
                     journal's oldest surviving row, or its rows have been trimmed off the \
                     front. That is not a statement that nothing happened",
                    arrival.record
                ),
                WIDTH - 9,
            ) {
                let _ = writeln!(out, "         {line}");
            }
            out.push('\n');
            continue;
        }

        for file in &arrival.files {
            if let Some(gap) = file.gap_seconds {
                let _ = writeln!(
                    out,
                    "       + {} after the line above, in the same directory",
                    interval(gap)
                );
                out.push('\n');
            }
            render_arrival_file(file, report, &anchored, &label, out);
        }
    }
}

fn render_arrival_order(timeline: &mm_core::ArrivalTimeline, report: &Report, out: &mut String) {
    let mut seen: Vec<(u64, u16)> = Vec::new();
    let mut files: Vec<(&mm_core::Arrival, &mm_core::FileLife)> = Vec::new();
    for arrival in &timeline.anchors {
        for file in &arrival.files {
            if !seen.contains(&(file.record, file.sequence)) {
                seen.push((file.record, file.sequence));
                files.push((arrival, file));
            }
        }
    }
    files.sort_by_key(|(_, f)| arrival_moment(f));
    if files.len() < 2 {
        return;
    }

    indented(
        "In the order the journal recorded them arriving. They are not all in the same \
         directory, and being next to each other on this list means only that nothing else \
         admitted here was recorded in between.",
        out,
    );
    out.push('\n');

    let mut previous: Option<chrono::DateTime<chrono::Utc>> = None;
    for (arrival, file) in files {
        let at = arrival_moment(file);
        if let Some(previous) = previous {
            let _ = writeln!(
                out,
                "     + {}",
                interval((at - previous).num_milliseconds() as f64 / 1000.0)
            );
        }
        previous = Some(at);
        let _ = writeln!(out, "     {}", mm_core::filetime::format_millis(at));
        let _ = writeln!(out, "       {}", file.name);
        let mut tail = match arrival
            .directory
            .as_deref()
            .or_else(|| file.display_path.as_deref().and_then(directory_of))
        {
            Some(directory) => format!("in {directory}"),
            None => "in a directory this run could not place".to_string(),
        };
        let (id, probability) = match &file.role {
            mm_core::Role::Anchor => (Some(arrival.candidate), Some(arrival.probability)),
            mm_core::Role::Candidate { id, probability, .. } => (Some(*id), Some(*probability)),
            mm_core::Role::NotACandidate => (None, None),
        };
        tail.push_str(&match (id, probability) {
            (Some(id), Some(p)) if p < report.threshold => {
                format!(
                    " — {id}, p = {p:.2}, BELOW the {:.2} reporting threshold",
                    report.threshold
                )
            }
            (Some(id), Some(p)) => format!(" — {id}, p = {p:.2}"),
            _ => " — not a candidate; nothing on this volume names it".to_string(),
        });
        for line in wrap(&tail, WIDTH - 7) {
            let _ = writeln!(out, "       {line}");
        }
    }
    out.push('\n');
}

fn arrival_moment(file: &mm_core::FileLife) -> chrono::DateTime<chrono::Utc> {
    file.events
        .iter()
        .find_map(|e| match e {
            mm_core::Event::Appeared { at } => Some(*at),
            _ => None,
        })
        .unwrap_or(file.first)
}

fn directory_of(path: &str) -> Option<&str> {
    let (directory, _) = path.rsplit_once('\\')?;
    Some(if directory.is_empty() { "\\" } else { directory })
}

fn render_arrival_file(
    file: &mm_core::FileLife,
    report: &Report,
    anchored: &[mm_core::CandidateId],
    label: &dyn Fn(mm_core::CandidateId) -> String,
    out: &mut String,
) {
    let _ = writeln!(out, "       {}", file.name);

    let (reason, elsewhere) = match &file.role {
        mm_core::Role::Anchor => (
            "the file this block is about, at the $MFT record and sequence the walk read"
                .to_string(),
            false,
        ),
        mm_core::Role::Candidate { id, probability, below_threshold } => {
            let mut reason = format!("{id}, p = {probability:.2}");
            if *below_threshold {
                reason.push_str(&format!(
                    " — BELOW the {:.2} reporting threshold, and not a finding",
                    report.threshold
                ));
            }
            reason.push_str(&format!(
                ". Listed here because the journal puts its arrival in this directory {} the \
                 file this block is about",
                relative(file.offset_seconds)
            ));
            let elsewhere = anchored.contains(id);
            if elsewhere {
                reason.push_str(&format!(
                    ". It appeared {}; its own rows are under {}",
                    mm_core::filetime::format_millis(arrival_moment(file)),
                    label(*id)
                ));
            }
            (reason, elsewhere)
        }
        mm_core::Role::NotACandidate => (
            format!(
                "not a candidate: no artifact on this volume named this file, and this run \
                 never scored it. Listed only because the journal puts its arrival in this \
                 directory {} the file this block is about, and for no other reason",
                relative(file.offset_seconds)
            ),
            false,
        ),
    };
    for line in wrap(&reason, WIDTH - 9) {
        let _ = writeln!(out, "         {line}");
    }

    if elsewhere {
        out.push('\n');
        return;
    }

    for event in &file.events {
        for (i, line) in wrap(&describe_event(event, file), WIDTH - 11).into_iter().enumerate() {
            let _ = writeln!(out, "         {}{line}", if i == 0 { "" } else { "  " });
        }
    }

    for line in wrap(
        &format!(
            "out of {} journal row(s) for $MFT record {} sequence {}",
            file.rows, file.record, file.sequence
        ),
        WIDTH - 9,
    ) {
        let _ = writeln!(out, "         {line}");
    }
    out.push('\n');
}

fn describe_event(event: &mm_core::Event, file: &mm_core::FileLife) -> String {
    use mm_core::Event;
    match event {
        Event::Appeared { at } => {
            format!("appeared {}", mm_core::filetime::format_millis(*at))
        }
        Event::Written { at, extended, overwritten, truncated } => {
            let mut verbs: Vec<&str> = Vec::new();
            if *extended {
                verbs.push("written");
            }
            if *overwritten {
                verbs.push("rewritten in place");
            }
            if *truncated {
                verbs.push("truncated");
            }
            format!("{} by {}", join_with_and(&verbs), mm_core::filetime::format_millis(*at))
        }
        Event::Closed { at, after_seconds } => {
            let mut line = if after_seconds.abs() < 0.0005 {
                format!(
                    "closed {} — the same instant the journal recorded it appearing",
                    mm_core::filetime::format_millis(*at)
                )
            } else {
                format!(
                    "closed {}, {} after it appeared",
                    mm_core::filetime::format_millis(*at),
                    interval(*after_seconds)
                )
            };
            if *at >= file.last {
                line.push_str("; the journal holds nothing further for it");
            }
            line
        }
        Event::Renamed { at, from, to } => {
            let from = from.as_deref().unwrap_or("a name the journal does not hold");
            let to = to.as_deref().unwrap_or("a name the journal does not hold");
            format!("renamed from `{from}` to `{to}`, {}", mm_core::filetime::format_millis(*at))
        }
        Event::Deleted { at } => {
            format!(
                "the name was gone from this directory by {}",
                mm_core::filetime::format_millis(*at)
            )
        }
    }
}

fn interval(seconds: f64) -> String {
    let magnitude = seconds.abs();
    if magnitude < 1.0 {
        format!("{:.0} ms", magnitude * 1000.0)
    } else if magnitude < 120.0 {
        format!("{magnitude:.1} s")
    } else {
        format!("{:.1} min", magnitude / 60.0)
    }
}

fn relative(offset_seconds: f64) -> String {
    if offset_seconds.abs() < 0.0005 {
        return "at the same moment as".to_string();
    }
    format!(
        "{} {}",
        interval(offset_seconds),
        if offset_seconds < 0.0 { "before" } else { "after" }
    )
}

fn render_mass_encryption(report: &Report, out: &mut String) {
    let Some(found) = &report.mass_encryption else {
        return;
    };

    rule("THIS MACHINE'S OWN FILES WERE ENCRYPTED", out);

    let subject = if found.files_scanned > 0 {
        format!(
            "{} of the {} live files this scan considered",
            thousands(found.files),
            thousands(found.files_scanned)
        )
    } else {
        format!("{} file{}", thousands(found.files), if found.files == 1 { "" } else { "s" })
    };

    for line in wrap(
        &format!(
            "{} on this volume {} renamed with the same appended extension \
             `.{}`, across {} director{}, and a file named `{}` \u{2014} {} bytes, that same \
             size every copy \u{2014} was left in {} of them. That pairing is what this report \
             is naming: files rewritten in bulk, and one note dropped beside them.",
            subject,
            if found.files == 1 { "was" } else { "were" },
            found.extension,
            thousands(found.directories),
            if found.directories == 1 { "y" } else { "ies" },
            found.note_name,
            thousands(found.note_size),
            format_percent(found.note_coverage),
        ),
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    let originals: Vec<String> = found
        .original_extensions
        .iter()
        .take(8)
        .map(|(ext, n)| format!(".{ext} {}", thousands(*n)))
        .collect();
    if !originals.is_empty() {
        indented(
            &format!(
                "underneath the appended extension the original names survive — {}{}",
                originals.join(", "),
                if found.original_extensions.len() > 8 { ", and more" } else { "" }
            ),
            out,
        );
    }

    let roots: Vec<String> =
        found.roots.iter().take(4).map(|(root, n)| format!("{root} ({})", thousands(*n))).collect();
    if !roots.is_empty() {
        indented(&format!("where: {}", roots.join(", ")), out);
    }

    if let Some((first, last)) = found.window() {
        indented(
            &format!(
                "when: the renamed files carry modification times from {} to {}. That is \
                 this machine's own clock as the $MFT recorded it, which is not necessarily \
                 the wall-clock time of the attack — a restored snapshot, a rolled-back \
                 virtual machine or a changed time zone all move it.",
                first.format("%Y-%m-%d %H:%M:%SZ"),
                last.format("%Y-%m-%d %H:%M:%SZ"),
            ),
            out,
        );
    }

    out.push('\n');
    let _ = writeln!(out, "  the note");
    indented(&found.note_example, out);
    indented(
        &format!(
            "{} bytes, found in {} director{}",
            thousands(found.note_size),
            thousands(found.note_directories),
            if found.note_directories == 1 { "y" } else { "ies" }
        ),
        out,
    );

    if !found.examples.is_empty() {
        out.push('\n');
        let _ = writeln!(out, "  encrypted files, first few by record order");
        for path in found.examples.iter().take(6) {
            indented(path, out);
        }
    }

    out.push('\n');
    for line in wrap(
        "What this does NOT establish. malmathic cannot decrypt anything and does not try. \
         It cannot say which ransomware family this is, which key was used, or whether the \
         files are recoverable at all. It has not read the note's contents to reach this \
         conclusion and is not quoting them as a claim. Above all it does NOT say that any \
         candidate below did the encrypting: the files ranked below were ranked on \
         their own evidence, this section was reached without looking at them, and joining \
         the two is the analyst's call and not this tool's.",
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');
}

fn format_percent(fraction: f64) -> String {
    let percent = 100.0 * fraction;
    if (percent - percent.round()).abs() < 0.05 {
        format!("{:.0}%", percent)
    } else {
        format!("{percent:.1}%")
    }
}

fn render_other_volumes(coverage: &Coverage, out: &mut String) {
    const SHOWN: usize = 8;

    if coverage.other_volumes.is_empty() {
        return;
    }

    rule("RECORDED ON A VOLUME THIS RUN DID NOT EXAMINE", out);

    for line in wrap(
        "Artifacts on the volume analysed name files on other volumes. This run opened one \
         volume, so nothing below was looked for, and its absence here is not evidence of \
         anything — a file on another disk is UNKNOWN to this report, not missing from it. If \
         the machine ran something from a second disk, a USB stick or a mounted image, this is \
         where it went.",
        WIDTH,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    for volume in &coverage.other_volumes {
        let _ = writeln!(
            out,
            "  {}  — {} observation{}",
            volume.volume,
            volume.observations,
            if volume.observations == 1 { "" } else { "s" }
        );
        let identity = match &volume.identified_as {
            Some(identity) => format!("this machine's MountedDevices recorded it as {identity}"),
            None => "not recorded in this machine's MountedDevices — a removable or optical \
                     volume, or a mapping that has since been removed"
                .to_string(),
        };
        indented(&identity, out);

        for path in volume.paths.iter().take(SHOWN) {
            indented(&format!("{} — {}, {}", path.path, path.source, path.claim), out);
        }
        if volume.paths.len() > SHOWN {
            indented(&format!("... and {} more", volume.paths.len() - SHOWN), out);
        }
        out.push('\n');
    }
}

fn render_coverage(coverage: &Coverage, wall_clock: Option<f64>, out: &mut String) {
    rule("WHAT WAS READ", out);

    for entry in &coverage.artifacts {
        let detail = match &entry.status {
            CoverageStatus::Read { observations } => format!("{observations} observations"),
            CoverageStatus::Absent => "not present on this machine".to_string(),
            CoverageStatus::Failed { reason } => format!("FAILED — {reason}"),
            CoverageStatus::NotAvailableHere { reason } => format!("unavailable — {reason}"),
        };
        let time = match entry.seconds {
            Some(seconds) => format_seconds(seconds),
            None => String::new(),
        };
        render_coverage_entry(&entry.artifact, &detail, &time, out);
    }

    out.push('\n');
    let _ = writeln!(
        out,
        "  {} files enumerated, {} deleted records still readable",
        thousands(coverage.files_enumerated),
        thousands(coverage.deleted_records_seen)
    );

    render_timing_summary(coverage, wall_clock, out);

    if !coverage.baseline_usable {
        let _ = writeln!(
            out,
            "  ! too little of the filesystem was read for machine-relative scoring;\n    \
             location and rarity evidence was disabled for this run"
        );
    }

    for warning in &coverage.warnings {
        for (i, line) in wrap(warning, WIDTH - 4).into_iter().enumerate() {
            let prefix = if i == 0 { "  ! " } else { "    " };
            let _ = writeln!(out, "{prefix}{line}");
        }
    }
    out.push('\n');
}

fn render_coverage_entry(label: &str, detail: &str, time: &str, out: &mut String) {
    const LABEL: usize = 26;
    const DETAIL: usize = 32;
    const TIME: usize = 8;
    const _: () = assert!(2 + LABEL + 1 + DETAIL + TIME <= WIDTH);

    if label.chars().count() <= LABEL && detail.chars().count() <= DETAIL {
        let line = format!("  {label:<LABEL$} {detail:<DETAIL$}{time:>TIME$}");
        let _ = writeln!(out, "{}", line.trim_end());
        return;
    }

    let room = WIDTH.saturating_sub(2 + time.chars().count() + 1).max(16);
    let mut label_lines = wrap(label, room).into_iter();
    let head = format!("  {}", label_lines.next().unwrap_or_default());
    let gap = WIDTH.saturating_sub(head.chars().count() + time.chars().count()).max(1);
    let line = format!("{head}{:gap$}{time}", "");
    let _ = writeln!(out, "{}", line.trim_end());
    for rest in label_lines {
        let _ = writeln!(out, "    {rest}");
    }
    for line in wrap(detail, WIDTH - 6) {
        let _ = writeln!(out, "      {line}");
    }
}

fn render_timing_summary(coverage: &Coverage, wall_clock: Option<f64>, out: &mut String) {
    let total = coverage.measured_seconds();

    if let Some(wall) = wall_clock {
        let _ = writeln!(out, "  {} wall clock for the whole run", format_seconds(wall).trim());
        let outside = wall - total;
        if total > 0.0 && outside >= 0.05 {
            for line in wrap(
                &format!(
                    "of which {} is accounted for by the stages listed above and {} fell \
                     outside them — volume discovery, opening the volume, and writing the \
                     case directory",
                    format_seconds(total).trim(),
                    format_seconds(outside).trim(),
                ),
                WIDTH - 4,
            ) {
                let _ = writeln!(out, "    {line}");
            }
        }
    }

    if total <= 0.0 {
        return;
    }
    let sentence = match coverage.slowest_stage() {
        Some((stage, seconds)) if seconds > 0.0 => format!(
            "{} of measured work, most of it in {} ({}, {:.0}%)",
            format_seconds(total).trim(),
            stage.split(" (").next().unwrap_or(stage),
            format_seconds(seconds).trim(),
            100.0 * seconds / total
        ),
        _ => format!("{} of measured work", format_seconds(total).trim()),
    };
    for line in wrap(&sentence, WIDTH - 2) {
        let _ = writeln!(out, "  {line}");
    }
}

pub fn format_seconds(seconds: f64) -> String {
    let seconds = if seconds == 0.0 { 0.0 } else { seconds };
    if seconds >= 600.0 {
        let minutes = (seconds / 60.0).floor();
        format!("{minutes:.0}m{:02.0}s", seconds - minutes * 60.0)
    } else if seconds >= 10.0 {
        format!("{seconds:.1} s")
    } else if seconds >= 0.1 {
        format!("{seconds:.2} s")
    } else {
        format!("{seconds:.3} s")
    }
}

fn render_trust(report: &Report, out: &mut String) {
    rule("HOW FAR TO TRUST THIS", out);

    if !report.weights_calibrated {
        let _ = writeln!(
            out,
            "The probabilities are computed from EXPERT-ESTIMATED weights, not from\n\
             weights fitted to a labelled corpus. Read \"0.94\" as \"the evidence here\n\
             is about as strong as the author judged a 0.94 to be\", not as a\n\
             measured frequency. The reasoning shown under each candidate is the\n\
             part worth arguing with."
        );
        out.push('\n');
    }

    let _ = writeln!(
        out,
        "Scores are relative to THIS machine. A file can be malicious and score\n\
         low because the evidence that would prove it was destroyed, and a file\n\
         can score high and be an unusual but legitimate tool. More than one\n\
         infection can be present, so the top result is not necessarily all of it."
    );
    out.push('\n');

    let _ = writeln!(
        out,
        "Every WHY line above is tagged with the feature id it was scored under.\n\
         `malmathic explain <feature>` prints that row of the weight table:\n\
         what it means, why the number is that number, and how many files on\n\
         the machines measured for this tool -- and found clean -- carry it.\n\
         That measurement is what the score rests on, and it is the thing to\n\
         argue with."
    );
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
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

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

pub fn console(report: &Report) -> String {
    let mut out = String::with_capacity(2048);
    let failed = report.coverage.failed_stages();

    console_banner(report, &mut out);
    console_could_not_look(&failed, &mut out);
    console_warnings(&report.coverage, &mut out);

    if report.found_anything() {
        const LISTED: usize = 6;
        for (rank, candidate) in report.reportable().take(LISTED).enumerate() {
            console_finding(rank + 1, candidate, report, &mut out);
        }
        let unlisted = report.reportable_count().saturating_sub(LISTED);
        if unlisted > 0 {
            let _ = writeln!(
                out,
                "  + {} further finding{} above {:.2}, listed in full in report.txt.",
                thousands(unlisted as u64),
                if unlisted == 1 { "" } else { "s" },
                report.threshold
            );
            out.push('\n');
        }
        console_also_ran(report, &mut out);
    } else {
        console_negative(report, &mut out);
    }

    console_other_volumes(&report.coverage, &mut out);
    console_where(report, &mut out);
    defang(out)
}

fn console_banner(report: &Report, out: &mut String) {
    let found = report.found_anything();
    let qualified = !found
        && (!report.prior_established()
            || !report.coverage.failed_stages().is_empty()
            || report.close_call().is_some());

    let bar = if found { "=" } else { "-" }.repeat(WIDTH);
    let marker = if found {
        "***  "
    } else if qualified {
        "!!!  "
    } else {
        ""
    };

    out.push('\n');
    let _ = writeln!(out, "{bar}");
    for (i, line) in headline(report).lines().enumerate() {
        if i == 0 {
            let _ = writeln!(out, "  {marker}{line}");
        } else {
            let _ = writeln!(out, "  {:width$}{line}", "", width = marker.len());
        }
    }
    let _ = writeln!(out, "{bar}");
    out.push('\n');
}

fn console_finding(rank: usize, candidate: &Candidate, report: &Report, out: &mut String) {
    let families = candidate.corroboration();
    let _ = writeln!(
        out,
        "  [{rank}]  p = {:.2}   {}   {families} artifact famil{}",
        candidate.probability(),
        candidate.id,
        if families == 1 { "y" } else { "ies" }
    );
    let _ = writeln!(out, "       {}", candidate.label());

    if families <= 1 {
        let _ = writeln!(out, "       ! thin corroboration - a lead, not a conclusion");
    }

    console_why(candidate, out);
    console_sample(candidate, report.case_directory.as_deref(), out);

    let sentence = match break_even_population(evidence_log_odds(candidate), report.threshold) {
        BreakEven::AtMost(n) => Some(format!(
            "this evidence reaches {:.2} on a volume of up to {} candidates; this one holds {}",
            report.threshold,
            thousands(n),
            thousands(report.population())
        )),
        BreakEven::Always => {
            Some(format!("this evidence reaches {:.2} on a volume of any size", report.threshold))
        }
        BreakEven::Never => None,
    };
    if let Some(sentence) = sentence {
        let mut label = "scale";
        for line in wrap(&sentence, WIDTH - 13) {
            let _ = writeln!(out, "       {label} {line}");
            label = "     ";
        }
    }
    out.push('\n');
}

fn console_why(candidate: &Candidate, out: &mut String) {
    const SHOWN: usize = 3;
    const MAX_LINES: usize = 3;
    const CONTINUATION: &str = "                    ";

    if candidate.evidence.is_empty() {
        return;
    }

    let mut ranked: Vec<&mm_core::Evidence> = candidate.evidence.iter().collect();
    ranked.sort_by(|a, b| b.log_lr.partial_cmp(&a.log_lr).unwrap_or(std::cmp::Ordering::Equal));

    let mut label = "why  ";
    for evidence in ranked.iter().take(SHOWN) {
        let (head, folded) = match evidence.detail.split_once("; also:") {
            Some((head, _)) => (head, true),
            None => (evidence.detail.as_str(), false),
        };
        let wrapped = wrap(head, WIDTH - CONTINUATION.len());
        let mut shown: Vec<String> = wrapped.iter().take(MAX_LINES).cloned().collect();
        if wrapped.len() > MAX_LINES || folded {
            if let Some(last) = shown.last_mut() {
                last.push_str(" ...");
            }
        }
        let mut lines = shown.iter();
        if let Some(first) = lines.next() {
            let _ = writeln!(out, "       {label} {:+5.1}  {first}", evidence.log_lr);
        }
        for rest in lines {
            let _ = writeln!(out, "{CONTINUATION}{rest}");
        }
        label = "     ";
    }

    let dropped = candidate.evidence.len().saturating_sub(SHOWN);
    if dropped > 0 {
        let _ = writeln!(
            out,
            "             + {dropped} weaker reason{}, the \"...\" text, the arithmetic - report.txt",
            if dropped == 1 { "" } else { "s" }
        );
    }
}

fn console_sample(candidate: &Candidate, case_directory: Option<&str>, out: &mut String) {
    let bytes_were_read = match &candidate.acquisition {
        Acquisition::Bytes { via, size, saved_as, recovery } => {
            let caveat = match recovery {
                Recovery::Intact => String::new(),
                Recovery::UnlinkedButPresent { .. } => "  NOT IN ITS DIRECTORY".to_string(),
                Recovery::Confirmed { against } => format!("  VERIFIED against {against}"),
                Recovery::Unverified { .. } => "  UNVERIFIED".to_string(),
                Recovery::Partial { .. } => "  PARTIAL - NOT THE SAMPLE".to_string(),
            };
            let _ = writeln!(out, "       bytes {} from {}{caveat}", thousands(*size), via.label());
            match case_directory {
                Some(dir) => {
                    let _ = writeln!(out, "             {}", join_case_path(dir, saved_as));
                }
                None => {
                    let _ = writeln!(out, "             {saved_as} (in the case directory)");
                }
            }
            if !recovery.is_trustworthy() {
                let _ = writeln!(out, "             why it may not be the file: report.txt");
            }
            true
        }
        Acquisition::Withheld { via, size, recovery } => {
            let caveat = match recovery {
                Recovery::UnlinkedButPresent { .. } => "  NOT IN ITS DIRECTORY",
                _ if recovery.is_trustworthy() => "",
                _ => "  UNVERIFIED",
            };
            let _ = writeln!(
                out,
                "       bytes {} from {} - WITHHELD (--no-samples){caveat}",
                thousands(*size),
                via.label()
            );
            let _ = writeln!(out, "             hashed but not written out; digest below");
            if matches!(recovery, Recovery::UnlinkedButPresent { .. }) {
                let _ = writeln!(out, "             what that means: report.txt");
            }
            true
        }
        Acquisition::HashOnly { via } => {
            let _ = writeln!(out, "       bytes NO BYTES were written to the case directory.");
            let _ = writeln!(out, "             Identified from {} alone.", via.label());
            false
        }
        Acquisition::Failed { reason } => {
            let _ = writeln!(out, "       bytes NO BYTES - acquisition failed:");
            for line in wrap(reason, WIDTH - 14).into_iter().take(2) {
                let _ = writeln!(out, "             {line}");
            }
            false
        }
        Acquisition::NotAttempted => {
            let _ = writeln!(out, "       bytes NOT ATTEMPTED - none were sought for this one.");
            let _ = writeln!(out, "             Re-run with a larger --acquire-top to reach it.");
            false
        }
    };

    let acquired = candidate.acquired_hash.as_ref().filter(|h| !h.is_empty());
    let adopted = matches!(acquired, Some(a) if candidate.hash.agrees_with(a));

    let recorded_by = candidate.recorded_hash().map(|(source, _)| source.label());
    let withheld = matches!(candidate.acquisition, Acquisition::Withheld { .. });
    let of_the_bytes =
        if withheld { "of the bytes read (not saved)" } else { "of the saved bytes" };
    let (digest, provenance) = if adopted {
        (candidate.hash.best(), of_the_bytes.to_string())
    } else if let Some(a) = acquired {
        (a.best(), format!("{of_the_bytes}, which are NOT this file"))
    } else if !candidate.hash.is_empty() {
        let provenance = match (recorded_by, bytes_were_read) {
            (Some(by), true) => format!("as {by} recorded it - NOT {of_the_bytes}"),
            (Some(by), false) => format!("as {by} recorded it - no bytes were read to check it"),
            (None, false) => "recorded by an artifact - never checked against bytes".to_string(),
            (None, true) => "PROVENANCE NOT RECORDED - see report.txt".to_string(),
        };
        (candidate.hash.best(), provenance)
    } else {
        (None, String::new())
    };
    match digest {
        Some(hex) => {
            let _ = writeln!(out, "       hash  {hex}");
            let _ = writeln!(out, "             ({provenance})");
        }
        None => {
            let _ = writeln!(out, "       hash  UNKNOWN - none computed, none recorded");
        }
    }

    for check in candidate.hash_checks.iter().filter(|c| !c.agrees) {
        let algorithm = check.algorithm.to_uppercase();
        let sentence = if adopted {
            format!(
                "CHANGED - the {algorithm} {} recorded is NOT the {algorithm} of these bytes: \
                 the file here was replaced after it was recorded",
                check.recorded_by
            )
        } else {
            format!(
                "MISMATCH - these bytes do NOT hash to the {algorithm} {} recorded. Either the \
                 recovery is incomplete or the file was replaced; report.txt says why neither \
                 is claimed",
                check.recorded_by
            )
        };
        let mut prefix = "       ! ";
        for line in wrap(&sentence, WIDTH - 9) {
            let _ = writeln!(out, "{prefix}{line}");
            prefix = "         ";
        }
    }
}

fn console_also_ran(report: &Report, out: &mut String) {
    let below = report.candidates.len().saturating_sub(report.reportable_count());
    if below == 0 {
        return;
    }
    let strongest = report
        .candidates
        .get(report.reportable_count())
        .map(|c| format!("; strongest {:.2}", c.probability()))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "  {} further candidate{} scored below {:.2}{strongest}.",
        thousands(below as u64),
        if below == 1 { "" } else { "s" },
        report.threshold
    );
    out.push('\n');
}

fn console_negative(report: &Report, out: &mut String) {
    if !report.prior_established() {
        for line in wrap(
            "This run could not establish how many files this volume holds, so the base rate \
             every probability divides by has no measurement behind it. Nothing is called a \
             finding and no probability is quoted. What was seen is listed in report.txt as \
             leads, ordered by evidence alone.",
            WIDTH - 2,
        ) {
            let _ = writeln!(out, "  {line}");
        }
        out.push('\n');
        return;
    }

    let mut summary = format!("No file on this volume rose above {:.2}.", report.threshold);
    if let (Some(prior), Some(needed)) = (report.prior_log_odds(), report.evidence_needed()) {
        summary.push_str(&format!(
            " {} candidate{} formed; the base rate started every one of them at \
             {prior:+.2} - odds of one in {} - so a candidate needed {needed:+.2} of \
             evidence to be reported here.",
            thousands(report.candidates.len() as u64),
            if report.candidates.len() == 1 { " was" } else { "s were" },
            implied_population(prior),
        ));
    }
    for line in wrap(&summary, WIDTH - 2) {
        let _ = writeln!(out, "  {line}");
    }
    out.push('\n');

    if let Some(close) = report.close_call() {
        let subject = if close.in_band == 1 { "One candidate" } else { "Candidates" };
        let sentence = match (close.break_even, close.times_too_large()) {
            (BreakEven::AtMost(n), Some(factor)) => format!(
                "{subject} came within a factor of {factor:.2} in volume size of being reported: \
                 that evidence reaches {:.2} on a volume of up to {} candidates and this one \
                 holds {}. What kept it below the line is the amount of software on this \
                 machine, which is not a fact about the file.",
                report.threshold,
                thousands(n),
                thousands(close.population)
            ),
            _ => format!(
                "{subject} carries evidence that would be reported on a smaller machine. See \
                 report.txt for the arithmetic."
            ),
        };
        for line in wrap(&sentence, WIDTH - 2) {
            let _ = writeln!(out, "  {line}");
        }
        out.push('\n');
    }

    let Some(strongest) = report.near_misses(1).into_iter().next() else {
        if report.candidates.is_empty() {
            for line in wrap(
                "No candidate was formed at all: not one file on this volume drew a single \
                 observation. That is far more often an unreadable volume than a clean one - \
                 read the coverage table in report.txt before believing it.",
                WIDTH - 2,
            ) {
                let _ = writeln!(out, "  {line}");
            }
            out.push('\n');
        }
        return;
    };

    let families = strongest.corroboration();
    let _ = writeln!(out, "  Top of the ranking - NOT a finding, and not called malicious:");
    let _ = writeln!(
        out,
        "       p = {:.2}   {}   {families} artifact famil{}",
        strongest.probability(),
        strongest.id,
        if families == 1 { "y" } else { "ies" }
    );
    let _ = writeln!(out, "       {}", strongest.label());
    console_why(strongest, out);
    out.push('\n');
}

fn console_could_not_look(failed: &[(&str, &str)], out: &mut String) {
    if failed.is_empty() {
        return;
    }
    let n = failed.len();
    for line in wrap(
        &format!(
            "{n} artifact{} this run tried to read could NOT be read, so this result does not \
             rule out a sample whose only trace was in {}:",
            if n == 1 { "" } else { "s" },
            if n == 1 { "it" } else { "them" }
        ),
        WIDTH - 2,
    ) {
        let _ = writeln!(out, "  {line}");
    }
    for (stage, _) in failed {
        let _ = writeln!(out, "     ! {stage} - FAILED (why, in report.txt)");
    }
    out.push('\n');
}

fn console_warnings(coverage: &Coverage, out: &mut String) {
    let n = coverage.warnings.len();
    if n == 0 {
        return;
    }
    let sentence = if n == 1 {
        "! 1 condition limits how far this result reaches; it is written out in report.txt."
            .to_string()
    } else {
        format!(
            "! {n} conditions limit how far this result reaches; each of them is written out \
             in report.txt."
        )
    };
    let mut prefix = "  ";
    for line in wrap(&sentence, WIDTH - 6) {
        let _ = writeln!(out, "{prefix}{line}");
        prefix = "    ";
    }
    out.push('\n');
}

fn console_other_volumes(coverage: &Coverage, out: &mut String) {
    if coverage.other_volumes.is_empty() {
        return;
    }
    let names: Vec<&str> = coverage.other_volumes.iter().map(|v| v.volume.as_str()).collect();
    let n = coverage.other_volumes.len();
    let mut first = true;
    for line in wrap(
        &format!(
            "! Artifacts here name {n} volume{} this run did not open ({}). A file on {} is \
             UNKNOWN to this report, not absent from it. Paths in report.txt.",
            if n == 1 { "" } else { "s" },
            join_with_and(&names),
            if n == 1 { "it" } else { "them" }
        ),
        WIDTH - 6,
    ) {
        let _ = writeln!(out, "  {prefix}{line}", prefix = if first { "" } else { "  " });
        first = false;
    }
    out.push('\n');
}

fn console_where(report: &Report, out: &mut String) {
    let _ = writeln!(out, "{}", "-".repeat(WIDTH));
    match &report.case_directory {
        Some(dir) => {
            let _ = writeln!(out, "  FULL REPORT - all evidence, what was read, the caveats:");
            let _ = writeln!(out, "      {}", join_case_path(dir, "report.txt"));
            let _ =
                writeln!(out, "  A page at a time:  more {}", join_case_path(dir, "report.txt"));
            let _ = writeln!(out, "  Case directory (report.json, and any sample\\ bytes):");
            let _ = writeln!(out, "      {dir}");
        }
        None => {
            let _ = writeln!(out, "  No case directory was written; the full report went to");
            let _ = writeln!(out, "  standard output only.");
        }
    }
    if let Some(seconds) = report.wall_clock_seconds {
        let _ = writeln!(
            out,
            "  Ran in {}, of which {} in timed stages.",
            format_seconds(seconds).trim(),
            format_seconds(report.coverage.measured_seconds()).trim()
        );
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use mm_core::{ArtifactSource, CandidateId, Evidence, FileHash, NormalizedPath, Observation};

    use crate::{ForeignPath, OtherVolume, Target};

    fn target() -> Target {
        Target {
            display_name: "C:".into(),
            device_path: "\\\\?\\Volume{a76f}".into(),
            volume_serial: "b1a2c3d4e5f60718".into(),
        }
    }

    fn strong_candidate() -> Candidate {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.path = NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe");
        c.hash = FileHash::compute(b"payload");
        c.evidence.push(Evidence::new(
            "quarantined_by_av",
            8.0,
            "Windows Defender quarantined this file as Trojan:Win32/Wacatac",
        ));
        c.evidence.push(Evidence::new(
            "system_binary_name_outside_system_dir",
            6.0,
            "named `svchost.exe` — a Windows system binary — but located in the user AppData",
        ));
        c.evidence.push(Evidence::new(
            "persistence_run_key",
            3.2,
            "set to start automatically (T1547.001)",
        ));
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::DefenderQuarantine,
            size: 147_456,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Confirmed { against: "Amcache".into() },
        };
        for source in [
            ArtifactSource::Mft,
            ArtifactSource::Amcache,
            ArtifactSource::DefenderQuarantine,
            ArtifactSource::Registry { hive: "NTUSER".into(), key: "Run".into() },
        ] {
            c.observe(mm_core::Observation::about_path(
                source,
                NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe").unwrap(),
                mm_core::ObservationKind::HashRecovered,
            ));
        }
        c
    }

    fn weak_candidate() -> Candidate {
        let mut c = Candidate::new(CandidateId(2), -9.2);
        c.path = NormalizedPath::parse("C:\\Users\\bob\\setup.exe");
        c.evidence.push(Evidence::new("unsigned_in_user_zone", 1.1, "unsigned"));
        c
    }

    fn coverage() -> Coverage {
        let mut c = Coverage {
            files_enumerated: 437_221,
            deleted_records_seen: 8_109,
            baseline_usable: true,
            ..Default::default()
        };
        c.record("Amcache", CoverageStatus::Read { observations: 120 });
        c.record("Prefetch", CoverageStatus::Absent);
        c
    }

    fn report_with(candidates: Vec<Candidate>) -> Report {
        Report::new("0.1.0", "live Windows", target(), candidates, coverage(), false)
    }

    fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn arrival_timeline() -> mm_core::ArrivalTimeline {
        use mm_core::arrival::{Admission, Arrival, ArrivalTimeline, Event, FileLife, Role};

        let at = |secs: i64, millis: u32| {
            chrono::DateTime::from_timestamp(1_778_000_000 + secs, millis * 1_000_000)
                .expect("a moment")
        };
        let zip = FileLife {
            name: "payload.zip".into(),
            display_path: Some("\\Users\\bob\\Desktop\\payload.zip".into()),
            record: 54_420,
            sequence: 11,
            rows: 13,
            first: at(0, 0),
            last: at(29, 600),
            role: Role::NotACandidate,
            offset_seconds: -29.6,
            gap_seconds: None,
            events: vec![Event::Appeared { at: at(0, 0) }],
        };
        let exe = FileLife {
            name: "payload.exe".into(),
            display_path: Some("\\Users\\bob\\Desktop\\payload.exe".into()),
            record: 113_978,
            sequence: 15,
            rows: 7,
            first: at(29, 600),
            last: at(29, 615),
            role: Role::Anchor,
            offset_seconds: 0.0,
            gap_seconds: Some(29.6),
            events: vec![
                Event::Appeared { at: at(29, 600) },
                Event::Written {
                    at: at(29, 615),
                    extended: true,
                    overwritten: true,
                    truncated: false,
                },
                Event::Closed { at: at(29, 615), after_seconds: 0.015 },
            ],
        };
        ArrivalTimeline {
            rows_in_journal: 244_896,
            rows_admitted: 20,
            files_named: 2,
            radius_seconds: 60,
            oldest_record: Some(at(-90_000, 0)),
            anchors: vec![Arrival {
                candidate: CandidateId(633),
                display_path: "C:\\Users\\bob\\Desktop\\payload.exe".into(),
                probability: 0.34,
                admission: Admission::InIncidentWindow,
                directory: Some("\\Users\\bob\\Desktop".into()),
                record: 113_978,
                sequence: Some(15),
                files: vec![zip, exe],
            }],
        }
    }

    fn report_with_arrivals() -> Report {
        let mut report = report_with(vec![strong_candidate(), weak_candidate()]);
        report.set_arrival_timeline(arrival_timeline());
        report
    }

    #[test]
    fn every_file_in_the_arrival_section_carries_its_own_reason_for_being_there() {
        let out = render(&report_with_arrivals());
        assert!(out.contains("HOW THESE FILES ARRIVED"), "{out}");
        assert!(
            out.contains("not a candidate: no artifact on this volume named this file"),
            "the one file nothing named must say so:\n{out}"
        );
        assert!(
            out.contains("and for no other reason"),
            "and it must say what DID put it there, exclusively:\n{out}"
        );
    }

    #[test]
    fn a_below_threshold_anchor_is_never_printed_without_the_word_below() {
        let out = render(&report_with_arrivals());
        let block = out.split("HOW THESE FILES ARRIVED").nth(1).expect("the section renders");
        assert!(block.contains("p = 0.34"), "{block}");
        assert!(
            block.contains("BELOW the 0.50 reporting threshold"),
            "a score below the bar must never appear without it:\n{block}"
        );
        assert!(block.contains("[ ]"), "and it must not be given a finding's number:\n{block}");
    }

    #[test]
    fn the_arrival_section_never_says_that_one_file_produced_another() {
        let out = render(&report_with_arrivals());
        let block = out.split("HOW THESE FILES ARRIVED").nth(1).expect("the section renders");
        let flattened = flat(block);
        for forbidden in [" then ", "which dropped", "after which", "which produced", "caused by"] {
            assert!(
                !flattened.contains(forbidden),
                "the section must not say {forbidden:?}:\n{block}"
            );
        }
        assert!(
            flat(block).contains("nothing here says that one file produced another"),
            "and it must say so out loud:\n{block}"
        );
    }

    #[test]
    fn the_interval_between_two_arrivals_is_printed_between_them() {
        let out = render(&report_with_arrivals());
        assert!(out.contains("+ 29.6 s after the line above, in the same directory"), "{out}");
        assert!(out.contains("15 ms after it appeared"), "{out}");
    }

    #[test]
    fn a_report_with_nothing_to_anchor_prints_no_arrival_section() {
        let out = render(&report_with(vec![strong_candidate(), weak_candidate()]));
        assert!(!out.contains("HOW THESE FILES ARRIVED"), "{out}");
    }

    #[test]
    fn a_finding_names_the_second_path_its_own_bytes_are_at() {
        let mut twin = Candidate::new(CandidateId(633), -9.2);
        twin.path = NormalizedPath::parse("C:\\Users\\bob\\Desktop\\954d8fcd.exe");
        twin.hash = FileHash::compute(b"payload");
        twin.evidence.push(Evidence::new("random_looking_name", 2.4, "looks machine-generated"));

        let report = report_with(vec![strong_candidate(), twin]);
        let out = render(&report);
        let flattened = flat(&out);
        assert!(out.contains("same     the same bytes are also on this volume at:"), "{out}");
        assert!(out.contains("C:\\Users\\bob\\Desktop\\954d8fcd.exe"), "{out}");
        assert!(out.contains("BELOW the 0.50 reporting threshold"), "{out}");
        assert!(flattened.contains("Two paths with one digest are one file, copied"), "{out}");
        assert!(
            flattened.contains("is NOT established here"),
            "direction must not be claimed:\n{out}"
        );
        assert!(
            flattened.contains("it carries no log-odds and moved no probability"),
            "and the block must say it is not evidence: {out}"
        );
        assert!(
            flattened.contains("One of them is not merely low-scoring"),
            "and the tail paragraph must stop calling it plain noise:\n{out}"
        );
    }

    #[test]
    fn a_contradicted_identity_never_claims_to_be_the_same_file() {
        let mut stale = Candidate::new(CandidateId(5), -9.2);
        stale.path = NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\stage5.exe");
        stale.hash = FileHash::compute(b"payload");
        stale.hash_checks.push(mm_core::HashCheck {
            algorithm: "sha1".into(),
            recorded_by: "Amcache".into(),
            recorded: "aa".repeat(20),
            computed: "bb".repeat(20),
            agrees: false,
        });

        let report = report_with(vec![strong_candidate(), stale]);
        let out = render(&report);
        assert!(
            !out.contains("the same bytes are also on this volume at"),
            "a digest this run measured to be wrong must not join two files:\n{out}"
        );
    }

    #[test]
    fn a_finding_states_the_population_it_was_weighed_against() {
        let report = report_with(vec![strong_candidate(), weak_candidate()]);
        let out = render(&report);
        assert!(out.contains("FINDINGS"));
        assert!(
            out.contains("this much evidence reaches 0.50 on a volume of up to"),
            "a finding did not say what population it was weighed against:\n{out}"
        );
        assert!(out.contains("this one holds 2"), "and it must print this volume's own count");
    }

    fn encrypted_machine() -> mm_core::MassEncryption {
        mm_core::MassEncryption {
            extension: "fuckazov".into(),
            files: 2_666,
            directories: 476,
            original_extensions: vec![
                ("js".into(), 1_862),
                ("json".into(), 214),
                ("txt".into(), 194),
            ],
            roots: vec![("\\Users\\Alice".into(), 2_656), ("\\Users\\Public".into(), 10)],
            examples: vec!["\\Users\\Alice\\Desktop\\notes.txt.fuckazov".into()],
            note_name: "stop_propaganda.txt".into(),
            note_size: 131,
            note_directories: 477,
            note_coverage: 1.0,
            note_example: "\\Users\\Alice\\Desktop\\stop_propaganda.txt".into(),
            earliest: Some(
                chrono::DateTime::parse_from_rfc3339("2026-05-09T18:42:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            latest: Some(
                chrono::DateTime::parse_from_rfc3339("2026-05-09T18:42:58Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            files_scanned: 444_482,
        }
    }

    #[test]
    fn an_encrypted_machine_says_so_before_the_findings() {
        let mut report = report_with(vec![strong_candidate(), weak_candidate()]);
        report.set_mass_encryption(encrypted_machine());
        let out = render(&report);

        let section = out
            .find("THIS MACHINE'S OWN FILES WERE ENCRYPTED")
            .expect("the machine was encrypted and the report must say so");
        assert!(
            section < out.find("\nFINDINGS \u{2014}").expect("still has findings"),
            "the encryption reframes the candidate list and must be printed above it"
        );

        assert!(out.contains("2 666"), "the file count:\n{out}");
        assert!(out.contains(".fuckazov"), "the extension:\n{out}");
        assert!(out.contains("476 directories"), "the spread:\n{out}");
        assert!(out.contains("stop_propaganda.txt"), "the note:\n{out}");
        assert!(out.contains("131 bytes"), "and its size, which is the shape:\n{out}");
        assert!(out.contains("that same size every copy"), "the claim made:\n{out}");
        assert!(!out.contains("bytes every time"), "the claim NOT made:\n{out}");
        assert!(out.contains(".js 1 862"), "the original extensions:\n{out}");
    }

    #[test]
    fn the_window_is_quoted_as_the_machines_own_clock() {
        let mut report = report_with(vec![strong_candidate()]);
        report.set_mass_encryption(encrypted_machine());
        let out = render(&report);
        assert!(out.contains("2026-05-09"), "{out}");
        assert!(out.contains("18:42:58Z"), "{out}");
        assert!(
            out.contains("this machine's own clock"),
            "a timestamp offered without that caveat sends the analyst to the wrong day:\n{out}"
        );
    }

    #[test]
    fn the_section_states_what_it_does_not_establish() {
        let mut report = report_with(vec![strong_candidate()]);
        report.set_mass_encryption(encrypted_machine());
        let out = render(&report);
        assert!(out.contains("cannot decrypt anything"), "{out}");
        assert!(
            out.contains("did the encrypting"),
            "the sample it found is not necessarily what encrypted anything:\n{out}"
        );
        assert!(out.contains("cannot say which ransomware family"), "{out}");
    }

    #[test]
    fn a_machine_that_was_not_encrypted_gains_no_section() {
        let out = render(&report_with(vec![strong_candidate(), weak_candidate()]));
        assert!(!out.contains("ENCRYPTED"), "{out}");
        assert!(!out.contains("stop_propaganda"), "{out}");
    }

    #[test]
    fn the_section_changes_no_candidates_score() {
        let plain = render(&report_with(vec![strong_candidate(), weak_candidate()]));
        let mut report = report_with(vec![strong_candidate(), weak_candidate()]);
        report.set_mass_encryption(encrypted_machine());
        let encrypted = render(&report);

        let findings_of = |text: &str| {
            let at = text.find("\nFINDINGS \u{2014}").expect("the findings heading");
            text[at..].to_string()
        };
        assert_eq!(
            findings_of(&plain),
            findings_of(&encrypted),
            "an encrypted machine must not change one probability below the section"
        );
    }

    #[test]
    fn a_run_with_no_base_rate_refuses_both_verdicts() {
        let mut report = report_with(vec![strong_candidate(), weak_candidate()]);
        assert!(render(&report).contains("FINDINGS"));

        report.set_enumeration(mm_core::Enumeration::not_attempted());
        let out = render(&report);

        assert!(
            out.contains("COULD NOT ESTABLISH THE SIZE OF THIS VOLUME"),
            "the heading did not say what was missing:\n{out}"
        );
        assert!(!out.contains("FINDINGS"), "a run with no base rate reported a finding:\n{out}");
        assert!(!out.contains("NOTHING FOUND"), "and it must not claim the machine was clean");
        assert!(out.contains("LEADS, not findings"));
        assert!(out.contains("quarantined_by_av"));
        assert!(!out.contains("p = "), "a probability was printed without a base rate:\n{out}");
    }

    #[test]
    fn a_lossy_walk_shows_what_widened_the_base_rate() {
        let mut report = report_with(vec![weak_candidate()]);
        report.set_enumeration(mm_core::Enumeration::partial(437_221, 1_600));
        let out = render(&report);
        assert!(out.contains("files the walk could not place"), "{out}");
        assert!(
            out.contains("437 221"),
            "the placed count is what makes the loss readable:\n{out}"
        );
    }

    #[test]
    fn a_finding_shows_its_arithmetic() {
        let text = render(&report_with(vec![strong_candidate()]));

        assert!(text.contains("FINDINGS"));
        assert!(text.contains("svchost.exe"));
        assert!(text.contains("Wacatac"));
        assert!(text.contains("+8.0"));
        assert!(text.contains("-9.2"), "the base rate must be shown, not hidden");
        assert!(text.contains("total log-odds"));
        assert!(text.contains("sample/C001.bin"));
        assert!(text.contains("sha256"));
    }

    #[test]
    fn a_clean_machine_says_so_instead_of_listing_innocents() {
        let text = render(&report_with(vec![weak_candidate()]));

        assert!(text.contains("NOTHING FOUND"));
        assert!(!text.contains("FINDINGS"));
        assert!(text.contains("setup.exe"));
        assert!(text.contains("real result rather than a failure"));
    }

    fn ranked(id: u32, path: &str, prior: f64, features: &[(&str, f64)]) -> Candidate {
        let mut c = Candidate::new(CandidateId(id), prior);
        c.path = NormalizedPath::parse(path);
        for (feature, log_lr) in features {
            c.evidence.push(Evidence::new(*feature, *log_lr, format!("detail for {feature}")));
        }
        c.observe(mm_core::Observation::about_path(
            ArtifactSource::Mft,
            NormalizedPath::parse(path).unwrap(),
            mm_core::ObservationKind::HashRecovered,
        ));
        c
    }

    const VM_PRIOR: f64 = -7.6700;
    const LAPTOP_PRIOR: f64 = -9.8275;

    const PLANTED: &[(&str, f64)] = &[
        ("executable_in_user_temp", 2.6),
        ("persistence_run_key", 3.2),
        ("unsigned_in_user_zone", 1.9),
    ];

    #[test]
    fn the_negative_result_says_what_the_threshold_depended_on() {
        let text =
            render(&report_with(vec![ranked(1, "C:\\Users\\bob\\x.exe", LAPTOP_PRIOR, PLANTED)]));

        assert!(text.contains("NOTHING FOUND"), "{text}");
        assert!(text.contains("depended on this machine"), "{text}");
        assert!(text.contains("-9.83"), "the base rate itself must be shown: {text}");
        assert!(text.contains("+9.83"), "and what it cost to clear the bar: {text}");
        assert!(text.contains("cannot\nreorder them"), "{text}");
    }

    #[test]
    fn the_stated_odds_come_from_the_base_rate_and_not_from_the_count() {
        let text = render(&report_with(vec![
            ranked(1, "C:\\a.exe", LAPTOP_PRIOR, PLANTED),
            ranked(2, "C:\\b.exe", LAPTOP_PRIOR, PLANTED),
        ]));
        assert!(text.contains("odds of one in 18 537"), "{text}");
        assert!(text.contains("2   candidates were formed"), "{text}");
        assert!(!text.contains("one in 2"), "the count must not be passed off as the odds: {text}");
    }

    #[test]
    fn the_negative_result_shows_the_top_of_the_ranking_with_its_evidence() {
        let text = render(&report_with(vec![
            ranked(1, "C:\\Users\\bob\\loud.exe", LAPTOP_PRIOR, PLANTED),
            ranked(2, "C:\\Users\\bob\\quiet.exe", LAPTOP_PRIOR, &[("unsigned_in_user_zone", 1.1)]),
        ]));

        assert!(text.contains("loud.exe"), "{text}");
        assert!(text.contains("quiet.exe"), "{text}");
        assert!(text.contains("detail for persistence_run_key"), "{text}");
        assert!(text.contains("+3.2"), "{text}");
        assert!(text.contains("NOT findings"), "{text}");
        assert!(text.contains("not calling any of them\nmalicious"), "{text}");
    }

    #[test]
    fn each_listed_candidate_says_how_small_a_machine_it_would_clear() {
        let text =
            render(&report_with(vec![ranked(1, "C:\\Users\\bob\\x.exe", LAPTOP_PRIOR, PLANTED)]));
        assert!(text.contains("on a volume of up to 2 208 candidates"), "{text}");
    }

    #[test]
    fn the_base_rate_moves_every_score_and_no_position() {
        let population = |prior: f64| {
            vec![
                ranked(1, "C:\\a.exe", prior, PLANTED),
                ranked(2, "C:\\b.exe", prior, &[("persistence_service", 3.4)]),
                ranked(3, "C:\\c.exe", prior, &[("unsigned_in_user_zone", 1.1)]),
            ]
        };
        let vm = report_with(population(VM_PRIOR));
        let laptop = report_with(population(LAPTOP_PRIOR));

        let order = |r: &Report| r.candidates.iter().map(|c| c.id.0).collect::<Vec<_>>();
        assert_eq!(order(&vm), order(&laptop), "the base rate reordered the ranking");

        for (a, b) in vm.candidates.iter().zip(&laptop.candidates) {
            assert!(a.probability() > b.probability(), "the smaller machine must score higher");
            assert!(
                (crate::evidence_log_odds(a) - crate::evidence_log_odds(b)).abs() < 1e-9,
                "the evidence is a fact about the file and must not move"
            );
        }

        let (a, b) = (vm.candidates[0].probability(), laptop.candidates[0].probability());
        assert!((a - 0.507).abs() < 0.005, "{a}");
        assert!((b - 0.106).abs() < 0.005, "{b}");

        assert!(vm.found_anything());
        assert!(!laptop.found_anything());

        let break_even = |r: &Report| {
            crate::break_even_population(crate::evidence_log_odds(&r.candidates[0]), r.threshold)
        };
        assert_eq!(break_even(&vm), crate::BreakEven::AtMost(2_208));
        assert_eq!(break_even(&vm), break_even(&laptop));
        assert!(render(&laptop).contains("on a volume of up to 2 208 candidates"));
    }

    fn volume(n: usize, evidence: f64) -> Report {
        let prior = (1.0 / n.max(2) as f64).ln();
        let mut candidates = vec![ranked(
            0,
            "C:\\Users\\Bob\\AppData\\Local\\Temp\\svcupdate.exe",
            prior,
            &[("measured", evidence)],
        )];
        for i in 1..n {
            candidates.push(ranked(
                i as u32,
                &format!("C:\\Program Files\\App\\f{i}.exe"),
                prior,
                &[("ordinary", 1.0)],
            ));
        }
        report_with(candidates)
    }

    fn volume_that_could_not_look(n: usize, evidence: f64) -> Report {
        let mut report = volume(n, evidence);
        report.coverage.record(
            "$MFT",
            CoverageStatus::Failed {
                reason: "read failed at cluster 1449984: incorrect function (device I/O error)"
                    .into(),
            },
        );
        report
    }

    #[test]
    fn a_clean_machine_never_gets_the_near_miss_heading() {
        for (n, evidence) in [(17_544, 8.6), (2_143, 7.0)] {
            let text = render(&volume(n, evidence));
            assert!(text.contains("\nNOTHING FOUND\n"), "{n} candidates: {text}");
            assert!(!text.contains("CAME CLOSE"), "{n} candidates: {text}");
            assert!(!text.contains("came within a factor"), "{n} candidates: {text}");
        }
    }

    #[test]
    fn a_run_that_came_close_stops_saying_nothing_was_found() {
        let text = render(&volume(17_545, 9.6));

        assert!(
            text.contains("NOTHING CLEARED THE THRESHOLD — ONE CANDIDATE CAME CLOSE"),
            "{text}"
        );
        assert!(!text.contains("NOTHING FOUND"), "{text}");
        assert!(text.contains("rose above the reporting threshold of 0.50"), "{text}");
        assert!(text.contains("not calling that file malicious"), "{text}");
        assert!(text.contains("NOT findings"), "{text}");
        assert!(text.contains("It is [1] in the ranking below"), "{text}");
    }

    #[test]
    fn the_escalation_is_stated_in_break_even_terms_and_never_as_a_second_score() {
        let text = render(&volume(17_545, 9.6));
        let start = text.find("rose above the reporting threshold").expect("the verdict");
        let end = text.find("That threshold depended").expect("the base rate");
        let escalation = &text[start..end];

        assert!(escalation.contains("up to 14 764 candidates"), "{escalation}");
        assert!(escalation.contains("holds 17 545"), "{escalation}");
        assert!(escalation.contains("factor of 1.19"), "{escalation}");

        for token in ["0.60", "0.46", "p =", "probability", "confidence", "likel"] {
            assert!(!escalation.contains(token), "{token:?} appears in: {escalation}");
        }
        assert_eq!(escalation.matches("0.5").count(), 2, "{escalation}");
    }

    #[test]
    fn the_band_is_not_a_property_of_one_machine_size() {
        let text = render(&volume(2_144, 7.3));
        assert!(text.contains("ONE CANDIDATE CAME CLOSE"), "{text}");
        assert!(text.contains("factor of 1.45"), "{text}");
        assert!(text.contains("up to 1 480 candidates"), "{text}");
    }

    #[test]
    fn a_run_that_came_close_and_could_not_look_gets_one_heading_for_both() {
        let text = render(&volume_that_could_not_look(17_545, 9.6));

        assert!(
            text.contains(
                "NOTHING CLEARED THE THRESHOLD — ONE CANDIDATE CAME CLOSE,\n\
                 AND THIS RUN COULD NOT LOOK EVERYWHERE"
            ),
            "{text}"
        );
        assert!(!text.contains("NOTHING FOUND"), "{text}");
        assert_eq!(text.matches("COULD NOT LOOK EVERYWHERE").count(), 1, "{text}");
        let close = text.find("came within a factor").expect("the escalation");
        let failed = text.find("could NOT be read").expect("the failed stage");
        assert!(close < failed, "{text}");
    }

    #[test]
    fn a_run_that_only_failed_to_read_keeps_the_heading_it_had() {
        let text = render(&volume_that_could_not_look(2_143, 7.0));
        assert!(text.contains("NOTHING FOUND — BUT THIS RUN COULD NOT LOOK EVERYWHERE"), "{text}");
        assert!(!text.contains("CAME CLOSE"), "{text}");

        let text = render(&volume(2_143, 7.0));
        assert!(text.contains("\nNOTHING FOUND\n"), "{text}");
        assert!(!text.contains("COULD NOT LOOK EVERYWHERE"), "{text}");
    }

    #[test]
    fn a_heading_that_covers_twenty_files_says_twenty() {
        let prior = (1.0f64 / 100.0).ln();
        let mut candidates: Vec<Candidate> = (0..20)
            .map(|i| {
                ranked(
                    i,
                    &format!("C:\\Windows\\Temp\\{{g{i}}}\\stub.exe"),
                    prior,
                    &[("twin", 4.2)],
                )
            })
            .collect();
        for i in 20..100 {
            candidates.push(ranked(i, &format!("C:\\f{i}.exe"), prior, &[("ordinary", 1.0)]));
        }
        let text = render(&report_with(candidates));

        assert!(
            text.contains("NOTHING CLEARED THE THRESHOLD — 20 CANDIDATES CAME CLOSE"),
            "{text}"
        );
        assert!(text.contains("20 candidates came within a factor"), "{text}");
        assert!(text.contains("The strongest one's evidence reaches"), "{text}");
        assert!(text.contains("not calling any of those files"), "{text}");
    }

    #[test]
    fn the_close_call_headings_fit_an_eighty_column_console() {
        for report in [
            volume(17_545, 9.6),
            volume_that_could_not_look(17_545, 9.6),
            volume_that_could_not_look(2_143, 7.0),
        ] {
            for line in render(&report).lines() {
                assert!(line.chars().count() <= 80, "{} columns: {line:?}", line.chars().count());
            }
        }
    }

    #[test]
    fn the_negative_result_lists_a_handful_and_counts_the_rest() {
        let candidates: Vec<Candidate> = (0..40)
            .map(|i| {
                ranked(
                    i,
                    &format!("C:\\Users\\bob\\f{i}.exe"),
                    VM_PRIOR,
                    &[
                        ("unsigned_in_user_zone", 1.1),
                        ("persistence_service", 3.4 - f64::from(i) * 0.01),
                    ],
                )
            })
            .collect();
        let text = render(&report_with(candidates));

        let listed = text.matches("] p").count() + text.matches("]  p").count();
        assert_eq!(listed, crate::NEAR_MISS_LIMIT, "{text}");
        assert!(text.contains("35 further candidates ranked below these"), "{text}");
    }

    #[test]
    fn files_with_identical_evidence_are_folded_rather_than_filling_the_list() {
        let mut candidates: Vec<Candidate> = (0..6)
            .map(|i| {
                ranked(
                    i,
                    &format!("C:\\Windows\\Temp\\{{guid{i}}}\\vcredist.exe"),
                    VM_PRIOR,
                    &[("executable_in_windows_temp", 3.0), ("executed_but_now_absent", 3.0)],
                )
            })
            .collect();
        candidates.push(ranked(
            9,
            "C:\\Users\\bob\\other.exe",
            VM_PRIOR,
            &[("persistence_service", 3.4)],
        ));
        let text = render(&report_with(candidates));

        assert!(text.contains("+ 5 other files scored identically on the same features"), "{text}");
        assert!(text.contains("other.exe"), "{text}");
        assert_eq!(text.matches("vcredist.exe").count(), 1, "{text}");
    }

    #[test]
    fn candidates_with_no_incriminating_evidence_are_never_listed() {
        let text = render(&report_with(vec![
            ranked(
                1,
                "C:\\Windows\\System32\\signed.exe",
                VM_PRIOR,
                &[("signed_by_microsoft", -4.0)],
            ),
            ranked(2, "C:\\Windows\\System32\\blank.exe", VM_PRIOR, &[]),
        ]));

        assert!(!text.contains("signed.exe"), "{text}");
        assert!(!text.contains("blank.exe"), "{text}");
        assert!(text.contains("net evidence of maliciousness at all"), "{text}");
        assert!(text.contains("no volume, of any size"), "{text}");
        assert!(!text.contains("STRONGEST CANDIDATES"), "an empty ranking gets no heading: {text}");
    }

    #[test]
    fn a_volume_with_no_candidates_points_at_coverage_rather_than_safety() {
        let text = render(&report_with(vec![]));
        assert!(text.contains("No candidates were formed at all"), "{text}");
        assert!(text.contains("unreadable volume"), "{text}");
    }

    #[test]
    fn a_findings_list_scores_the_strongest_thing_it_left_out() {
        let mut runner_up = weak_candidate();
        runner_up.evidence = vec![Evidence::new("persistence_service", 9.1, "runner-up")];
        let text = render(&report_with(vec![strong_candidate(), runner_up]));

        assert!(text.contains("FINDINGS"), "{text}");
        assert!(text.contains("The strongest of them scored 0.48"), "{text}");
        assert!(!text.contains("setup.exe"), "runners-up are counted, not named: {text}");
    }

    #[test]
    fn the_negative_result_warns_that_absence_is_ambiguous() {
        let text = render(&report_with(vec![weak_candidate()]));
        assert!(text.contains("wiped looks the same as a machine that was never infected"));
    }

    #[test]
    fn below_threshold_candidates_are_counted_not_listed() {
        let mut candidates = vec![strong_candidate()];
        for i in 0..5 {
            let mut c = weak_candidate();
            c.id = CandidateId(10 + i);
            c.path = NormalizedPath::parse(&format!("C:\\Users\\bob\\innocent{i}.exe"));
            candidates.push(c);
        }
        let text = render(&report_with(candidates));

        assert!(text.contains("5 further candidates scored below the threshold"));
        assert!(!text.contains("innocent0.exe"), "below-threshold files must not be named");
    }

    #[test]
    fn a_single_family_finding_is_flagged_as_a_lead() {
        let mut c = strong_candidate();
        c.observations.clear();
        c.observe(mm_core::Observation::about_path(
            ArtifactSource::Amcache,
            NormalizedPath::parse("C:\\Users\\bob\\x.exe").unwrap(),
            mm_core::ObservationKind::HashRecovered,
        ));
        let text = render(&report_with(vec![c]));
        assert!(text.contains("single artifact family"));

        assert!(!render(&report_with(vec![strong_candidate()])).contains("single artifact family"));
    }

    fn downloaded(zone: mm_core::UrlZone, host: Option<&str>, referrer: Option<&str>) -> Candidate {
        let mut c = strong_candidate();
        c.observe(mm_core::Observation::about_path(
            ArtifactSource::ZoneIdentifier,
            NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe").unwrap(),
            ObservationKind::DownloadedFrom {
                zone,
                host_url: host.map(str::to_string),
                referrer_url: referrer.map(str::to_string),
            },
        ));
        c
    }

    #[test]
    fn where_the_file_came_from_is_printed() {
        let text = render(&report_with(vec![downloaded(
            mm_core::UrlZone::Internet,
            Some("https://cdn.evil.invalid/p/payload.exe"),
            Some("https://forum.invalid/thread/91"),
        )]));
        assert!(text.contains("origin"));
        assert!(text.contains("internet zone"));
        assert!(text.contains("https://cdn.evil.invalid/p/payload.exe"));
        assert!(text.contains("https://forum.invalid/thread/91"));
    }

    #[test]
    fn the_url_is_printed_even_when_the_zone_scores_nothing() {
        let mut c =
            downloaded(mm_core::UrlZone::LocalMachine, Some("http://10.0.0.7/share/x.exe"), None);
        c.evidence.retain(|e| e.feature != "download_origin_recorded");
        let text = render(&report_with(vec![c]));
        assert!(text.contains("http://10.0.0.7/share/x.exe"), "{text}");
        assert!(text.contains("local machine zone"));
    }

    #[test]
    fn a_file_with_no_mark_of_the_web_gets_no_origin_block() {
        assert!(!render(&report_with(vec![strong_candidate()])).contains("origin"));
    }

    #[test]
    fn a_stream_with_a_zone_but_no_urls_says_so_rather_than_showing_a_gap() {
        let text = render(&report_with(vec![downloaded(mm_core::UrlZone::Internet, None, None)]));
        assert!(text.contains("no URL was recorded"));
    }

    #[test]
    fn a_hostile_url_is_wrapped_whole_rather_than_overflowing_or_being_cut() {
        let url = format!("https://a.invalid/{}", "x".repeat(240));
        let text =
            render(&report_with(vec![downloaded(mm_core::UrlZone::Untrusted, Some(&url), None)]));

        for line in text.lines() {
            assert!(line.chars().count() <= WIDTH + 2, "line too long: {line}");
        }
        let rejoined: String = text.lines().map(|l| l.trim()).collect::<Vec<_>>().concat();
        assert!(rejoined.contains(&url), "the URL was mangled or truncated");
    }

    #[test]
    fn uncalibrated_weights_are_disclosed() {
        let text = render(&report_with(vec![strong_candidate()]));
        assert!(text.contains("EXPERT-ESTIMATED"));
        assert!(text.contains("not as a\nmeasured frequency"));
    }

    #[test]
    fn coverage_reports_what_was_missing_too() {
        let text = render(&report_with(vec![strong_candidate()]));
        assert!(text.contains("Amcache"));
        assert!(text.contains("120 observations"));
        assert!(text.contains("Prefetch"));
        assert!(text.contains("not present on this machine"));
        assert!(text.contains("437 221"));
    }

    #[test]
    fn an_unverified_recovery_is_labelled_before_the_hash_is_shown() {
        let mut c = strong_candidate();
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 4096,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Unverified {
                basis: "carved from MFT record 84215, whose clusters are still marked free in \
                        $Bitmap"
                    .into(),
            },
        };
        let text = render(&report_with(vec![c]));
        assert!(text.contains("UNVERIFIED"), "{text}");
        assert!(text.contains("reconstructed from"), "{text}");
        assert!(text.contains("84215"), "{text}");
        assert!(text.find("UNVERIFIED") < text.find("sha256"), "{text}");
    }

    fn withheld_candidate(recovery: Recovery) -> Candidate {
        let mut c = strong_candidate();
        let bytes = FileHash::compute(b"payload");
        c.acquired_hash = Some(bytes.clone());
        c.hash = bytes;
        c.acquisition = Acquisition::Withheld { via: ArtifactSource::Mft, size: 24_064, recovery };
        c
    }

    #[test]
    fn a_withheld_sample_keeps_its_identity_and_points_at_no_file() {
        let text = render(&report_with(vec![withheld_candidate(Recovery::Intact)]));

        assert!(text.contains("WITHHELD"), "{text}");
        assert!(text.contains("recovered from $MFT"), "{text}");
        assert!(text.contains("24 064 bytes"), "{text}");
        assert!(text.contains("--no-samples"), "{text}");

        let bytes = FileHash::compute(b"payload");
        assert!(text.contains(&bytes.sha256_hex().unwrap()), "{text}");
        assert!(text.contains(&bytes.sha1_hex().unwrap()), "{text}");
        assert!(text.contains(&bytes.md5_hex().unwrap()), "{text}");

        assert!(text.contains("computed from the bytes read above"), "{text}");
        assert!(!text.contains("saved above"), "{text}");

        assert!(!text.contains("NOT ATTEMPTED"), "{text}");
        assert!(!text.contains("acquisition failed"), "{text}");
        assert!(!text.contains("NO BYTES"), "{text}");
        assert!(!text.contains("sample/C001.bin"), "{text}");
        assert!(!text.contains("C001.bin"), "{text}");

        assert!(text.contains(r"C:\Users\bob\AppData\Roaming\svchost.exe"), "{text}");
    }

    #[test]
    fn a_withheld_recovery_keeps_its_caveat_and_never_mentions_a_saved_copy() {
        for (recovery, word) in [
            (Recovery::Confirmed { against: "Amcache".into() }, "VERIFIED"),
            (
                Recovery::Unverified {
                    basis: "carved from MFT record 84215, whose clusters are still marked free"
                        .into(),
                },
                "UNVERIFIED",
            ),
            (
                Recovery::Partial {
                    detail: "$Bitmap shows 3 of its 4 clusters have been reallocated".into(),
                },
                "PARTIAL",
            ),
        ] {
            let text = render(&report_with(vec![withheld_candidate(recovery)]));
            assert!(text.contains(word), "{word} missing:\n{text}");
            assert!(text.contains("WITHHELD"), "{text}");
            assert!(!text.contains("saved above"), "{word}:\n{text}");
            assert!(!text.contains("in the case directory"), "{word}:\n{text}");
            for line in text.lines() {
                assert!(line.chars().count() <= 80, "{} columns: {line:?}", line.chars().count());
            }
        }
    }

    #[test]
    fn a_contradicted_withheld_carve_never_offers_a_copy_to_recognise() {
        let mut c = withheld_candidate(Recovery::Partial {
            detail: "$Bitmap shows 3 of its 4 clusters have been reallocated".into(),
        });
        c.acquired_hash = Some(FileHash::compute(b"other file's clusters"));

        let text = render(&report_with(vec![c]));
        assert!(text.contains("of the bytes read above"), "{text}");
        assert!(!text.contains("saved above"), "{text}");
        assert!(!text.contains("case directory"), "{text}");
        assert!(
            text.contains(&FileHash::compute(b"other file's clusters").sha256_hex().unwrap()),
            "{text}"
        );
        assert!(text.contains("NOT this file"), "{text}");
        for line in text.lines() {
            assert!(line.chars().count() <= 80, "{} columns: {line:?}", line.chars().count());
        }
    }

    #[test]
    fn the_console_says_withheld_rather_than_naming_a_file_that_is_not_there() {
        let report = report_with(vec![withheld_candidate(Recovery::Intact)]);
        let text = console(&report);
        assert!(text.contains("WITHHELD (--no-samples)"), "{text}");
        assert!(text.contains("of the bytes read (not saved)"), "{text}");
        assert!(!text.contains(".bin"), "{text}");
        assert!(!text.contains("NO BYTES"), "{text}");
    }

    #[test]
    fn a_partial_recovery_says_it_is_not_the_sample() {
        let mut c = strong_candidate();
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 4096,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Partial {
                detail: "$Bitmap shows 3 of its 4 clusters have been reallocated".into(),
            },
        };
        let text = render(&report_with(vec![c]));
        assert!(text.contains("PARTIAL"), "{text}");
        assert!(text.contains("NOT the sample"), "{text}");
        assert!(text.contains("reallocated"), "{text}");
    }

    #[test]
    fn a_confirmed_recovery_names_the_artifact_that_confirmed_it() {
        let text = render(&report_with(vec![strong_candidate()]));
        assert!(text.contains("VERIFIED — hash matches the one Amcache recorded"), "{text}");
        assert!(text.contains("recovered from Defender quarantine"), "{text}");
    }

    #[test]
    fn an_intact_read_claims_nothing_about_verification() {
        let mut c = strong_candidate();
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 4096,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Intact,
        };
        let text = render(&report_with(vec![c]));
        assert!(text.contains("recovered from $MFT"), "{text}");
        assert!(!text.contains("VERIFIED"), "{text}");
        assert!(!text.contains("UNVERIFIED"), "{text}");
    }

    #[test]
    fn the_recovery_caveats_fit_an_eighty_column_console() {
        let long = "carved 172032 bytes from MFT record 84215, but $Bitmap shows 3 of its 42 \
                    clusters have been reallocated since the file was deleted — that much of \
                    these bytes belongs to another file. Treat this as fragments, not as the \
                    sample";
        for recovery in [
            Recovery::Confirmed { against: "Defender quarantine".into() },
            Recovery::Unverified { basis: long.into() },
            Recovery::Partial { detail: long.into() },
        ] {
            let mut c = strong_candidate();
            c.acquisition = Acquisition::Bytes {
                via: ArtifactSource::Mft,
                size: 172_032,
                saved_as: "sample/C001.bin".into(),
                recovery,
            };
            for line in render(&report_with(vec![c])).lines() {
                assert!(line.chars().count() <= 80, "{} columns: {line:?}", line.chars().count());
            }
        }
    }

    #[test]
    fn a_thin_baseline_is_called_out() {
        let mut cov = coverage();
        cov.baseline_usable = false;
        let r = Report::new("0.1.0", "WinRE", target(), vec![strong_candidate()], cov, false);
        assert!(render(&r).contains("machine-relative scoring"));
    }

    #[test]
    fn a_candidate_with_no_hash_says_so_rather_than_showing_nothing() {
        let mut c = strong_candidate();
        c.hash = FileHash::default();
        c.acquisition = Acquisition::Failed { reason: "clusters overwritten".into() };
        let text = render(&report_with(vec![c]));
        assert!(text.contains("hash     UNKNOWN"), "{text}");
        assert!(text.contains("clusters overwritten"));
    }

    #[test]
    fn a_candidate_whose_acquisition_never_ran_says_so() {
        let mut c = strong_candidate();
        c.hash = FileHash::default();
        c.acquisition = Acquisition::NotAttempted;
        let text = render(&report_with(vec![c]));
        assert!(text.contains("NOT ATTEMPTED"), "{text}");
        assert!(text.contains("not about the file"), "{text}");
    }

    #[test]
    fn a_hash_says_whether_any_bytes_backed_it() {
        let mut recovered = strong_candidate();
        recovered.record_acquired_hash(&FileHash::compute(b"payload"), true);
        recovered.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 7,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Intact,
        };
        let text = render(&report_with(vec![recovered]));
        assert!(text.contains("computed from the bytes saved above"), "{text}");

        let mut claimed = strong_candidate();
        claimed.hash = FileHash::compute(b"payload");
        claimed.acquisition = Acquisition::HashOnly { via: ArtifactSource::Amcache };
        let text = render(&report_with(vec![claimed]));
        assert!(text.contains("NOT verified against any bytes"), "{text}");
    }

    #[test]
    fn an_artifacts_claim_is_never_printed_under_the_computed_heading() {
        let stale = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut c = strong_candidate();
        c.observations.push(
            Observation::about_path(
                ArtifactSource::Amcache,
                NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe").unwrap(),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(stale).unwrap()),
        );
        c.hash = FileHash::from_sha1_hex(stale).unwrap();
        let bytes = FileHash::compute(b"the bytes on the volume now");
        c.record_acquired_hash(&bytes, true);
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 27,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Intact,
        };

        let text = render(&report_with(vec![c]));

        assert!(text.contains("computed from the bytes saved above"), "{text}");
        assert!(text.contains(&bytes.sha1_hex().unwrap()), "{text}");
        assert!(text.contains(&bytes.sha256_hex().unwrap()), "{text}");
        assert!(text.contains("CHANGED"), "{text}");
        assert!(text.contains(stale), "{text}");
        assert!(text.contains("was replaced or updated after Amcache"), "{text}");
        assert!(text.contains("5.5%"), "{text}");
    }

    #[test]
    fn an_agreeing_artifact_hash_is_stated_as_a_match() {
        let bytes = FileHash::compute(b"payload");
        let mut c = strong_candidate();
        c.observations.push(
            Observation::about_path(
                ArtifactSource::Amcache,
                NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe").unwrap(),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(&bytes.sha1_hex().unwrap()).unwrap()),
        );
        c.record_acquired_hash(&bytes, true);
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 7,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Intact,
        };
        let text = render(&report_with(vec![c]));
        assert!(text.contains("matches  the SHA1 Amcache recorded"), "{text}");
        assert!(!text.contains("CHANGED"), "{text}");
    }

    #[test]
    fn the_digest_of_contradicted_fragments_is_labelled_as_such() {
        let recorded = FileHash::from_sha1_hex(&"bc".repeat(20)).unwrap();
        let mut c = strong_candidate();
        c.observations.push(
            Observation::about_path(
                ArtifactSource::Amcache,
                NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe").unwrap(),
                ObservationKind::HashRecovered,
            )
            .with_hash(recorded.clone()),
        );
        c.hash = recorded.clone();
        let fragments = FileHash::compute(b"half of another file");
        c.record_acquired_hash(&fragments, false);
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 20,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Partial { detail: "clusters reallocated".into() },
        };

        let text = render(&report_with(vec![c]));

        assert!(text.contains("are NOT this file"), "{text}");
        assert!(text.contains(&fragments.sha256_hex().unwrap()), "{text}");
        assert!(text.contains("as Amcache recorded them for this file"), "{text}");
        assert!(text.contains(&recorded.sha1_hex().unwrap()), "{text}");
    }

    #[test]
    fn digests_with_no_recorded_provenance_are_not_given_one() {
        let mut c = strong_candidate();
        c.hash = FileHash::compute(b"payload");
        c.acquired_hash = None;
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 7,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Intact,
        };
        let text = render(&report_with(vec![c]));
        assert!(text.contains("PROVENANCE NOT RECORDED"), "{text}");
        assert!(!text.contains("computed from the bytes saved above"), "{text}");
    }

    #[test]
    fn an_acquired_sample_is_anchored_to_the_case_directory() {
        let mut c = strong_candidate();
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 7,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Intact,
        };
        let mut r = report_with(vec![c]);
        r.set_case_directory(r"E:\case");
        let text = render(&r);
        assert!(text.contains(r"E:\case\sample\C001.bin"), "{text}");
    }

    #[test]
    fn a_failed_stage_changes_what_nothing_found_means() {
        let mut cov = coverage();
        cov.record_timed(
            "$MFT",
            CoverageStatus::Failed { reason: "device I/O error at cluster 1449984".into() },
            12.6,
        );
        let r = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let text = render(&r);
        assert!(text.contains("COULD NOT LOOK EVERYWHERE"), "{text}");
        assert!(text.contains("NOT a clean bill of health"), "{text}");
        assert!(
            text.find("device I/O error").unwrap() < text.find("WHAT WAS READ").unwrap(),
            "{text}"
        );
        assert!(!text.contains("This is a real result rather than a failure"), "{text}");
    }

    #[test]
    fn a_clean_run_still_says_the_negative_result_is_real() {
        let r = Report::new("0.1.0", "WinRE", target(), vec![], coverage(), false);
        let text = render(&r);
        assert!(text.contains("This is a real result rather than a failure"), "{text}");
        assert!(!text.contains("COULD NOT LOOK EVERYWHERE"), "{text}");
    }

    #[test]
    fn a_volume_that_was_not_examined_is_not_a_clean_bill_of_health() {
        let mut cov = coverage();
        cov.other_volumes.push(OtherVolume {
            volume: "W:".into(),
            identified_as: Some(
                "MBR disk signature 0x1a2b3c4d, partition at offset 1048576".into(),
            ),
            observations: 3,
            paths: vec![ForeignPath {
                path: r"W:\TRASH\Downloads\svch0st.exe".into(),
                source: "ShimCache".into(),
                claim: "executed".into(),
            }],
        });
        let r = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let text = render(&r);

        assert!(!text.contains("This is a real result rather than a failure"), "{text}");
        assert!(text.contains("RECORDED ON A VOLUME THIS RUN DID NOT EXAMINE"), "{text}");
        assert!(text.contains("W:"), "{text}");
        assert!(text.contains("MBR disk signature"), "{text}");
        assert!(text.contains("0x1a2b3c4d"), "{text}");
        assert!(text.contains(r"W:\TRASH\Downloads\svch0st.exe"), "{text}");
        assert!(text.contains("ShimCache"), "{text}");
        assert!(
            text.find("a different disk").unwrap()
                < text.find("RECORDED ON A VOLUME THIS RUN DID NOT EXAMINE").unwrap(),
            "{text}"
        );
    }

    #[test]
    fn an_unmapped_letter_says_the_mapping_is_not_known() {
        let mut cov = coverage();
        cov.other_volumes.push(OtherVolume {
            volume: "E:".into(),
            identified_as: None,
            observations: 1,
            paths: vec![ForeignPath {
                path: r"E:\setup.exe".into(),
                source: "UserAssist".into(),
                claim: "executed".into(),
            }],
        });
        let r = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let text = render(&r);
        assert!(text.contains("not recorded in this machine's MountedDevices"), "{text}");
        assert!(text.contains("removable or optical"), "{text}");
    }

    #[test]
    fn a_one_disk_machine_gains_nothing() {
        let r = Report::new("0.1.0", "WinRE", target(), vec![], coverage(), false);
        let text = render(&r);
        assert!(!text.contains("RECORDED ON A VOLUME"), "{text}");
        assert!(text.contains("This is a real result rather than a failure"), "{text}");
    }

    #[test]
    fn the_lead_lines_fit_an_eighty_column_console() {
        let mut cov = coverage();
        cov.other_volumes.push(OtherVolume {
            volume: "W:".into(),
            identified_as: Some("volume ID {7c8d9e0f-1a2b-4c3d-8394-a5b6c7d8e9fa}".into()),
            observations: 1,
            paths: vec![ForeignPath {
                path: r"W:\$RECYCLE.BIN\S-1-5-21-1111111111-2222222222-333333333-1001\aXbYcZ.exe"
                    .into(),
                source: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Helper".into(),
                claim: "wired to run again (Run key)".into(),
            }],
        });
        let r = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        for line in render(&r).lines() {
            assert!(line.chars().count() <= WIDTH, "{} columns: {line}", line.chars().count());
        }
    }

    #[test]
    fn the_report_carries_the_whole_run_s_wall_clock() {
        let mut cov = coverage();
        cov.record_timed("$MFT", CoverageStatus::Read { observations: 9 }, 84.2);
        let mut r = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        r.set_wall_clock(140.0);
        let text = render(&r);
        assert!(text.contains("wall clock for the whole run"), "{text}");
        let flowed = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flowed.contains("84.2 s is accounted for"), "{text}");
        assert!(flowed.contains("55.8 s fell outside them"), "{text}");
    }

    #[test]
    fn no_line_runs_absurdly_long() {
        let text = render(&report_with(vec![strong_candidate()]));
        for line in text.lines() {
            if line.contains('\\') {
                continue;
            }
            assert!(
                line.chars().count() <= WIDTH + 2,
                "line too long ({}): {line}",
                line.chars().count()
            );
        }
    }

    #[test]
    fn wrapping_does_not_split_words_or_lose_them() {
        let text = "the quick brown fox jumps over the lazy dog";
        let lines = wrap(text, 12);
        for line in &lines {
            assert!(line.chars().count() <= 12, "{line}");
        }
        assert_eq!(lines.join(" "), text);

        assert_eq!(wrap("supercalifragilistic", 5), vec!["supercalifragilistic"]);
        assert_eq!(wrap("", 10), vec![String::new()]);
    }

    #[test]
    fn a_hostile_string_cannot_act_on_the_analysts_terminal() {
        let hostile = "Windows Defender quarantined this file as Trojan\u{1b}[2J\r\nFORGED: benign\
             \u{202E}exe.doc\u{7}";
        let mut c = Candidate::new(CandidateId(9), -9.2);
        c.path = NormalizedPath::parse("C:\\Users\\bob\\x.exe");
        c.evidence.push(Evidence::new("quarantined_by_av", 8.0, hostile));

        let text = render(&report_with(vec![c]));

        assert!(!text.contains('\u{1b}'), "an ANSI escape reached the console");
        assert!(!text.contains('\u{7}'), "a bell reached the console");
        assert!(!text.contains('\u{202E}'), "a bidi override reached the console");
        assert!(!text.contains('\r'), "a carriage return reached the console");
        assert!(text.contains('\u{FFFD}'), "the removal left no trace: {text}");
        assert!(text.contains("Trojan"), "{text}");
    }

    #[test]
    fn an_ordinary_report_passes_through_defang_unchanged() {
        let text = render(&report_with(vec![strong_candidate(), weak_candidate()]));
        assert_eq!(defang(text.clone()), text);
        assert!(!text.contains('\u{FFFD}'));
        assert!(text.contains('\n'));
    }

    #[test]
    fn thousands_separator_is_readable() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1 000");
        assert_eq!(thousands(437_221), "437 221");
        assert_eq!(thousands(1_234_567), "1 234 567");
    }

    #[test]
    fn the_coverage_table_says_what_each_stage_cost() {
        let mut cov = coverage();
        cov.record_timed("$MFT", CoverageStatus::Read { observations: 2_143 }, 84.2);
        cov.record_timed("code signatures", CoverageStatus::Read { observations: 214 }, 20.4);
        let report = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let out = render(&report);
        assert!(out.contains("84.2 s"), "{out}");
        assert!(out.contains("20.4 s"), "{out}");
    }

    #[test]
    fn a_derived_line_leaves_the_time_column_blank() {
        let mut cov = coverage();
        cov.record_timed("$MFT", CoverageStatus::Read { observations: 2_143 }, 84.2);
        cov.record("executables installed out of band", CoverageStatus::Read { observations: 861 });
        let report = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let out = render(&report);
        let lines: Vec<&str> = out.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains("executables installed out of band"))
            .expect("the line is rendered");
        assert!(!lines[at].contains(" s"), "{}", lines[at]);
        assert!(lines[at + 1].contains("861 observations"), "{}", lines[at + 1]);
        assert!(!lines[at + 1].contains(" s"), "{}", lines[at + 1]);
    }

    #[test]
    fn the_timing_summary_names_the_bottleneck() {
        let mut cov = coverage();
        cov.record_timed("$MFT", CoverageStatus::Read { observations: 2_143 }, 84.0);
        cov.record_timed("code signatures", CoverageStatus::Read { observations: 214 }, 16.0);
        let report = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let out = render(&report);
        let summary = out
            .lines()
            .find(|l| l.contains("of measured work"))
            .expect("a timing summary")
            .to_string();
        assert!(summary.contains("$MFT"), "{summary}");
        assert!(summary.contains("84%"), "{summary}");
    }

    #[test]
    fn timing_never_appears_before_the_verdict() {
        let mut cov = coverage();
        cov.record_timed("$MFT", CoverageStatus::Read { observations: 2_143 }, 84.0);
        let report = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let out = render(&report);
        let verdict = out.find("NOTHING").expect("a verdict");
        let timing = out.find("of measured work").expect("a timing summary");
        assert!(verdict < timing, "timing at {timing} came before the verdict at {verdict}");
    }

    #[test]
    fn an_untimed_report_gains_no_timing_line() {
        let report = Report::new("0.1.0", "WinRE", target(), vec![], coverage(), false);
        assert!(!render(&report).contains("of measured work"));
    }

    #[test]
    fn a_long_coverage_line_wraps_instead_of_running_off_the_console() {
        let mut cov = coverage();
        cov.record_timed(
            "incident window",
            CoverageStatus::NotAvailableHere {
                reason: "no candidate rose above the reporting threshold (strongest 0.15), so \
                         there was no burst to cluster around"
                    .into(),
            },
            0.001,
        );
        let report = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let out = render(&report);
        for line in out.lines() {
            assert!(line.chars().count() <= WIDTH, "{} columns: {line}", line.chars().count());
        }
        let head =
            out.lines().find(|l| l.contains("incident window")).expect("the line is rendered");
        assert!(head.contains("0.001 s"), "{head}");
    }

    #[test]
    fn a_long_coverage_label_wraps_and_keeps_its_timing_on_the_first_line() {
        let mut cov = coverage();
        cov.record_timed(
            "incident window (2026-05-30 13:49:25Z - 2026-05-30 13:49:25Z observed, anchored on 1 candidate; widened to 2026-05-30 13:39:25Z - 2026-05-30 13:59:25Z by the 10-minute burst gap; 12 candidates created in it, and 14 not credited: every executable known in 4 directories was created in it too, so the window is not what put them there)",
            CoverageStatus::Read { observations: 12 },
            0.002,
        );
        let report = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let out = render(&report);
        for line in out.lines() {
            assert!(line.chars().count() <= WIDTH, "{} columns: {line}", line.chars().count());
        }
        let head =
            out.lines().find(|l| l.contains("incident window")).expect("the line is rendered");
        assert!(head.contains("0.002 s"), "{head}");
        assert!(out.contains("there)"), "{out}");
    }

    #[test]
    fn the_timing_summary_fits_the_console() {
        let mut cov = coverage();
        cov.record_timed(
            "catalog store (4719 catalogs, 175029 members)",
            CoverageStatus::Read { observations: 175_029 },
            24.8,
        );
        cov.record_timed("$MFT", CoverageStatus::Read { observations: 2 }, 14.8);
        let report = Report::new("0.1.0", "WinRE", target(), vec![], cov, false);
        let out = render(&report);
        for line in out.lines() {
            assert!(line.chars().count() <= WIDTH, "{} columns: {line}", line.chars().count());
        }
        let summary = out.lines().find(|l| l.contains("of measured work")).expect("a summary");
        assert!(summary.contains("catalog store"), "{summary}");
        assert!(!summary.contains("175029"), "the parenthetical belongs in the table: {summary}");
    }

    #[test]
    fn a_sub_second_stage_reports_a_real_number() {
        assert_eq!(format_seconds(0.0004), "0.000 s");
        assert_eq!(format_seconds(0.043), "0.043 s");
        assert_eq!(format_seconds(0.42), "0.42 s");
        assert_eq!(format_seconds(6.9), "6.90 s");
        assert_eq!(format_seconds(20.44), "20.4 s");
        assert_eq!(format_seconds(624.0), "10m24s");
    }

    fn every_console_state() -> Vec<(&'static str, Report)> {
        let mut states: Vec<(&'static str, Report)> = Vec::new();

        let mut found = report_with(vec![strong_candidate(), weak_candidate()]);
        found.set_case_directory(r"D:\case-03");
        found.set_wall_clock(30.7);
        states.push(("two findings", found));

        states.push(("one finding", report_with(vec![strong_candidate()])));

        let mut many: Vec<Candidate> = Vec::new();
        for i in 0..40 {
            let mut c = strong_candidate();
            c.id = CandidateId(i);
            many.push(c);
        }
        states.push(("forty findings", report_with(many)));
        states.push(("nothing found", report_with(vec![weak_candidate()])));
        states.push(("no candidates at all", report_with(vec![])));

        let mut failed = report_with(vec![weak_candidate()]);
        failed.coverage.record(
            "$MFT",
            CoverageStatus::Failed { reason: "device I/O error at cluster 1449984".into() },
        );
        states.push(("could not look", failed));

        let mut unmeasured = report_with(vec![strong_candidate()]);
        unmeasured.set_enumeration(mm_core::Enumeration::not_attempted());
        states.push(("no base rate", unmeasured));

        for acquisition in [
            Acquisition::NotAttempted,
            Acquisition::Failed { reason: "clusters reallocated since deletion".into() },
            Acquisition::HashOnly { via: ArtifactSource::Amcache },
            Acquisition::Bytes {
                via: ArtifactSource::Mft,
                size: 61_440,
                saved_as: "sample/C001.bin".into(),
                recovery: Recovery::Partial { detail: "3 of 15 clusters reallocated".into() },
            },
        ] {
            let mut c = strong_candidate();
            c.acquisition = acquisition;
            let mut report = report_with(vec![c]);
            report.set_case_directory(r"D:\case-03");
            states.push(("an acquisition state", report));
        }

        states.push(("came close", volume(2_144, 7.3)));
        states.push(("came close and could not look", volume_that_could_not_look(2_144, 7.3)));

        let mut other = report_with(vec![weak_candidate()]);
        other.coverage.other_volumes.push(OtherVolume {
            volume: "W:".into(),
            identified_as: None,
            observations: 3,
            paths: vec![ForeignPath {
                path: "W:\\tools\\x.exe".into(),
                source: "UserAssist".into(),
                claim: "executed".into(),
            }],
        });
        states.push(("a volume this run did not open", other));

        states
    }

    #[test]
    fn the_console_block_never_emits_an_escape_byte() {
        for (name, report) in every_console_state() {
            let block = console(&report);
            assert!(!block.contains('\u{1b}'), "{name} put an escape byte on the console");
            assert!(
                block.chars().all(|c| !c.is_control() || c == '\n' || c == '\t'),
                "{name} put a control character on the console"
            );
        }
    }

    #[test]
    fn only_a_path_is_allowed_past_eighty_columns() {
        for (name, report) in every_console_state() {
            let paths: Vec<String> = report
                .candidates
                .iter()
                .map(|c| c.label())
                .chain(report.case_directory.clone())
                .collect();
            for line in console(&report).lines() {
                if line.chars().count() <= WIDTH {
                    continue;
                }
                assert!(
                    paths.iter().any(|p| line.contains(p.as_str())),
                    "{name} wrapped on an 80-column console: {line:?}"
                );
            }
        }
    }

    #[test]
    fn the_console_verdict_is_the_report_s_own_verdict() {
        for (name, report) in every_console_state() {
            let block = console(&report);
            let full = render(&report);
            for line in headline(&report).lines() {
                assert!(block.contains(line), "{name}: the console omits {line:?}");
                assert!(full.contains(line), "{name}: the report omits {line:?}");
            }
        }
    }

    #[test]
    fn two_findings_are_unmissable_and_listed_with_their_samples() {
        let mut report = report_with(vec![strong_candidate(), weak_candidate()]);
        report.set_case_directory(r"D:\case-03");
        let block = console(&report);

        let head: String = block.lines().take(6).collect::<Vec<_>>().join("\n");
        assert!(head.contains("***"), "no marker in the first lines:\n{block}");
        assert!(head.contains("FINDINGS"), "no verdict in the first lines:\n{block}");

        assert!(block.contains("[1]"), "{block}");
        assert!(block.contains("p = 1.00"), "{block}");
        assert!(
            block.contains("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe"),
            "the finding's path is not listed:\n{block}"
        );
        assert!(
            block.contains("D:\\case-03\\sample\\C001.bin"),
            "the console does not say where the sample was written:\n{block}"
        );
        assert!(
            block.contains("Windows Defender quarantined this file"),
            "the console dropped the evidence entirely:\n{block}"
        );
    }

    #[test]
    fn a_finding_with_no_bytes_never_names_a_file_in_the_case_directory() {
        for acquisition in [
            Acquisition::NotAttempted,
            Acquisition::Failed { reason: "clusters reallocated since deletion".into() },
            Acquisition::HashOnly { via: ArtifactSource::Amcache },
        ] {
            let mut c = strong_candidate();
            c.acquisition = acquisition;
            let mut report = report_with(vec![c]);
            report.set_case_directory(r"D:\case-03");
            let block = console(&report);
            assert!(
                !block.contains("sample\\C001.bin") && !block.contains("sample/C001.bin"),
                "the console implies a sample file exists:\n{block}"
            );
            assert!(
                block.contains("NO BYTES") || block.contains("NOT ATTEMPTED"),
                "the console is silent about there being no bytes:\n{block}"
            );
        }
    }

    #[test]
    fn fragments_are_never_offered_as_the_sample() {
        let mut c = strong_candidate();
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 61_440,
            saved_as: "sample/C001.bin".into(),
            recovery: Recovery::Partial { detail: "3 of 15 clusters reallocated".into() },
        };
        let block = console(&report_with(vec![c]));
        assert!(block.contains("PARTIAL"), "{block}");
        assert!(block.contains("NOT THE SAMPLE"), "{block}");
    }

    #[test]
    fn no_digest_is_printed_without_its_provenance() {
        let mut hash_only = strong_candidate();
        hash_only.acquisition = Acquisition::HashOnly { via: ArtifactSource::Amcache };
        hash_only.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                NormalizedPath::parse("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe").unwrap(),
                mm_core::ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::compute(b"payload")),
        );
        let block = console(&report_with(vec![hash_only]));
        assert!(block.contains("Amcache recorded it"), "{block}");
        assert!(!block.contains("of the saved bytes"), "{block}");

        let mut acquired = strong_candidate();
        acquired.record_acquired_hash(&FileHash::compute(b"payload"), true);
        let block = console(&report_with(vec![acquired]));
        assert!(block.contains("of the saved bytes"), "{block}");
    }

    #[test]
    fn a_hash_that_disagrees_with_an_artifact_reaches_the_console() {
        let mut c = strong_candidate();
        c.record_acquired_hash(&FileHash::compute(b"payload"), true);
        c.hash_checks.push(mm_core::HashCheck {
            algorithm: "sha1".into(),
            recorded_by: "Amcache".into(),
            recorded: "3f2a91c4bd77e0155ab3c9e8d147f0b62c8ad934".into(),
            computed: "9c1f0b7d2e4a6538ff01b9c7d3e5a24680bd1f37".into(),
            agrees: false,
        });
        let block = console(&report_with(vec![c]));
        assert!(block.contains("CHANGED"), "the console hid a hash disagreement:\n{block}");
        assert!(block.contains("Amcache"), "{block}");
    }

    #[test]
    fn a_clean_run_and_a_run_that_could_not_look_read_differently() {
        let clean = console(&report_with(vec![weak_candidate()]));

        let mut broken_report = report_with(vec![weak_candidate()]);
        broken_report.coverage.record(
            "$MFT",
            CoverageStatus::Failed { reason: "device I/O error at cluster 1449984".into() },
        );
        let broken = console(&broken_report);

        assert_ne!(clean, broken);
        assert!(clean.contains("NOTHING FOUND"), "{clean}");
        assert!(!clean.contains("could NOT be read"), "{clean}");
        assert!(broken.contains("COULD NOT LOOK EVERYWHERE"), "{broken}");
        assert!(broken.contains("$MFT"), "the failed stage is not named:\n{broken}");
        assert!(broken.contains("!!!"), "{broken}");
        assert!(!clean.contains("!!!"), "{clean}");
    }

    #[test]
    fn all_four_negative_headings_reach_the_console_distinctly() {
        let clean = console(&report_with(vec![weak_candidate()]));

        let mut blind_report = report_with(vec![weak_candidate()]);
        blind_report.coverage.record(
            "$MFT",
            CoverageStatus::Failed { reason: "device I/O error at cluster 1449984".into() },
        );
        let blind = console(&blind_report);

        let close = console(&volume(2_144, 7.3));
        let both = console(&volume_that_could_not_look(2_144, 7.3));

        assert!(clean.contains("NOTHING FOUND"), "{clean}");
        assert!(!clean.contains("COULD NOT LOOK"), "{clean}");
        assert!(!clean.contains("CAME CLOSE"), "{clean}");

        assert!(
            blind.contains("NOTHING FOUND — BUT THIS RUN COULD NOT LOOK EVERYWHERE"),
            "{blind}"
        );
        assert!(!blind.contains("CAME CLOSE"), "{blind}");

        assert!(
            close.contains("NOTHING CLEARED THE THRESHOLD — ONE CANDIDATE CAME CLOSE"),
            "{close}"
        );
        assert!(!close.contains("COULD NOT LOOK"), "{close}");

        assert!(
            both.contains("!!!  NOTHING CLEARED THE THRESHOLD — ONE CANDIDATE CAME CLOSE,"),
            "{both}"
        );
        assert!(both.contains("\n       AND THIS RUN COULD NOT LOOK EVERYWHERE"), "{both}");
        assert_eq!(both.matches("!!!").count(), 1, "{both}");

        let all = [&clean, &blind, &close, &both];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "two arms of the lattice render identically");
            }
        }

        assert!(!clean.contains("!!!"), "{clean}");
        for qualified in [&blind, &close, &both] {
            assert!(qualified.contains("!!!"), "an unqualified marker:\n{qualified}");
        }
    }

    #[test]
    fn a_run_with_no_base_rate_quotes_no_probability_on_the_console() {
        let mut report = report_with(vec![strong_candidate()]);
        report.set_enumeration(mm_core::Enumeration::not_attempted());
        let block = console(&report);
        assert!(block.contains("COULD NOT ESTABLISH THE SIZE"), "{block}");
        assert!(!block.contains("p = "), "a probability was quoted anyway:\n{block}");
        assert!(!block.contains("FINDINGS"), "{block}");
    }

    #[test]
    fn every_state_says_where_the_full_report_is() {
        for (name, mut report) in every_console_state() {
            report.set_case_directory(r"D:\case-03");
            let block = console(&report);
            assert!(block.contains("report.txt"), "{name} does not name the report:\n{block}");
            assert!(
                block.contains(r"D:\case-03\report.txt"),
                "{name} does not give a path that can be typed:\n{block}"
            );
            assert!(block.contains("report.json"), "{name}:\n{block}");
        }
    }

    #[test]
    fn every_console_state_fits_inside_a_screen_buffer() {
        for (name, report) in every_console_state() {
            let lines = console(&report).lines().count();
            assert!(lines <= 120, "{name} renders {lines} lines on the console");
        }
    }

    #[test]
    fn a_run_with_forty_findings_still_fits_a_screen_buffer() {
        let (_, report) = every_console_state()
            .into_iter()
            .find(|(name, _)| *name == "forty findings")
            .expect("the forty-finding state");
        assert_eq!(report.reportable_count(), 40);

        let block = console(&report);
        assert!(block.contains("[6]"), "the sixth finding is not listed:\n{block}");
        assert!(!block.contains("[7]"), "the console listed more than six findings");
        assert!(
            block.contains("34 further findings"),
            "the console dropped thirty-four findings without saying so:\n{block}"
        );
        let lines = block.lines().count();
        assert!(lines <= 120, "forty findings render {lines} lines");
    }

    #[test]
    fn a_finding_on_the_console_still_says_what_the_machine_contributed() {
        let block = console(&report_with(vec![strong_candidate()]));
        assert!(block.contains("this evidence reaches 0.50"), "{block}");
        assert!(block.contains("this one holds"), "{block}");
    }
}
