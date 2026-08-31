use std::collections::{HashMap, HashSet};

use mm_core::{ArtifactSource, Candidate, Observation, ObservationKind, PersistenceKind};
use mm_score::weights::EvidenceSet;
use mm_score::zone::{self, Zone};
use mm_score::{Baseline, Weights};

const BASELINE_FEATURES: &[&str] = &[
    "name_unique_on_machine",
    "name_recurs_on_machine",
    "executable_rare_for_zone_on_this_machine",
    "lone_executable_among_documents",
];

const REPORTING_THRESHOLD: f64 = 0.5;

const SELF_FRAGMENTS: &[&str] =
    &["\\appdata\\local\\temp\\claude\\", "\\documents\\malmathic\\", "\\.claude\\projects\\"];

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: rescore <report.json> [--top N]");
    let mut top_n = 15usize;
    let rest: Vec<String> = args.collect();
    if let Some(i) = rest.iter().position(|a| a == "--top") {
        if let Some(n) = rest.get(i + 1).and_then(|n| n.parse().ok()) {
            top_n = n;
        }
    }
    let render = rest.iter().any(|a| a == "--render");
    let arrivals = rest
        .iter()
        .position(|a| a == "--arrivals")
        .and_then(|i| rest.get(i + 1))
        .map(|p| read_arrivals(p));
    let signatures = rest
        .iter()
        .position(|a| a == "--signatures")
        .and_then(|i| rest.get(i + 1))
        .map(|p| read_signatures(p));
    let startup = rest
        .iter()
        .position(|a| a == "--startup")
        .and_then(|i| rest.get(i + 1))
        .map(|p| read_startup(p));
    let zone_filter =
        rest.iter().position(|a| a == "--zone").and_then(|i| rest.get(i + 1)).cloned();
    let window = rest.iter().any(|a| a == "--window");
    let real_window = rest.iter().any(|a| a == "--real-window");
    let plants: Vec<(Plant, chrono::DateTime<chrono::Utc>)> = rest
        .iter()
        .enumerate()
        .filter(|(i, a)| *a == "--plant" && rest.len() > i + 1)
        .filter_map(|(i, _)| rest.get(i + 1))
        .map(|s| parse_plant(s))
        .collect();

    let exclude: Vec<String> = if rest.iter().any(|a| a == "--exclude-self") {
        SELF_FRAGMENTS.iter().map(|s| (*s).to_string()).collect()
    } else {
        rest.iter()
            .enumerate()
            .filter(|(i, a)| *a == "--exclude" && rest.len() > i + 1)
            .filter_map(|(i, _)| rest.get(i + 1).cloned())
            .map(|f| f.to_lowercase())
            .collect()
    };

    let text = std::fs::read_to_string(&path).expect("report must be readable");
    let value: serde_json::Value = serde_json::from_str(&text).expect("report must be JSON");
    let mut candidates: Vec<Candidate> =
        serde_json::from_value(value["candidates"].clone()).expect("candidates must deserialise");

    if !exclude.is_empty() {
        let before = candidates.len();
        candidates.retain(|c| {
            let Some(p) = &c.path else { return true };
            !exclude.iter().any(|f| p.key().contains(f.as_str()))
        });
        println!(
            "excluded: {} of {before} candidates matched {:?}",
            before - candidates.len(),
            exclude
        );
    }

    println!("== {path}");
    println!(
        "as written: {} candidates, prior {:.4}",
        candidates.len(),
        candidates[0].prior_log_odds
    );
    let before_max = candidates.iter().map(Candidate::probability).fold(0.0f64, f64::max);
    let before_over = candidates.iter().filter(|c| c.probability() >= REPORTING_THRESHOLD).count();
    println!(
        "as written: strongest p = {before_max:.4}, {before_over} at or over {REPORTING_THRESHOLD}"
    );

    let mut carried: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut stomped: HashSet<String> = HashSet::new();
    let mut old_score: HashMap<String, f64> = HashMap::new();
    for c in &candidates {
        let Some(p) = &c.path else { continue };
        for e in &c.evidence {
            if BASELINE_FEATURES.contains(&e.feature.as_str()) {
                carried
                    .entry(p.key().to_string())
                    .or_default()
                    .push((e.feature.clone(), e.detail.clone()));
            }
            if e.feature == "timestomped" {
                stomped.insert(p.key().to_string());
            }
        }
        old_score.insert(p.key().to_string(), c.probability());
    }

    let mut observations: Vec<Observation> =
        candidates.iter().flat_map(|c| c.observations.iter().cloned()).collect();
    let started_with = observations.len();

    let was_hijack = demote_com_hijacks(&mut observations);
    let promoted = promote_com_hijacks(&mut observations);
    let deferred = defer_ordinary_com_registrations(&mut observations);
    let dropped = drop_unreferenced_filesystem_observations(&mut observations, &stomped);
    reattach_deferred_com(&mut observations, deferred.clone());
    println!(
        "COM replay: {was_hijack} hijack claims demoted, {promoted} re-promoted, \
         {} registrations deferred, {dropped} filesystem observations dropped with them \
         ({started_with} observations in, {} out)",
        deferred.len(),
        observations.len()
    );

    if let Some(rows) = &arrivals {
        let (touched, created) = inject_arrivals(&mut observations, rows);
        println!(
            "arrivals replayed: {} rows, {touched} attached to candidates the report already \
             held, {created} new candidates the admission rule creates",
            rows.len()
        );
    }

    if let Some(rows) = &startup {
        let (attached, created) = inject_startup(&mut observations, rows);
        println!(
            "Startup folders replayed: {} entries, {attached} pointing at candidates the report              already held, {created} new candidates the Startup harvester creates",
            rows.len()
        );
    }

    if let Some(rows) = &signatures {
        let applied = inject_signatures(&mut observations, rows);
        println!(
            "signatures replayed: {} rows, {applied} attached to paths the report already held",
            rows.len()
        );
    }

    let mut planted_keys: Vec<(String, &'static str)> = Vec::new();
    for (plant, at) in &plants {
        let (p, obs) = plant_observations(plant, *at);
        println!(
            "planted: {} at {} — {} observation(s) into `{}`",
            plant.label,
            mm_core::filetime::format(*at),
            obs.len(),
            p.raw()
        );
        carried.entry(p.key().to_string()).or_default().push((
            "name_unique_on_machine".to_string(),
            "no other file on the volume has this name".to_string(),
        ));
        planted_keys.push((p.key().to_string(), plant.label));
        observations.extend(obs);
    }

    let weights = Weights::embedded();
    let mut rebuilt = mm_score::graph::build(observations, 0.0);
    let prior = prior_log_odds(rebuilt.len());
    println!("rebuilt: {} candidates, prior {prior:.4}", rebuilt.len());

    let thin = Baseline::from_completed_walk();
    assert!(!thin.is_usable());

    for c in &mut rebuilt {
        c.prior_log_odds = prior;
        let fresh = mm_score::extract(c, &thin, &weights);
        let mut set = EvidenceSet::new();
        for e in fresh {
            set.offer(&weights, &e.feature, e.detail, e.sources);
        }
        if let Some(p) = &c.path {
            for (feature, detail) in carried.get(p.key()).into_iter().flatten() {
                set.offer(&weights, feature, detail.clone(), vec![]);
            }
        }
        if window && has_creation_time(c) {
            set_window(&weights, &mut set);
        }
        c.evidence = set.into_evidence();
    }

    if real_window {
        let detection = mm_score::window::IncidentWindow::detect(&rebuilt, REPORTING_THRESHOLD);
        println!("\nreal incident window: {}", detection.describe());
        if let Some(w) = detection.window() {
            let mut paid = 0usize;
            for c in &mut rebuilt {
                let Some(when) = w.membership(c) else { continue };
                let mut set = EvidenceSet::new();
                for e in std::mem::take(&mut c.evidence) {
                    set.offer(&weights, &e.feature, e.detail, e.sources);
                }
                set.offer(
                    &weights,
                    "created_in_incident_window",
                    format!(
                        "created at {}, inside the incident window",
                        mm_core::filetime::format(when)
                    ),
                    vec![],
                );
                c.evidence = set.into_evidence();
                if c.evidence.iter().any(|e| e.feature == "created_in_incident_window") {
                    paid += 1;
                }
            }
            println!(
                "real incident window: {} member(s), {paid} of them actually collected the row \
                 (the rest already held the lifecycle group)",
                w.members()
            );
            let refused: std::collections::HashSet<mm_core::CandidateId> =
                w.explained_by_directory().iter().copied().collect();
            let mut credited: std::collections::BTreeMap<String, (usize, usize)> =
                std::collections::BTreeMap::new();
            let mut declined: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for c in &rebuilt {
                let Some(parent) = c.path.as_ref().and_then(|p| p.parent()) else { continue };
                if refused.contains(&c.id) {
                    *declined.entry(parent.to_string()).or_default() += 1;
                } else if w.membership(c).is_some() {
                    credited.entry(parent.to_string()).or_default().0 += 1;
                }
            }
            for c in &rebuilt {
                let Some(parent) = c.path.as_ref().and_then(|p| p.parent()) else { continue };
                if let Some(row) = credited.get_mut(parent) {
                    row.1 += 1;
                }
            }
            let mut rows: Vec<(String, (usize, usize))> = credited.into_iter().collect();
            rows.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
            for (parent, (n, total)) in rows.iter().take(15) {
                println!("    credited: {n:4} of {total:4} known here   {parent}");
            }
            let mut refused_rows: Vec<(String, usize)> = declined.into_iter().collect();
            refused_rows.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            for (parent, n) in &refused_rows {
                println!("    REFUSED:  {n:4} (the whole directory arrived with them)   {parent}");
            }
        }
    }

    rebuilt.sort_by(|a, b| b.logit().partial_cmp(&a.logit()).unwrap_or(std::cmp::Ordering::Equal));

    for (key, label) in &planted_keys {
        match rebuilt.iter().position(|c| c.path.as_ref().is_some_and(|p| p.key() == key)) {
            Some(i) => println!(
                "PLANT [{label}] scored {:.4}, rank {} of {}  [{}]",
                rebuilt[i].probability(),
                i + 1,
                rebuilt.len(),
                rebuilt[i]
                    .evidence
                    .iter()
                    .map(|e| format!("{}{:+.1}", e.feature, e.log_lr))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            None => {
                println!("PLANT [{label}] PRODUCED NO CANDIDATE — key `{key}` is not in the graph")
            }
        }
    }

    study(&rebuilt, &planted_keys);

    let over: Vec<&Candidate> =
        rebuilt.iter().filter(|c| c.probability() >= REPORTING_THRESHOLD).collect();
    println!(
        "rescored: strongest p = {:.4}, {} at or over {REPORTING_THRESHOLD}",
        rebuilt.first().map(|c| c.probability()).unwrap_or(0.0),
        over.len()
    );

    println!("\n-- top {top_n} after rescoring (was -> now) --");
    for c in rebuilt.iter().take(top_n) {
        let key =
            c.path.as_ref().map(|p| p.key().to_string()).unwrap_or_else(|| "<no path>".into());
        let was = old_score.get(&key).copied().unwrap_or(f64::NAN);
        println!(
            "{:.4}  (was {:>6.4})  {}  [{}]",
            c.probability(),
            was,
            c.path.as_ref().map(|p| p.raw()).unwrap_or("<no path>"),
            c.evidence
                .iter()
                .map(|e| format!("{}{:+.1}", e.feature, e.log_lr))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    let mut by_zone: HashMap<Zone, (usize, f64)> = HashMap::new();
    for c in &rebuilt {
        let Some(p) = &c.path else { continue };
        let entry = by_zone.entry(zone::classify(p)).or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 = entry.1.max(c.probability());
    }
    println!("\n-- candidates and strongest score per zone --");
    let mut zones: Vec<_> = by_zone.into_iter().collect();
    zones.sort_by_key(|(z, _)| *z);
    for (z, (n, worst)) in zones {
        println!("{:<22} {:>6}  strongest {:.4}", z.label(), n, worst);
    }

    if let Some(label) = &zone_filter {
        println!("\n-- every candidate in zone `{label}`, strongest first --");
        for c in rebuilt.iter() {
            let Some(p) = &c.path else { continue };
            if zone::classify(p).label() != label {
                continue;
            }
            println!(
                "{:.4}  {}  [{}]",
                c.probability(),
                p.raw(),
                c.evidence
                    .iter()
                    .map(|e| format!("{}{:+.1}", e.feature, e.log_lr))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
    }

    if render {
        println!("\n\n======== as the analyst reads it ========\n");
        let report = mm_report::Report::new(
            value["tool_version"].as_str().unwrap_or("?"),
            value["environment"].as_str().unwrap_or("?"),
            target_from(&value["target"]),
            rebuilt,
            coverage_from(&value["coverage"]),
            value["weights_calibrated"].as_bool().unwrap_or(false),
        );
        print!("{}", mm_report::text::render(&report));
    }
}

struct Arrival {
    path: mm_core::NormalizedPath,
    kind: mm_core::OutOfBandArrival,
    signature: Option<mm_core::SignatureStatus>,
    present: bool,
}

fn read_arrivals(path: &str) -> Vec<Arrival> {
    let text = std::fs::read_to_string(path).expect("arrivals file must be readable");
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_start_matches('\u{feff}').trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 {
            eprintln!("arrivals: skipping malformed row: {line}");
            continue;
        }
        let Some(p) = mm_core::NormalizedPath::parse(f[0]) else {
            eprintln!("arrivals: unparsable path: {}", f[0]);
            continue;
        };
        let value: i64 = f[2].parse().unwrap_or(0);
        let kind = match f[1] {
            "link1" => mm_core::OutOfBandArrival::NotAComponentStoreLink {
                hard_links: value.clamp(0, u16::MAX as i64) as u16,
            },
            "gap" => mm_core::OutOfBandArrival::AfterItsDirectory { days_later: value },
            other => {
                eprintln!("arrivals: unknown rule `{other}`");
                continue;
            }
        };
        let signature = match f[3] {
            "unsigned" => Some(mm_core::SignatureStatus::Unsigned),
            "microsoft" => Some(mm_core::SignatureStatus::CatalogValid {
                signer: "Microsoft".into(),
                catalog: "<measured>".into(),
                root_is_microsoft: true,
            }),
            "third" => {
                Some(mm_core::SignatureStatus::EmbeddedValid { signer: "<measured>".into() })
            }
            _ => None,
        };
        out.push(Arrival { path: p, kind, signature, present: f[4] != "absent" });
    }
    out
}

fn inject_arrivals(observations: &mut Vec<Observation>, rows: &[Arrival]) -> (usize, usize) {
    let known: HashSet<String> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect();
    let (mut touched, mut created) = (0, 0);
    for row in rows {
        if known.contains(row.path.key()) {
            touched += 1;
        } else {
            created += 1;
            if row.present {
                observations.push(Observation::about_path(
                    ArtifactSource::Mft,
                    row.path.clone(),
                    ObservationKind::FileExists {
                        size: 0,
                        created: None,
                        modified: None,
                        mft_modified: None,
                        record: None,
                    },
                ));
            }
        }
        observations.push(Observation::about_path(
            ArtifactSource::Mft,
            row.path.clone(),
            ObservationKind::ArrivedOutOfBand(row.kind),
        ));
        if let Some(status) = &row.signature {
            observations.push(Observation::about_path(
                ArtifactSource::FileContent,
                row.path.clone(),
                ObservationKind::Signature(status.clone()),
            ));
        }
    }
    (touched, created)
}

fn has_creation_time(candidate: &Candidate) -> bool {
    candidate.observations.iter().any(|o| {
        matches!(&o.kind, ObservationKind::FileExists { created: Some(_), .. })
            || matches!(&o.kind, ObservationKind::FileDeleted { .. })
    })
}

fn set_window(weights: &Weights, set: &mut EvidenceSet) {
    set.offer(
        weights,
        "created_in_incident_window",
        "created inside the window a planted sample would open (bound: assumed for every \
         candidate with a creation time)"
            .to_string(),
        vec![],
    );
}

fn read_signatures(path: &str) -> Vec<(mm_core::NormalizedPath, mm_core::SignatureStatus)> {
    let text = std::fs::read_to_string(path).expect("signatures file must be readable");
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_start_matches('\u{feff}').trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 2 {
            eprintln!("signatures: skipping malformed row: {line}");
            continue;
        }
        let Some(p) = mm_core::NormalizedPath::parse(f[0]) else {
            eprintln!("signatures: unparsable path: {}", f[0]);
            continue;
        };
        let status = match f[1] {
            "microsoft" => mm_core::SignatureStatus::CatalogValid {
                signer: "Microsoft".into(),
                catalog: "<measured>".into(),
                root_is_microsoft: true,
            },
            "third" => mm_core::SignatureStatus::EmbeddedValid { signer: "<measured>".into() },
            "unsigned" => mm_core::SignatureStatus::Unsigned,
            "invalid" => mm_core::SignatureStatus::Invalid { reason: "<measured>".into() },
            "untrusted" => mm_core::SignatureStatus::Untrusted {
                signer: "<measured>".into(),
                self_signed_leaf: false,
            },
            "selfsigned" => mm_core::SignatureStatus::Untrusted {
                signer: "<measured>".into(),
                self_signed_leaf: true,
            },
            "unknown" => mm_core::SignatureStatus::Unknown { reason: "<measured>".into() },
            other => {
                eprintln!("signatures: unknown verdict `{other}`");
                continue;
            }
        };
        out.push((p, status));
    }
    out
}

fn inject_signatures(
    observations: &mut Vec<Observation>,
    rows: &[(mm_core::NormalizedPath, mm_core::SignatureStatus)],
) -> usize {
    let known: HashSet<String> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect();
    let mut attached = 0;
    for (path, status) in rows {
        if known.contains(path.key()) {
            attached += 1;
        }
        observations.push(Observation::about_path(
            ArtifactSource::FileContent,
            path.clone(),
            ObservationKind::Signature(status.clone()),
        ));
    }
    attached
}

struct StartupEntry {
    entry: String,
    target: mm_core::NormalizedPath,
    arguments: Option<String>,
}

fn read_startup(path: &str) -> Vec<StartupEntry> {
    let text = std::fs::read_to_string(path).expect("startup file must be readable");
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 2 {
            eprintln!("startup: skipping malformed row: {line}");
            continue;
        }
        let Some(target) = mm_core::NormalizedPath::parse(f[1].trim()) else {
            eprintln!("startup: unparsable target: {}", f[1]);
            continue;
        };
        out.push(StartupEntry {
            entry: f[0].trim().to_string(),
            target,
            arguments: f.get(2).map(|a| a.trim().to_string()).filter(|a| !a.is_empty()),
        });
    }
    out
}

fn inject_startup(observations: &mut Vec<Observation>, rows: &[StartupEntry]) -> (usize, usize) {
    let known: HashSet<String> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect();
    let (mut attached, mut created) = (0, 0);
    for row in rows {
        if known.contains(row.target.key()) {
            attached += 1;
        } else {
            created += 1;
        }
        let entry_name = row.entry.rsplit(['\\', '/']).next().unwrap_or(&row.entry);
        let mut raw_value = format!("{entry_name} -> {}", row.target.raw());
        if let Some(arguments) = &row.arguments {
            raw_value.push(' ');
            raw_value.push_str(arguments);
        }
        observations.push(Observation::about_path(
            ArtifactSource::StartupFolder { file: row.entry.clone() },
            row.target.clone(),
            ObservationKind::Persistence { kind: PersistenceKind::StartupFolder, raw_value },
        ));
    }
    (attached, created)
}

fn target_from(value: &serde_json::Value) -> mm_report::Target {
    let field = |name: &str| value[name].as_str().unwrap_or("<unrecorded>").to_string();
    mm_report::Target {
        display_name: field("display_name"),
        device_path: field("device_path"),
        volume_serial: field("volume_serial"),
    }
}

fn coverage_from(value: &serde_json::Value) -> mm_report::Coverage {
    use mm_report::CoverageStatus;

    let mut coverage = mm_report::Coverage {
        files_enumerated: value["files_enumerated"].as_u64().unwrap_or(0),
        deleted_records_seen: value["deleted_records_seen"].as_u64().unwrap_or(0),
        baseline_usable: value["baseline_usable"].as_bool().unwrap_or(false),
        ..Default::default()
    };
    for entry in value["artifacts"].as_array().into_iter().flatten() {
        let reason = || entry["reason"].as_str().unwrap_or("<unrecorded>").to_string();
        let status = match entry["status"].as_str().unwrap_or("") {
            "read" => CoverageStatus::Read {
                observations: entry["observations"].as_u64().unwrap_or(0) as usize,
            },
            "absent" => CoverageStatus::Absent,
            "failed" => CoverageStatus::Failed { reason: reason() },
            _ => CoverageStatus::NotAvailableHere { reason: reason() },
        };
        coverage.record(entry["artifact"].as_str().unwrap_or("?"), status);
    }
    for warning in value["warnings"].as_array().into_iter().flatten() {
        if let Some(text) = warning.as_str() {
            coverage.warn(text);
        }
    }
    coverage
}

fn prior_log_odds(candidate_count: usize) -> f64 {
    (1.0 / candidate_count.max(2) as f64).ln()
}

fn demote_com_hijacks(observations: &mut [Observation]) -> usize {
    let mut n = 0;
    for o in observations.iter_mut() {
        if let ObservationKind::Persistence { kind, .. } = &mut o.kind {
            if *kind == PersistenceKind::ComHijack {
                *kind = PersistenceKind::ComServer;
                n += 1;
            }
        }
    }
    n
}

fn com_target_is_ordinary(path: &mm_core::NormalizedPath) -> bool {
    matches!(
        zone::classify(path),
        Zone::SystemDir
            | Zone::WindowsOther
            | Zone::WinSxs
            | Zone::ProgramFiles
            | Zone::ProgramData
            | Zone::Unlocated
    )
}

fn is_deferrable_com(observation: &Observation) -> bool {
    match &observation.kind {
        ObservationKind::Persistence { kind: PersistenceKind::ComServer, raw_value } => {
            if raw_value.starts_with("[deleted]") {
                return false;
            }
            observation.path.as_ref().is_some_and(com_target_is_ordinary)
        }
        _ => false,
    }
}

fn registry_source(observation: &Observation) -> Option<(&str, &str)> {
    match &observation.source {
        ArtifactSource::Registry { hive, key } => Some((hive.as_str(), key.as_str())),
        _ => None,
    }
}

fn is_com_server(observation: &Observation) -> bool {
    matches!(
        &observation.kind,
        ObservationKind::Persistence { kind: PersistenceKind::ComServer, .. }
    )
}

fn hive_is_machine_wide(hive: &str) -> bool {
    hive.eq_ignore_ascii_case("SOFTWARE") || hive.eq_ignore_ascii_case("SYSTEM")
}

fn clsid_of(key: &str) -> Option<String> {
    key.split('\\')
        .find(|s| s.len() > 2 && s.starts_with('{') && s.ends_with('}'))
        .map(|s| s.to_ascii_lowercase())
}

fn promote_com_hijacks(observations: &mut [Observation]) -> usize {
    let mut machine: HashMap<String, HashSet<String>> = HashMap::new();
    for o in observations.iter() {
        let Some((hive, key)) = registry_source(o) else { continue };
        if !hive_is_machine_wide(hive) || !is_com_server(o) {
            continue;
        }
        let (Some(clsid), Some(path)) = (clsid_of(key), o.path.as_ref()) else { continue };
        machine.entry(clsid).or_default().insert(path.key().to_string());
    }
    if machine.is_empty() {
        return 0;
    }
    let mut promoted = 0;
    for o in observations.iter_mut() {
        let (hive, key) = match &o.source {
            ArtifactSource::Registry { hive, key } => (hive.clone(), key.clone()),
            _ => continue,
        };
        if hive_is_machine_wide(&hive) || !is_com_server(o) {
            continue;
        }
        let (Some(clsid), Some(path)) = (clsid_of(&key), o.path.as_ref()) else { continue };
        let Some(targets) = machine.get(&clsid) else { continue };
        if targets.contains(path.key()) {
            continue;
        }
        if let ObservationKind::Persistence { kind, .. } = &mut o.kind {
            *kind = PersistenceKind::ComHijack;
            promoted += 1;
        }
    }
    promoted
}

fn defer_ordinary_com_registrations(observations: &mut Vec<Observation>) -> Vec<Observation> {
    let mut deferred = Vec::new();
    let mut kept = Vec::with_capacity(observations.len());
    for o in observations.drain(..) {
        if is_deferrable_com(&o) {
            deferred.push(o);
        } else {
            kept.push(o);
        }
    }
    *observations = kept;
    deferred
}

fn reattach_deferred_com(observations: &mut Vec<Observation>, deferred: Vec<Observation>) {
    if deferred.is_empty() {
        return;
    }
    let present: HashSet<String> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect();
    let rejoining: Vec<Observation> = deferred
        .into_iter()
        .filter(|o| o.path.as_ref().is_some_and(|p| present.contains(p.key())))
        .collect();
    observations.extend(rejoining);
}

fn drop_unreferenced_filesystem_observations(
    observations: &mut Vec<Observation>,
    stomped: &HashSet<String>,
) -> usize {
    let referenced: HashSet<String> = observations
        .iter()
        .filter(|o| o.source != ArtifactSource::Mft)
        .filter_map(|o| o.path.as_ref())
        .map(|p| p.key().to_string())
        .collect();

    let before = observations.len();
    observations.retain(|o| {
        if o.source != ArtifactSource::Mft {
            return true;
        }
        let Some(p) = o.path.as_ref() else { return true };
        if referenced.contains(p.key()) || stomped.contains(p.key()) {
            return true;
        }
        if matches!(o.kind, ObservationKind::FileDeleted { .. }) && p.is_executable_extension() {
            return true;
        }
        p.is_executable_extension()
            && matches!(zone::classify(p), Zone::VolumeRoot | Zone::WindowsTemp)
    });
    before - observations.len()
}

struct Plant {
    label: &'static str,
    path: &'static str,
    persistence: Option<PersistenceKind>,
    on_disk: bool,
    self_deleted: bool,
    signature: mm_core::SignatureStatus,
}

const PLANT_SHAPES: &[&str] = &[
    "appdata-temp-run",
    "appdata-temp-run-microsoft",
    "appdata-temp-run-thirdparty",
    "appdata-temp-run-untrusted",
    "appdata-roaming-run",
    "programdata-service",
    "programfiles-task",
    "programfiles-run",
    "downloads-selfdelete",
    "downloads-absent",
    "system32-service",
    "appdata-roaming-sidecar-a",
    "appdata-roaming-sidecar-b",
];

fn plant_shape(name: &str) -> Option<Plant> {
    Some(match name {
        "appdata-temp-run" => Plant {
            label: "%LOCALAPPDATA%\\Temp + HKCU Run, on disk, unsigned",
            path: "C:\\Users\\Bob\\AppData\\Local\\Temp\\svcupdate.exe",
            persistence: Some(PersistenceKind::RunKey),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "appdata-roaming-run" => Plant {
            label: "%APPDATA%\\Vendor + HKCU Run, on disk, unsigned",
            path: "C:\\Users\\Bob\\AppData\\Roaming\\Vendor\\svcupdate.exe",
            persistence: Some(PersistenceKind::RunKey),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "appdata-roaming-sidecar-a" => Plant {
            label: r"%APPDATA%\Vendor sidecar A, on disk, unsigned, no persistence",
            path: r"C:\Users\Bob\AppData\Roaming\Vendor\vcruntime150.dll",
            persistence: None,
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "appdata-roaming-sidecar-b" => Plant {
            label: r"%APPDATA%\Vendor sidecar B, on disk, unsigned, no persistence",
            path: r"C:\Users\Bob\AppData\Roaming\Vendor\helper.exe",
            persistence: None,
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "programdata-service" => Plant {
            label: "%ProgramData%\\Vendor + HKLM service, on disk, unsigned",
            path: "C:\\ProgramData\\Vendor\\svcupdate.exe",
            persistence: Some(PersistenceKind::Service),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "programfiles-task" => Plant {
            label: "%ProgramFiles%\\Vendor + scheduled task, on disk, unsigned",
            path: "C:\\Program Files\\Vendor\\svcupdate.exe",
            persistence: Some(PersistenceKind::ScheduledTask),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "programfiles-run" => Plant {
            label: "%ProgramFiles%\\Vendor + HKCU Run, on disk, unsigned",
            path: "C:\\Program Files\\Vendor\\svcupdate.exe",
            persistence: Some(PersistenceKind::RunKey),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "downloads-selfdelete" => Plant {
            label: "Downloads, ran once, deleted itself 90 seconds later",
            path: "C:\\Users\\Bob\\Downloads\\svcupdate.exe",
            persistence: None,
            on_disk: false,
            self_deleted: true,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "downloads-absent" => Plant {
            label: "Downloads, ran once, no longer on disk, no deletion record",
            path: "C:\\Users\\Bob\\Downloads\\svcupdate.exe",
            persistence: None,
            on_disk: false,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "system32-service" => Plant {
            label: "%SystemRoot%\\System32 + HKLM service, on disk, unsigned",
            path: "C:\\Windows\\System32\\svcupdate.exe",
            persistence: Some(PersistenceKind::Service),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Unsigned,
        },
        "appdata-temp-run-microsoft" => Plant {
            label: r"%LOCALAPPDATA%\Temp + HKCU Run, on disk, MICROSOFT-CATALOG SIGNED (control)",
            path: r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe",
            persistence: Some(PersistenceKind::RunKey),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::CatalogValid {
                signer: "Microsoft Windows".into(),
                catalog: "Package_for_control.cat".into(),
                root_is_microsoft: true,
            },
        },
        "appdata-temp-run-thirdparty" => Plant {
            label: r"%LOCALAPPDATA%\Temp + HKCU Run, on disk, THIRD-PARTY SIGNED (control)",
            path: r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe",
            persistence: Some(PersistenceKind::RunKey),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::EmbeddedValid { signer: "Some Vendor Ltd".into() },
        },
        "appdata-temp-run-selfsigned" => Plant {
            label: r"%LOCALAPPDATA%\Temp + HKCU Run, on disk, SELF-SIGNED LEAF",
            path: r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe",
            persistence: Some(PersistenceKind::RunKey),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Untrusted {
                signer: "CN=Test".into(),
                self_signed_leaf: true,
            },
        },
        "appdata-temp-run-untrusted" => Plant {
            label: r"%LOCALAPPDATA%\Temp + HKCU Run, on disk, CHAIN TO AN UNRECOGNISED CA",
            path: r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe",
            persistence: Some(PersistenceKind::RunKey),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Untrusted {
                signer: "CN=Contoso Internal Code Signing".into(),
                self_signed_leaf: false,
            },
        },
        "appdata-temp-run-tampered" => Plant {
            label: r"%LOCALAPPDATA%\Temp + HKCU Run, on disk, TAMPERED (hash mismatch)",
            path: r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe",
            persistence: Some(PersistenceKind::RunKey),
            on_disk: true,
            self_deleted: false,
            signature: mm_core::SignatureStatus::Invalid {
                reason: "the file's SHA-256 Authenticode hash does not match the one in the \
                         signature"
                    .into(),
            },
        },
        _ => return None,
    })
}

fn plant_observations(
    plant: &Plant,
    at: chrono::DateTime<chrono::Utc>,
) -> (mm_core::NormalizedPath, Vec<Observation>) {
    use chrono::Duration;
    let p = mm_core::NormalizedPath::parse(plant.path).expect("planted path must parse");
    let mut out = Vec::new();

    if plant.on_disk {
        out.push(Observation::about_path(
            ArtifactSource::Mft,
            p.clone(),
            ObservationKind::FileExists {
                size: 148_480,
                created: Some(at),
                modified: Some(at),
                mft_modified: Some(at),
                record: None,
            },
        ));
        out.push(Observation::about_path(
            ArtifactSource::FileContent,
            p.clone(),
            ObservationKind::Signature(plant.signature.clone()),
        ));
        match zone::classify(&p) {
            Zone::SystemDir => out.push(Observation::about_path(
                ArtifactSource::Mft,
                p.clone(),
                ObservationKind::ArrivedOutOfBand(
                    mm_core::OutOfBandArrival::NotAComponentStoreLink { hard_links: 1 },
                ),
            )),
            Zone::ProgramFiles => out.push(Observation::about_path(
                ArtifactSource::Mft,
                p.clone(),
                ObservationKind::ArrivedOutOfBand(mm_core::OutOfBandArrival::AfterItsDirectory {
                    days_later: 180,
                }),
            )),
            _ => {}
        }
    } else {
        out.push(Observation::about_path(
            ArtifactSource::Prefetch,
            p.clone(),
            ObservationKind::Executed { when: Some(at), run_count: Some(1) },
        ));
        if plant.self_deleted {
            out.push(Observation::about_path(
                ArtifactSource::Mft,
                p.clone(),
                ObservationKind::FileDeleted {
                    when: Some(at + Duration::seconds(90)),
                    record: Some(4242),
                    sequence: None,
                },
            ));
        }
    }

    if let Some(kind) = plant.persistence {
        out.push(Observation::about_path(
            ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "planted".into() },
            p.clone(),
            ObservationKind::Persistence { kind, raw_value: p.raw().to_string() },
        ));
    }
    (p, out)
}

fn parse_plant(spec: &str) -> (Plant, chrono::DateTime<chrono::Utc>) {
    let (name, when) = match spec.split_once('@') {
        Some((n, t)) => (n, Some(t)),
        None => (spec, None),
    };
    let plant = plant_shape(name).unwrap_or_else(|| {
        panic!("unknown plant shape `{name}`; known shapes: {}", PLANT_SHAPES.join(", "))
    });
    let at = match when {
        Some(t) => chrono::DateTime::parse_from_rfc3339(t)
            .unwrap_or_else(|e| panic!("plant time `{t}` is not RFC3339: {e}"))
            .with_timezone(&chrono::Utc),
        None => chrono::DateTime::parse_from_rfc3339("2026-08-20T14:03:11Z")
            .expect("the default plant moment is a constant")
            .with_timezone(&chrono::Utc),
    };
    (plant, at)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Door {
    RunKey,
    Service,
    ScheduledTask,
    OtherAutostart,
    ComRegistration,
    Quarantine,
    Executed,
    Deleted,
    Downloaded,
    Other,
}

impl Door {
    fn label(self) -> &'static str {
        match self {
            Door::RunKey => "run key",
            Door::Service => "service",
            Door::ScheduledTask => "scheduled task",
            Door::OtherAutostart => "other autostart",
            Door::ComRegistration => "COM registration",
            Door::Quarantine => "AV named it",
            Door::Executed => "executed",
            Door::Deleted => "deleted executable",
            Door::Downloaded => "downloaded",
            Door::Other => "filesystem only",
        }
    }
}

fn door_of(c: &Candidate) -> Door {
    let mut best: Option<Door> = None;
    for o in &c.observations {
        let d = match &o.kind {
            ObservationKind::Persistence { kind, .. } => match kind {
                PersistenceKind::RunKey | PersistenceKind::RunOnceKey => Door::RunKey,
                PersistenceKind::Service => Door::Service,
                PersistenceKind::ScheduledTask => Door::ScheduledTask,
                PersistenceKind::ComHijack | PersistenceKind::ComServer => Door::ComRegistration,
                _ => Door::OtherAutostart,
            },
            ObservationKind::Quarantined { .. } | ObservationKind::AvDetected { .. } => {
                Door::Quarantine
            }
            ObservationKind::Executed { .. } => Door::Executed,
            ObservationKind::FileDeleted { .. } => Door::Deleted,
            ObservationKind::DownloadedFrom { .. } => Door::Downloaded,
            _ => continue,
        };
        best = Some(match best {
            Some(b) if b <= d => b,
            _ => d,
        });
    }
    best.unwrap_or(Door::Other)
}

fn logistic(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

fn study(rebuilt: &[Candidate], planted: &[(String, &'static str)]) {
    use std::collections::BTreeMap;
    let n = rebuilt.len() as f64;
    let global = (1.0f64 / n).ln();

    let mut totals: Vec<f64> =
        rebuilt.iter().map(|c| c.evidence.iter().map(|e| e.log_lr).sum::<f64>()).collect();
    totals.sort_by(|a, b| b.partial_cmp(a).unwrap());
    let sum: f64 = totals.iter().sum();
    println!("\n== PRIOR STUDY ==");
    println!(
        "population {} | global prior {:.4} | mean evidence total {:.4} | median {:.4} | max {:.4}",
        rebuilt.len(),
        global,
        sum / n,
        totals[totals.len() / 2],
        totals[0]
    );
    println!(
        "the prior is {:.1}% of the mean candidate's absolute log-odds, and {:.1}% of the strongest's",
        100.0 * global.abs() / (global.abs() + sum / n),
        100.0 * global.abs() / (global.abs() + totals[0])
    );
    println!("evidence total needed to reach p=0.50 at the global prior: {:.2}", -global);

    let mut by_door: BTreeMap<Door, Vec<f64>> = BTreeMap::new();
    for c in rebuilt {
        by_door
            .entry(door_of(c))
            .or_default()
            .push(c.evidence.iter().map(|e| e.log_lr).sum::<f64>());
    }
    println!("\n-- population and clean evidence ceiling per admission door --");
    println!(
        "{:<18} {:>7} {:>10} {:>9} {:>9} {:>9}",
        "door", "n", "ln(1/n)", "ceiling", "p_global", "p_door"
    );
    for (d, v) in &by_door {
        let mut v = v.clone();
        v.sort_by(|a, b| b.partial_cmp(a).unwrap());
        let dp = (1.0f64 / (v.len().max(2) as f64)).ln();
        println!(
            "{:<18} {:>7} {:>10.4} {:>9.2} {:>9.4} {:>9.4}",
            d.label(),
            v.len(),
            dp,
            v[0],
            logistic(global + v[0]),
            logistic(dp + v[0])
        );
    }

    for (key, label) in planted {
        let Some(c) =
            rebuilt.iter().find(|c| c.path.as_ref().is_some_and(|p| p.key() == key.as_str()))
        else {
            continue;
        };
        let t: f64 = c.evidence.iter().map(|e| e.log_lr).sum();
        let d = door_of(c);
        let dn = by_door.get(&d).map(|v| v.len()).unwrap_or(1).max(2) as f64;
        let dp = (1.0f64 / dn).ln();
        println!(
            "\nPLANT-MODEL [{label}] door={} total={t:.2}\n  global ln(1/{}) -> {:.4}\n  door   ln(1/{}) -> {:.4}",
            d.label(),
            rebuilt.len(),
            logistic(global + t),
            dn as usize,
            logistic(dp + t)
        );
    }

    if std::env::args().any(|a| a == "--dump") {
        for c in rebuilt {
            let t: f64 = c.evidence.iter().map(|e| e.log_lr).sum();
            println!(
                "DOORROW	{}	{t:.4}	{}	{}",
                door_of(c).label(),
                c.path.as_ref().map(|p| zone::classify(p).label()).unwrap_or("none"),
                c.path.as_ref().map(|p| p.raw()).unwrap_or("<no path>")
            );
        }
    }

    let mut worst: Vec<(&Candidate, f64, Door)> = rebuilt
        .iter()
        .filter(|c| {
            !planted.iter().any(|(k, _)| c.path.as_ref().is_some_and(|p| p.key() == k.as_str()))
        })
        .map(|c| {
            let t: f64 = c.evidence.iter().map(|e| e.log_lr).sum();
            (c, t, door_of(c))
        })
        .collect();
    worst.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    println!("\n-- strongest CLEAN candidates by evidence total, and what each prior model gives them --");
    for (c, t, d) in worst.iter().take(10) {
        let dn = by_door.get(d).map(|v| v.len()).unwrap_or(1).max(2) as f64;
        let dp = (1.0f64 / dn).ln();
        println!(
            "  total {t:5.2}  global {:.4}  door[{}] {:.4}   {}",
            logistic(global + t),
            d.label(),
            logistic(dp + t),
            c.path.as_ref().map(|p| p.raw()).unwrap_or("<no path>")
        );
    }
}
