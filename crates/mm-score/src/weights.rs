use std::collections::HashMap;

use crate::machine;
use mm_core::{ArtifactSource, Evidence};
use serde::Deserialize;

const EMBEDDED: &str = include_str!("../rules/weights.toml");

pub mod feature {
    pub const QUARANTINED_BY_AV: &str = "quarantined_by_av";
    pub const AV_DETECTION_LOGGED: &str = "av_detection_logged";

    pub const SIGNED_MICROSOFT_CATALOG: &str = "signed_microsoft_catalog";
    pub const SIGNED_TRUSTED_PUBLISHER: &str = "signed_trusted_publisher";
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    pub const SIGNATURE_SELF_SIGNED: &str = "signature_self_signed";
    pub const SIGNATURE_EXPIRED: &str = "signature_expired";
    pub const SIGNATURE_UNVERIFIABLE: &str = "signature_unverifiable";
    pub const UNSIGNED_IN_SYSTEM_ZONE: &str = "unsigned_in_system_zone";
    pub const UNSIGNED_IN_PROGRAM_FILES: &str = "unsigned_in_program_files";
    pub const UNSIGNED_MANAGED_ASSEMBLY: &str = "unsigned_managed_assembly";
    pub const UNSIGNED_IN_USER_ZONE: &str = "unsigned_in_user_zone";

    pub const INSTALLED_OUTSIDE_COMPONENT_STORE: &str = "installed_outside_component_store";
    pub const ARRIVED_AFTER_ITS_DIRECTORY: &str = "arrived_after_its_directory";

    pub const EXECUTABLE_IN_USER_TEMP: &str = "executable_in_user_temp";
    pub const EXECUTABLE_AT_VOLUME_ROOT: &str = "executable_at_volume_root";
    pub const EXECUTABLE_IN_RECYCLE_BIN: &str = "executable_in_recycle_bin";
    pub const EXECUTABLE_IN_WINDOWS_TEMP: &str = "executable_in_windows_temp";
    pub const EXECUTABLE_IN_USER_APPDATA: &str = "executable_in_user_appdata";
    pub const EXECUTABLE_IN_USER_DOWNLOADS: &str = "executable_in_user_downloads";
    pub const EXECUTABLE_IN_PROGRAMDATA: &str = "executable_in_programdata";
    pub const EXECUTABLE_IN_USER_PROFILE: &str = "executable_in_user_profile";
    pub const EXECUTABLE_IN_WINDOWS_DIRECTORY: &str = "executable_in_windows_directory";
    pub const EXECUTABLE_OUTSIDE_STANDARD_ZONES: &str = "executable_outside_standard_zones";

    pub const PERSISTENCE_TARGETS_USER_PROFILE: &str = "persistence_targets_user_profile";
    pub const PERSISTENCE_TARGETS_SCRATCH_SPACE: &str = "persistence_targets_scratch_space";

    pub const LONE_EXECUTABLE_AMONG_DOCUMENTS: &str = "lone_executable_among_documents";
    pub const EXECUTABLE_RARE_FOR_ZONE: &str = "executable_rare_for_zone_on_this_machine";
    pub const COMPACT_OS_COMPRESSED_EXECUTABLE: &str = "compact_os_compressed_executable";
    pub const NAME_UNIQUE_ON_MACHINE: &str = "name_unique_on_machine";
    pub const NAME_RECURS_ON_MACHINE: &str = "name_recurs_on_machine";

    pub const SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR: &str = "system_binary_name_outside_system_dir";
    pub const DOUBLE_EXTENSION: &str = "double_extension";
    pub const RANDOM_LOOKING_NAME: &str = "random_looking_name";

    pub const PERSISTENCE_IFEO: &str = "persistence_ifeo";
    pub const PERSISTENCE_COM_SERVER: &str = "persistence_com_server";
    pub const PERSISTENCE_COM_HIJACK: &str = "persistence_com_hijack";
    pub const PERSISTENCE_WINLOGON: &str = "persistence_winlogon";
    pub const PERSISTENCE_SCHEDULED_TASK: &str = "persistence_scheduled_task";
    pub const PERSISTENCE_SERVICE: &str = "persistence_service";
    pub const PERSISTENCE_RUN_KEY: &str = "persistence_run_key";
    pub const PERSISTENCE_DELETED_ENTRY: &str = "persistence_deleted_entry";

    pub const DELETED_SOON_AFTER_EXECUTION: &str = "deleted_soon_after_execution";
    pub const EXECUTED_BUT_NOW_ABSENT: &str = "executed_but_now_absent";
    pub const ABSENT_FROM_SCRATCH_SPACE: &str = "executed_but_now_absent_from_scratch_space";
    pub const TIMESTOMPED: &str = "timestomped";
    pub const CREATED_IN_INCIDENT_WINDOW: &str = "created_in_incident_window";

    pub const YARA_MATCH: &str = "yara_match";
    pub const HIGH_ENTROPY_CODE_SECTION: &str = "high_entropy_code_section";
    pub const PE_STRUCTURAL_ANOMALY: &str = "pe_structural_anomaly";
    pub const RICH_HEADER_CHECKSUM_INVALID: &str = "rich_header_checksum_invalid";
    pub const NO_VERSION_RESOURCE: &str = "no_version_resource";
    pub const AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE: &str =
        "autostart_target_without_version_resource";

    pub const SHARED_DIGEST_RENAMED_COPY: &str = "shared_digest_renamed_copy";

    pub const DOWNLOADED_FROM_INTERNET_ZONE: &str = "downloaded_from_internet_zone";
    pub const DOWNLOADED_FROM_RESTRICTED_ZONE: &str = "downloaded_from_restricted_zone";
    pub const DOWNLOAD_ORIGIN_RECORDED: &str = "download_origin_recorded";

    pub const UNBACKED_EXECUTABLE_MEMORY: &str = "unbacked_executable_memory";
    pub const RUNNING_FROM_USER_DIRECTORY: &str = "running_from_user_directory";

    pub const ALL: &[&str] = &[
        QUARANTINED_BY_AV,
        AV_DETECTION_LOGGED,
        SIGNED_MICROSOFT_CATALOG,
        SIGNED_TRUSTED_PUBLISHER,
        SIGNATURE_INVALID,
        SIGNATURE_SELF_SIGNED,
        SIGNATURE_EXPIRED,
        SIGNATURE_UNVERIFIABLE,
        UNSIGNED_IN_SYSTEM_ZONE,
        UNSIGNED_IN_PROGRAM_FILES,
        UNSIGNED_MANAGED_ASSEMBLY,
        UNSIGNED_IN_USER_ZONE,
        INSTALLED_OUTSIDE_COMPONENT_STORE,
        ARRIVED_AFTER_ITS_DIRECTORY,
        EXECUTABLE_IN_USER_TEMP,
        EXECUTABLE_AT_VOLUME_ROOT,
        EXECUTABLE_IN_RECYCLE_BIN,
        EXECUTABLE_IN_WINDOWS_TEMP,
        EXECUTABLE_IN_USER_APPDATA,
        EXECUTABLE_IN_USER_DOWNLOADS,
        EXECUTABLE_IN_PROGRAMDATA,
        EXECUTABLE_IN_USER_PROFILE,
        EXECUTABLE_IN_WINDOWS_DIRECTORY,
        EXECUTABLE_OUTSIDE_STANDARD_ZONES,
        PERSISTENCE_TARGETS_USER_PROFILE,
        PERSISTENCE_TARGETS_SCRATCH_SPACE,
        LONE_EXECUTABLE_AMONG_DOCUMENTS,
        EXECUTABLE_RARE_FOR_ZONE,
        COMPACT_OS_COMPRESSED_EXECUTABLE,
        NAME_UNIQUE_ON_MACHINE,
        NAME_RECURS_ON_MACHINE,
        SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR,
        DOUBLE_EXTENSION,
        RANDOM_LOOKING_NAME,
        PERSISTENCE_IFEO,
        PERSISTENCE_COM_SERVER,
        PERSISTENCE_COM_HIJACK,
        PERSISTENCE_WINLOGON,
        PERSISTENCE_SCHEDULED_TASK,
        PERSISTENCE_SERVICE,
        PERSISTENCE_RUN_KEY,
        PERSISTENCE_DELETED_ENTRY,
        DELETED_SOON_AFTER_EXECUTION,
        EXECUTED_BUT_NOW_ABSENT,
        ABSENT_FROM_SCRATCH_SPACE,
        TIMESTOMPED,
        CREATED_IN_INCIDENT_WINDOW,
        YARA_MATCH,
        HIGH_ENTROPY_CODE_SECTION,
        PE_STRUCTURAL_ANOMALY,
        RICH_HEADER_CHECKSUM_INVALID,
        NO_VERSION_RESOURCE,
        AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE,
        SHARED_DIGEST_RENAMED_COPY,
        DOWNLOADED_FROM_INTERNET_ZONE,
        DOWNLOADED_FROM_RESTRICTED_ZONE,
        DOWNLOAD_ORIGIN_RECORDED,
        UNBACKED_EXECUTABLE_MEMORY,
        RUNNING_FROM_USER_DIRECTORY,
    ];
}

#[derive(Debug, Deserialize)]
struct TableFile {
    meta: Meta,
    features: HashMap<String, FeatureWeight>,
}

#[derive(Debug, Deserialize)]
struct Meta {
    version: u32,
    calibrated: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FeatureWeight {
    pub group: String,
    pub log_lr: f64,
    pub rationale: String,
    pub benign_rate: String,

    #[serde(default)]
    pub convicts_alone: Option<String>,
}

#[derive(Debug)]
pub struct Weights {
    features: HashMap<String, FeatureWeight>,
    version: u32,
    calibrated: bool,
}

impl Weights {
    pub fn embedded() -> Self {
        Self::parse(EMBEDDED).expect("the embedded weight table must be valid")
    }

    pub fn parse(toml_text: &str) -> Result<Self, String> {
        let file: TableFile = toml::from_str(toml_text).map_err(|e| e.to_string())?;

        for (name, weight) in &file.features {
            if !weight.log_lr.is_finite() {
                return Err(format!("feature `{name}` has a non-finite log_lr"));
            }
            if weight.group.trim().is_empty() {
                return Err(format!("feature `{name}` has no group"));
            }
            check_benign_rate(name, &weight.benign_rate)?;
            check_convicts_alone(name, weight)?;
        }

        Ok(Weights {
            features: file.features,
            version: file.meta.version,
            calibrated: file.meta.calibrated,
        })
    }

    pub fn get(&self, feature: &str) -> Option<&FeatureWeight> {
        self.features.get(feature)
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn is_calibrated(&self) -> bool {
        self.calibrated
    }

    pub fn feature_names(&self) -> impl Iterator<Item = &str> {
        self.features.keys().map(String::as_str)
    }

    pub fn all(&self) -> impl Iterator<Item = (&str, &FeatureWeight)> {
        self.features.iter().map(|(name, weight)| (name.as_str(), weight))
    }

    pub fn max_log_lr_in_group(&self, group: &str) -> f64 {
        self.features.values().filter(|w| w.group == group).map(|w| w.log_lr).fold(0.0f64, f64::max)
    }
}

pub const UNMEASURED: &str = "UNMEASURED:";

fn check_benign_rate(name: &str, rate: &str) -> Result<(), String> {
    let rate = rate.trim();
    if let Some(reason) = rate.strip_prefix(UNMEASURED) {
        if reason.trim().len() < 20 {
            return Err(format!(
                "feature `{name}` declares its benign rate UNMEASURED without saying what would have to be counted; the reason is the whole point of the admission"
            ));
        }
        return Ok(());
    }
    if rate.is_empty() {
        return Err(format!(
            "feature `{name}` has no `benign_rate`. Every row must state P(feature | benign) as absolute counts over a named population, or say `{UNMEASURED} <reason>`."
        ));
    }
    if !rate.chars().any(|c| c.is_ascii_digit()) {
        return Err(format!(
            "feature `{name}` has a `benign_rate` with no numbers in it: `{rate}`. A denominator is a count, not a description. Say `{UNMEASURED} <reason>` if nothing was counted."
        ));
    }
    Ok(())
}

fn check_convicts_alone(name: &str, weight: &FeatureWeight) -> Result<(), String> {
    let ceiling = machine::SMALLEST_MACHINE.single_feature_ceiling();
    if weight.log_lr <= ceiling {
        return Ok(());
    }
    match weight.convicts_alone.as_deref().map(str::trim) {
        Some(reason) if reason.len() >= 40 => Ok(()),
        Some(_) => Err(format!(
            "feature `{name}` carries {:.1}, which is above the {ceiling:.4} a single row may \
             carry without convicting a file on its own on a {}-candidate machine. Its \
             `convicts_alone` justification is too short to be one — say what makes an \
             unaccompanied instance of this feature enough to accuse a file.",
            weight.log_lr,
            machine::SMALLEST_MACHINE.candidates,
        )),
        None => Err(format!(
            "feature `{name}` carries {:.1}. On the smallest machine this tool will report on \
             ({} candidates, ln = {:.4}) that is enough to push a file over the even-odds \
             threshold with nothing else against it but a +{:.1} row that fires on a third of \
             the volume. A row may do that, but not silently: add a `convicts_alone` field \
             saying why an unaccompanied instance of this feature is enough to accuse a file, \
             or bring the weight to {ceiling:.4} or below. \
             This check exists because `quarantined_by_av` sat at +8.0 while a test asserted \
             the opposite against a prior that had stopped describing any machine.",
            weight.log_lr,
            machine::SMALLEST_MACHINE.candidates,
            machine::SMALLEST_MACHINE.ln_population(),
            machine::CHEAPEST_UBIQUITOUS_ROW,
        )),
    }
}

pub mod group {
    pub const SIGNATURE: &str = "signature";
}

#[derive(Debug, Default)]
pub struct EvidenceSet {
    by_group: HashMap<String, Evidence>,
}

impl EvidenceSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn offer(
        &mut self,
        weights: &Weights,
        feature: &str,
        detail: impl Into<String>,
        sources: Vec<ArtifactSource>,
    ) {
        let Some(weight) = weights.get(feature) else {
            log::warn!("no weight for feature `{feature}`; ignoring");
            return;
        };

        let detail = detail.into();
        let candidate =
            Evidence { feature: feature.to_string(), log_lr: weight.log_lr, detail, sources };

        match self.by_group.get_mut(&weight.group) {
            Some(existing) if existing.log_lr.abs() >= candidate.log_lr.abs() => {
                append_detail(existing, &candidate.detail);
                existing.sources.extend(candidate.sources);
            }
            Some(existing) => {
                let superseded = std::mem::replace(existing, candidate);
                append_detail(existing, &superseded.detail);
                existing.sources.extend(superseded.sources);
            }
            None => {
                self.by_group.insert(weight.group.clone(), candidate);
            }
        }
    }

    pub fn into_evidence(self) -> Vec<Evidence> {
        let mut out: Vec<Evidence> = self.by_group.into_values().collect();
        out.sort_by(|a, b| {
            b.log_lr
                .partial_cmp(&a.log_lr)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.feature.cmp(&b.feature))
        });
        out
    }
}

fn append_detail(existing: &mut Evidence, addition: &str) {
    const MAX_DISTINCT: usize = 3;

    if existing.detail.contains(addition) {
        return;
    }
    let already = existing.detail.matches("; also: ").count();
    if already >= MAX_DISTINCT {
        if !existing.detail.ends_with('…') {
            existing.detail.push_str(" …and more");
        }
        return;
    }
    existing.detail.push_str("; also: ");
    existing.detail.push_str(addition);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_loads() {
        let w = Weights::embedded();
        assert_eq!(w.version(), 1);
    }

    #[test]
    fn the_shipped_table_admits_it_is_uncalibrated() {
        assert!(!Weights::embedded().is_calibrated());
    }

    #[test]
    fn a_table_that_claims_calibration_is_read_as_calibrated() {
        let fitted = Weights::parse(
            "[meta]\nversion = 1\ncalibrated = true\n\n\
             [features.x]\ngroup = \"g\"\nlog_lr = 1.0\n\
             benign_rate = \"0 of 1,000 candidates\"\nrationale = \"r\"\n",
        )
        .expect("a well-formed table");
        assert!(fitted.is_calibrated());
    }

    fn table_with(
        name: &str,
        log_lr: f64,
        convicts_alone: Option<&str>,
    ) -> Result<Weights, String> {
        let extra = convicts_alone
            .map(|r| format!("convicts_alone = \"\"\"{r}\"\"\"\n"))
            .unwrap_or_default();
        Weights::parse(&format!(
            "[meta]\nversion = 1\ncalibrated = false\n\n\
             [features.{name}]\ngroup = \"g\"\nlog_lr = {log_lr}\n\
             benign_rate = \"0 of 1,000 candidates\"\nrationale = \"r\"\n{extra}"
        ))
    }

    #[test]
    fn a_row_strong_enough_to_convict_alone_must_say_why_or_the_table_will_not_load() {
        let ceiling = machine::SMALLEST_MACHINE.single_feature_ceiling();
        let err = table_with("too_strong", ceiling + 0.1, None)
            .expect_err("a row above the ceiling with no justification must not parse");
        assert!(err.contains("too_strong"), "{err}");
        assert!(err.contains("convicts_alone"), "{err}");
    }

    #[test]
    fn a_token_justification_is_not_a_justification() {
        let ceiling = machine::SMALLEST_MACHINE.single_feature_ceiling();
        assert!(table_with("too_strong", ceiling + 0.1, Some("yes")).is_err());
        assert!(table_with(
            "too_strong",
            ceiling + 0.1,
            Some("a present structural fact about the file, not a recorded opinion about it")
        )
        .is_ok());
    }

    #[test]
    fn a_row_below_the_ceiling_needs_no_justification() {
        let ceiling = machine::SMALLEST_MACHINE.single_feature_ceiling();
        assert!(table_with("ordinary", ceiling, None).is_ok());
        assert!(table_with("ordinary", ceiling - 1.0, None).is_ok());
    }

    #[test]
    fn exactly_three_shipped_rows_declare_that_they_convict_alone() {
        let w = Weights::embedded();
        let ceiling = machine::SMALLEST_MACHINE.single_feature_ceiling();
        let mut declared: Vec<&str> =
            w.all().filter(|(_, f)| f.convicts_alone.is_some()).map(|(n, _)| n).collect();
        declared.sort_unstable();
        assert_eq!(
            declared,
            [
                "persistence_ifeo",
                "system_binary_name_outside_system_dir",
                "unbacked_executable_memory"
            ],
            "the set of rows allowed to convict a file with no corroboration has changed"
        );
        for (name, f) in w.all() {
            if f.convicts_alone.is_none() {
                assert!(
                    f.log_lr <= ceiling,
                    "`{name}` at {:+} is above the {ceiling:.4} ceiling and declares nothing",
                    f.log_lr
                );
            }
        }
    }

    #[test]
    fn every_feature_constant_matches_the_table_exactly() {
        let w = Weights::embedded();

        for name in feature::ALL {
            assert!(w.get(name).is_some(), "feature constant `{name}` has no table entry");
        }

        let known: std::collections::HashSet<&str> = feature::ALL.iter().copied().collect();
        for name in w.feature_names() {
            assert!(known.contains(name), "table entry `{name}` has no feature constant");
        }
    }

    const PENDING: &[(&str, &str)] = &[];

    const PRODUCERLESS: &[(&str, &str, &str)] = &[
        (
            "yara_match",
            "YaraMatch",
            "no rule engine and no rule set ship. Measured before shipping one: a \
             generic anti-analysis rule fires on 62.86% of the laptop's on-disk PE \
             candidates, which caps any honest weight at +0.46; a packer section-name \
             rule fires on 0.025%. One row cannot price both, so if a producer lands, \
             split the row by rule family and measure each against the set that ships",
        ),
        (
            "unbacked_executable_memory",
            "UnbackedExecutableMemory",
            "live-only, and this tool analyses a cold disk from WinRE. +6.8 with no \
             benign population ever counted; count one before any producer lands",
        ),
        (
            "running_from_user_directory",
            "ProcessRunning",
            "live-only, same as above. Over half the reference laptop's candidates are \
             in user temp, so the benign population for this is large and uncounted",
        ),
    ];

    const MAX_UNMEASURED: usize = 7;

    const SELF_SOURCE: &str = include_str!("weights.rs");

    fn producer_source() -> String {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("mm-score sits under crates/")
            .to_path_buf();

        let mut combined = String::new();
        let mut stack = vec![crates];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                if path.is_dir() {
                    if name == "mm-score"
                        || name == "target"
                        || name == "tests"
                        || name == "examples"
                    {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                if name == "observation.rs" {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else { continue };
                for line in text.split("#[cfg(test)]").next().unwrap_or("").lines() {
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    combined.push_str(line);
                    combined.push('\n');
                }
            }
        }
        combined
    }

    fn observation_kinds() -> Vec<String> {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("mm-score sits under crates/")
                .join("mm-core/src/observation.rs"),
        )
        .expect("mm-core/src/observation.rs must be readable");

        let body = source
            .split_once("pub enum ObservationKind {")
            .expect("the ObservationKind enum must exist")
            .1;

        let mut names = Vec::new();
        let mut depth = 0usize;
        for line in body.lines() {
            let trimmed = line.trim();
            if depth == 0 && trimmed == "}" {
                break;
            }
            if depth == 0 && !trimmed.starts_with("//") && !trimmed.starts_with('#') {
                let head: String =
                    trimmed.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                if head.chars().next().is_some_and(char::is_uppercase) {
                    names.push(head);
                }
            }
            depth += line.matches('{').count();
            depth = depth.saturating_sub(line.matches('}').count());
        }
        names
    }

    #[test]
    fn no_weight_becomes_reachable_without_a_measurement() {
        let weights = Weights::embedded();
        let source = producer_source();
        let kinds = observation_kinds();

        assert!(
            source.contains("ObservationKind::FileExists"),
            "the producer scan found nothing at all — it is reading the wrong \
             directories, and would pass whatever the tree contained"
        );
        assert!(
            kinds.len() >= 15,
            "only {} ObservationKind variants were parsed out of the enum; the parser \
             has drifted from the source it reads",
            kinds.len()
        );

        for (feature, kind, why) in PRODUCERLESS {
            assert!(
                kinds.iter().any(|k| k == kind),
                "PRODUCERLESS names `ObservationKind::{kind}`, which is not a variant"
            );
            assert!(
                weights.get(feature).is_some(),
                "PRODUCERLESS names `{feature}`, which is not in the weight table"
            );
            assert!(
                !source.contains(&format!("ObservationKind::{kind}")),
                "`ObservationKind::{kind}` is now built by production code, which arms \
                 the weight `{feature}` ({:+.1}) on every real machine. It was listed as \
                 unreachable because: {why}\n\n\
                 Before deleting this entry: count P(feature | benign) over both clean \
                 datasets, write it into the row's `benign_rate`, and check that both \
                 still report NOTHING FOUND. A weight that arrives without that is how \
                 this table shipped three of them.",
                weights.get(feature).expect("checked above").log_lr
            );
        }
    }

    #[test]
    fn the_number_of_unmeasured_rows_only_goes_down() {
        let weights = Weights::embedded();
        let mut unmeasured: Vec<&str> = weights
            .feature_names()
            .filter(|n| {
                weights.get(n).expect("just listed").benign_rate.trim().starts_with(UNMEASURED)
            })
            .collect();
        unmeasured.sort_unstable();

        assert!(
            unmeasured.len() <= MAX_UNMEASURED,
            "{} rows now declare their benign rate UNMEASURED, over the ratchet of \
             {MAX_UNMEASURED}: {unmeasured:?}. Measure the new one, or raise \
             MAX_UNMEASURED by hand and write down why it could not be measured.",
            unmeasured.len()
        );
    }

    #[test]
    fn every_weight_states_a_benign_rate() {
        let weights = Weights::embedded();
        for name in feature::ALL {
            let rate = &weights.get(name).unwrap().benign_rate;
            assert!(
                check_benign_rate(name, rate).is_ok(),
                "`{name}` has an unusable benign_rate: {rate}"
            );
            assert!(
                rate.trim().len() > 30,
                "`{name}` states its benign rate in {} characters, which is not a \
                 population: {rate}",
                rate.trim().len()
            );
        }
    }

    #[test]
    fn a_yara_rule_cannot_convict_on_its_own() {
        let weights = Weights::embedded();
        let yara = weights.get(feature::YARA_MATCH).unwrap().log_lr;
        let ceiling = (1.0f64 / 0.6286).ln();
        assert!(
            yara <= ceiling,
            "`yara_match` is {yara}, above the {ceiling:.3} that a benign rate of \
             62.86% can support. See the row's benign_rate for the measurement."
        );
        assert!(yara > 0.0, "a rule match is still evidence, just not much");
    }

    fn feature_constants() -> HashMap<String, String> {
        let block = SELF_SOURCE
            .split_once("pub mod feature {")
            .expect("the feature module must exist")
            .1
            .split_once("pub const ALL")
            .expect("the ALL array must follow the constants")
            .0;

        let mut named = HashMap::new();
        for statement in block.split(';') {
            let Some(rest) = statement.trim().strip_prefix("pub const ") else { continue };
            let Some((ident, tail)) = rest.split_once(':') else { continue };
            let Some(value) = tail.split('"').nth(1) else { continue };
            named.insert(value.to_string(), ident.trim().to_string());
        }
        named
    }

    fn production_source() -> String {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let entries =
            std::fs::read_dir(&dir).expect("mm-score/src must be readable by its own tests");

        let mut combined = String::new();
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some("weights.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a readable source file");
            for line in text.split("#[cfg(test)]").next().unwrap_or("").lines() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                combined.push_str(line);
                combined.push('\n');
            }
        }
        combined
    }

    #[test]
    fn every_table_entry_is_offered_by_production_code() {
        let weights = Weights::embedded();
        let constants = feature_constants();
        let source = production_source();
        let pending: HashMap<&str, &str> = PENDING.iter().copied().collect();

        assert!(
            source.contains("feature::QUARANTINED_BY_AV"),
            "the source scan found nothing at all — it is checking the wrong files, \
             and would pass whatever the table said"
        );

        for name in weights.feature_names() {
            let ident = constants
                .get(name)
                .unwrap_or_else(|| panic!("table entry `{name}` has no feature constant"));
            let offered = source.contains(&format!("feature::{ident}"));

            match pending.get(name) {
                None => assert!(
                    offered,
                    "the weight table declares `{name}` and no production code in mm-score ever \
                     offers `feature::{ident}`, so nothing on any machine can ever produce it. \
                     Either wire it up, or delete the entry and say why where it used to be. \
                     If it is deliberately waiting on work that has not landed, add it to \
                     PENDING with the reason."
                ),
                Some(why) => assert!(
                    !offered,
                    "`{name}` is listed in PENDING as unreachable ({why}), but production code \
                     now offers `feature::{ident}`. The work landed — delete the PENDING entry."
                ),
            }
        }

        for (name, _) in PENDING {
            assert!(
                weights.get(name).is_some(),
                "PENDING names `{name}`, which is no longer in the weight table at all"
            );
        }
    }

    #[test]
    fn the_features_wired_up_for_roadmap_item_four_stay_wired() {
        let source = production_source();
        for ident in
            ["HIGH_ENTROPY_CODE_SECTION", "EXECUTABLE_RARE_FOR_ZONE", "CREATED_IN_INCIDENT_WINDOW"]
        {
            assert!(
                source.contains(&format!("feature::{ident}")),
                "`{ident}` lost its producer and is a dead weight again"
            );
        }
    }

    #[test]
    fn every_weight_carries_a_rationale() {
        let w = Weights::embedded();
        for name in feature::ALL {
            let weight = w.get(name).unwrap();
            assert!(
                weight.rationale.trim().len() > 40,
                "feature `{name}` needs a real rationale, not `{}`",
                weight.rationale
            );
        }
    }

    #[test]
    fn exonerating_features_are_actually_negative() {
        let w = Weights::embedded();
        for name in [
            feature::SIGNED_MICROSOFT_CATALOG,
            feature::SIGNED_TRUSTED_PUBLISHER,
            feature::NAME_RECURS_ON_MACHINE,
        ] {
            assert!(w.get(name).unwrap().log_lr < 0.0, "`{name}` should exonerate");
        }
    }

    #[test]
    fn incriminating_features_are_positive() {
        let w = Weights::embedded();
        for name in [
            feature::QUARANTINED_BY_AV,
            feature::PERSISTENCE_IFEO,
            feature::TIMESTOMPED,
            feature::YARA_MATCH,
        ] {
            assert!(w.get(name).unwrap().log_lr > 0.0, "`{name}` should incriminate");
        }
    }

    #[test]
    fn merely_being_unsigned_stays_weak() {
        let w = Weights::embedded();
        let unsigned = w.get(feature::UNSIGNED_IN_USER_ZONE).unwrap().log_lr;
        assert!(unsigned < 1.5, "unsigned-in-user-dir is {unsigned}, too strong to be safe");
        assert!(unsigned < w.get(feature::QUARANTINED_BY_AV).unwrap().log_lr / 4.0);
    }

    #[test]
    fn an_unfinished_check_is_weighted_at_exactly_zero() {
        let w = Weights::embedded();
        assert_eq!(w.get(feature::SIGNATURE_UNVERIFIABLE).unwrap().log_lr, 0.0);
    }

    #[test]
    fn expiry_is_priced_well_below_tampering() {
        let w = Weights::embedded();
        let expired = w.get(feature::SIGNATURE_EXPIRED).unwrap().log_lr;
        let invalid = w.get(feature::SIGNATURE_INVALID).unwrap().log_lr;
        assert!(expired > 0.0, "an untimestamped expired signature is still odd");
        assert!(
            expired < invalid / 2.0,
            "expiry ({expired}) must not read as tampering ({invalid})"
        );
    }

    #[test]
    fn a_microsoft_catalog_outweighs_any_other_signature() {
        let w = Weights::embedded();
        let ms = w.get(feature::SIGNED_MICROSOFT_CATALOG).unwrap().log_lr;
        let other = w.get(feature::SIGNED_TRUSTED_PUBLISHER).unwrap().log_lr;
        assert!(ms < other, "Microsoft ({ms}) should exonerate harder than anyone else ({other})");
    }

    #[test]
    fn the_signature_groups_bound_comes_from_the_table() {
        let w = Weights::embedded();
        let bound = w.max_log_lr_in_group(group::SIGNATURE);
        assert_eq!(bound, w.get(feature::SIGNATURE_INVALID).unwrap().log_lr);
        for name in [
            feature::SIGNED_MICROSOFT_CATALOG,
            feature::SIGNED_TRUSTED_PUBLISHER,
            feature::SIGNATURE_INVALID,
            feature::SIGNATURE_SELF_SIGNED,
            feature::SIGNATURE_EXPIRED,
            feature::SIGNATURE_UNVERIFIABLE,
            feature::UNSIGNED_IN_SYSTEM_ZONE,
            feature::UNSIGNED_IN_PROGRAM_FILES,
            feature::UNSIGNED_IN_USER_ZONE,
        ] {
            assert_eq!(w.get(name).unwrap().group, group::SIGNATURE, "`{name}` left the group");
            assert!(w.get(name).unwrap().log_lr <= bound);
        }
        assert_eq!(w.max_log_lr_in_group("no such group"), 0.0);
    }

    #[test]
    fn the_incident_window_shares_the_group_of_the_evidence_that_built_it() {
        let w = Weights::embedded();
        let window = w.get(feature::CREATED_IN_INCIDENT_WINDOW).unwrap();
        for name in [feature::DELETED_SOON_AFTER_EXECUTION, feature::EXECUTED_BUT_NOW_ABSENT] {
            assert_eq!(
                w.get(name).unwrap().group,
                window.group,
                "`{name}` and the incident window must not be able to stack"
            );
            assert!(
                w.get(name).unwrap().log_lr > window.log_lr,
                "corroboration must lose to the evidence it corroborates"
            );
        }
    }

    #[test]
    fn malformed_tables_are_rejected() {
        assert!(Weights::parse("not toml at all {{{").is_err());
        assert!(Weights::parse("[meta]\nversion = 1\ncalibrated = false\n").is_err());
        assert!(Weights::parse(
            "[meta]\nversion=1\ncalibrated=false\n[features.x]\ngroup=\"\"\nlog_lr=1.0\nrationale=\"r\"\n"
        )
        .is_err());
        assert!(Weights::parse(
            "[meta]\nversion=1\ncalibrated=false\n[features.x]\ngroup=\"g\"\nlog_lr=nan\nrationale=\"r\"\n"
        )
        .is_err());
    }

    fn table() -> Weights {
        Weights::parse(
            r#"
[meta]
version = 1
calibrated = false
[features.weak]
group = "g"
log_lr = 1.0
rationale = "weak"
benign_rate = "0 of 1"
[features.strong]
group = "g"
log_lr = 4.0
rationale = "strong"
benign_rate = "0 of 1"
[features.other]
group = "h"
log_lr = 2.0
rationale = "other"
benign_rate = "0 of 1"
"#,
        )
        .unwrap()
    }

    #[test]
    fn only_the_strongest_of_a_group_scores() {
        let w = table();
        let mut set = EvidenceSet::new();
        set.offer(&w, "weak", "weak detail", vec![]);
        set.offer(&w, "strong", "strong detail", vec![]);
        set.offer(&w, "other", "other detail", vec![]);

        let evidence = set.into_evidence();
        assert_eq!(evidence.len(), 2, "one per group");
        let total: f64 = evidence.iter().map(|e| e.log_lr).sum();
        assert!((total - 6.0).abs() < 1e-9, "should be 4.0 + 2.0, got {total}");
    }

    #[test]
    fn group_selection_is_order_independent() {
        let w = table();
        let mut a = EvidenceSet::new();
        a.offer(&w, "strong", "s", vec![]);
        a.offer(&w, "weak", "w", vec![]);

        let mut b = EvidenceSet::new();
        b.offer(&w, "weak", "w", vec![]);
        b.offer(&w, "strong", "s", vec![]);

        let sum = |set: EvidenceSet| set.into_evidence().iter().map(|e| e.log_lr).sum::<f64>();
        assert_eq!(sum(a), sum(b));
    }

    #[test]
    fn superseded_evidence_keeps_its_explanation() {
        let w = table();
        let mut set = EvidenceSet::new();
        set.offer(&w, "weak", "the weaker thing", vec![]);
        set.offer(&w, "strong", "the stronger thing", vec![]);

        let evidence = set.into_evidence();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].detail.contains("the stronger thing"));
        assert!(evidence[0].detail.contains("the weaker thing"), "lost the superseded explanation");
    }

    #[test]
    fn unknown_features_are_ignored_not_fatal() {
        let w = table();
        let mut set = EvidenceSet::new();
        set.offer(&w, "no_such_feature", "detail", vec![]);
        assert!(set.into_evidence().is_empty());
    }

    #[test]
    fn evidence_comes_out_strongest_first() {
        let w = Weights::embedded();
        let mut set = EvidenceSet::new();
        set.offer(&w, feature::NAME_UNIQUE_ON_MACHINE, "d", vec![]);
        set.offer(&w, feature::QUARANTINED_BY_AV, "d", vec![]);
        set.offer(&w, feature::SIGNED_MICROSOFT_CATALOG, "d", vec![]);

        let evidence = set.into_evidence();
        assert_eq!(evidence[0].feature, feature::QUARANTINED_BY_AV);
        assert_eq!(evidence.last().unwrap().feature, feature::SIGNED_MICROSOFT_CATALOG);
    }
}
