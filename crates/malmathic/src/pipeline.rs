use std::collections::HashSet;
use std::io::{Read, Seek};

use mm_core::{
    ArtifactSource, Candidate, NormalizedPath, Observation, ObservationKind, OutOfBandArrival,
    SignatureStatus, VolumeIdentity, VolumeRef,
};
use mm_env::Environment;
use mm_harvest::{filesystem, HiveSource};
use mm_raw::Volume;
use mm_report::{Coverage, CoverageStatus, ForeignPath, OtherVolume, Report, Target};
use mm_score::weights::group;
use mm_score::{zone, Baseline, BaselineBuilder, Weights};

use crate::acquire::{ClusterMap, QuarantineStore, RecycleBinStore, RecycledPointer};
use crate::progress::{Stage, Style};

mod limits {
    pub const HIVE: usize = 384 * 1024 * 1024;
    pub const AMCACHE: usize = 128 * 1024 * 1024;
    pub const PREFETCH: usize = 8 * 1024 * 1024;

    pub const PCA: usize = 64 * 1024 * 1024;
    pub const TASK: usize = 2 * 1024 * 1024;
    pub const QUARANTINE: usize = 64 * 1024 * 1024;
    pub const EVENT_LOG: usize = 256 * 1024 * 1024;
    pub const TASK_DEPTH: usize = 8;
    pub const STARTUP_LINK: usize = mm_harvest::startup::MAX_LINK_BYTES;
    pub const STARTUP_ENTRIES: usize = 4096;
    pub const STARTUP_TOTAL_BYTES: usize = 64 * 1024 * 1024;
    pub const RECYCLE_INFO: usize = mm_harvest::recycle_bin::MAX_INFO_BYTES;
    pub const RECYCLE_PROFILES: usize = 256;
    pub const RECYCLE_STUBS: usize = 8192;
    pub const VERIFY: usize = 256 * 1024 * 1024;
}

fn guarded<T, F>(step: F) -> std::result::Result<T, String>
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    std::panic::catch_unwind(step).map_err(|payload| {
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "the parser panicked".to_string());
        format!("parser failure: {message}")
    })
}

mod paths {
    pub const SOFTWARE: &str = "\\Windows\\System32\\config\\SOFTWARE";
    pub const SYSTEM: &str = "\\Windows\\System32\\config\\SYSTEM";
    pub const AMCACHE: &str = "\\Windows\\appcompat\\Programs\\Amcache.hve";
    pub const USERS: &str = "\\Users";
    pub const PREFETCH: &str = "\\Windows\\Prefetch";
    pub const PCA: &str = "\\Windows\\appcompat\\pca";
    pub const TASKS: &str = "\\Windows\\System32\\Tasks";
    pub const COMMON_STARTUP: &str =
        "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
    pub const USER_STARTUP_SUFFIX: &str =
        "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    pub const RECYCLE_BIN: &str = "\\$Recycle.Bin";
    pub const QUARANTINE_ENTRIES: &str =
        "\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\Entries";
    pub const DEFENDER_LOG: &str =
        "\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx";
}

const NON_PROFILE_DIRECTORIES: &[&str] =
    &["public", "default", "default user", "all users", "desktop.ini"];

pub struct Options {
    pub output_dir: std::path::PathBuf,
    pub acquire_top: usize,
    pub write_samples: bool,
    pub deep: bool,
    pub verify_top: usize,
    pub progress: Style,
}

fn decodes_compact_os(name: &str) -> bool {
    (0..8u32).any(|algorithm| {
        let backing = mm_raw::wof::Backing { provider: mm_raw::wof::WOF_PROVIDER_FILE, algorithm };
        backing.chunk_size().is_some() && backing.algorithm_name() == name
    })
}

fn detail_of(status: &CoverageStatus) -> String {
    match status {
        CoverageStatus::Read { observations } => format!("{observations} observations"),
        CoverageStatus::Absent => "not present".to_string(),
        CoverageStatus::Failed { .. } => "FAILED".to_string(),
        CoverageStatus::NotAvailableHere { .. } => "not applicable".to_string(),
    }
}

fn settle(
    stage: Stage,
    coverage: &mut Coverage,
    label: impl Into<String>,
    status: CoverageStatus,
) -> f64 {
    let label = label.into();
    let seconds = stage.finish_as(&label, &detail_of(&status));
    coverage.record_timed(label, status, seconds);
    seconds
}

pub fn run<R: Read + Seek>(
    volume: &Volume<R>,
    environment: Environment,
    target: Target,
    options: &Options,
) -> Report {
    let mut coverage = Coverage::default();
    let mut observations = Vec::new();
    let mut identity = VolumeIdentity::new(volume.serial());

    let style = options.progress;

    let startup_folders =
        harvest_registry(volume, &mut observations, &mut identity, &mut coverage, style);
    harvest_startup_folders(volume, &startup_folders, &mut observations, &mut coverage, style);
    harvest_amcache(volume, &mut observations, &mut coverage, style);
    harvest_prefetch(volume, &mut observations, &mut coverage, style);
    harvest_pca(volume, &mut observations, &mut coverage, style);
    harvest_tasks(volume, &mut observations, &mut coverage, style);
    let quarantine = harvest_quarantine(volume, &mut observations, &mut coverage, style);
    let recycle_bin =
        harvest_recycle_bin(volume, &identity, &mut observations, &mut coverage, style);
    harvest_defender_log(volume, &mut observations, &mut coverage, style);

    withhold_other_volumes(&mut observations, &identity, &mut coverage);

    if let Some(reason) = environment.no_processes_reason() {
        coverage.record(
            "live process memory",
            CoverageStatus::NotAvailableHere { reason: reason.into() },
        );
    }

    let com = Stage::begin("COM class registrations", style);
    let hijacks = promote_com_hijacks(&mut observations);
    let superseded = relabel_superseded_com_registrations(&mut observations);
    let registrations = count_com_registrations(&observations);
    let deferred_com = defer_ordinary_com_registrations(&mut observations);
    settle(
        com,
        &mut coverage,
        "COM class registrations",
        CoverageStatus::Read { observations: registrations },
    );
    if registrations > 0 {
        coverage.record(
            "COM class redirections (hijacks)",
            if hijacks == 0 {
                CoverageStatus::Absent
            } else {
                CoverageStatus::Read { observations: hijacks }
            },
        );
        coverage.record(
            "COM registrations superseded by a live machine-wide one",
            if superseded == 0 {
                CoverageStatus::Absent
            } else {
                CoverageStatus::Read { observations: superseded }
            },
        );
    }

    let referenced: HashSet<String> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect();

    let deferred_av = defer_defender_log(&mut observations);
    let deferred_values = defer_deleted_registry_values(&mut observations);

    let Walk { baseline, out_of_band, junctions, orphans, enumeration, mass_encryption } =
        walk_filesystem(volume, &referenced, &mut observations, &mut coverage, style);

    reattach_deferred_com(&mut observations, deferred_com);
    reattach_defender_log(&mut observations, deferred_av, &mut coverage);
    reattach_deleted_registry_values(&mut observations, deferred_values, &mut coverage);

    canonicalize_through_junctions(volume, &junctions, &mut observations, &mut coverage);

    let index_slack = harvest_index_slack(volume, &observations, &mut coverage, style);

    let journal_clock = harvest_usn_journal(volume, &mut observations, &mut coverage, style);

    let weights = Weights::embedded();
    let scoring = Stage::begin("scoring", style);
    let mut candidates = build_and_score(observations, &baseline, &weights, &enumeration);
    settle(
        scoring,
        &mut coverage,
        "scoring",
        CoverageStatus::Read { observations: candidates.len() },
    );

    verify_signatures(
        volume,
        &mut candidates,
        &baseline,
        &weights,
        options,
        &out_of_band,
        &mut coverage,
    );

    let (incident_window, window) = apply_incident_window(
        &mut candidates,
        &baseline,
        &weights,
        &journal_clock,
        &mut coverage,
        style,
    );

    acquire_samples(
        volume,
        &quarantine,
        &recycle_bin,
        &orphans,
        &index_slack,
        &mut candidates,
        options,
        &mut coverage,
        style,
    );

    relink_shared_digests_after_acquisition(
        &mut candidates,
        &baseline,
        &weights,
        window.as_ref(),
        &mut coverage,
        style,
    );

    coverage.baseline_usable = baseline.is_usable();
    let mut report = Report::new(
        env!("CARGO_PKG_VERSION"),
        environment.label(),
        target,
        candidates,
        coverage,
        weights.is_calibrated(),
    );
    report.set_enumeration(enumeration);
    if let Some(found) = mass_encryption {
        report.set_mass_encryption(found);
    }
    harvest_arrivals(volume, &mut report, incident_window, style);
    report
}

#[derive(Default)]
struct StartupFolders {
    dirs: Vec<(String, Option<String>)>,
    notes: Vec<String>,
}

impl StartupFolders {
    fn add(&mut self, redirect: Option<String>, default: String, profile: Option<String>) {
        let scope = match &profile {
            Some(p) => p.rsplit('\\').next().unwrap_or(p).to_string(),
            None => "all users".to_string(),
        };
        let directory = match redirect {
            None => default,
            Some(raw) => match mm_harvest::startup::resolve_directory(&raw, profile.as_deref()) {
                Some(resolved) if resolved.eq_ignore_ascii_case(&default) => default,
                Some(resolved) => {
                    self.notes.push(format!(
                        "the Startup folder for {scope} is redirected to {resolved}"
                    ));
                    resolved
                }
                None => {
                    self.notes.push(format!(
                        "the Startup folder for {scope} is redirected to \"{raw}\", which does not \
                         name a directory on this volume — it was not read"
                    ));
                    return;
                }
            },
        };
        self.dirs.push((directory, profile));
    }
}

fn harvest_registry<R: Read + Seek>(
    volume: &Volume<R>,
    out: &mut Vec<Observation>,
    identity: &mut VolumeIdentity,
    coverage: &mut Coverage,
    style: Style,
) -> StartupFolders {
    let mut startup = StartupFolders::default();
    let mut common_startup: Option<String> = None;
    let mut system_root: Option<String> = None;
    let mut mounted: Vec<(char, String)> = Vec::new();

    if let Some(o) = read_hive(
        volume,
        paths::SOFTWARE,
        limits::HIVE,
        coverage,
        "SOFTWARE hive",
        style,
        |bytes| {
            common_startup =
                mm_harvest::persistence::startup_redirect(bytes, &HiveSource::Software);
            system_root = mm_harvest::persistence::system_root(bytes, &HiveSource::Software);
            let mut o = mm_harvest::persistence::harvest(bytes, &HiveSource::Software);
            o.extend(mm_harvest::useractivity::harvest(bytes, &HiveSource::Software));
            o
        },
    ) {
        out.extend(o);
    }
    startup.add(common_startup, paths::COMMON_STARTUP.to_string(), None);

    if let Some(o) =
        read_hive(volume, paths::SYSTEM, limits::HIVE, coverage, "SYSTEM hive", style, |bytes| {
            mounted = mm_harvest::persistence::mounted_devices(bytes, &HiveSource::System);
            let mut o = mm_harvest::persistence::harvest(bytes, &HiveSource::System);
            o.extend(mm_harvest::shimcache::harvest(bytes));
            o.extend(mm_harvest::useractivity::harvest(bytes, &HiveSource::System));
            o
        })
    {
        out.extend(o);
    }

    if let Some(root) = &system_root {
        identity.set_system_root(root);
    }
    identity.set_mounted_devices(mounted);
    match identity.system_letter() {
        Some(letter) => coverage.record(
            format!("this volume's own drive letter ({}:)", letter.to_ascii_uppercase()),
            CoverageStatus::Read { observations: 1 },
        ),
        None => coverage.record(
            "this volume's own drive letter (not established; paths naming another \
             volume cannot be told apart from paths on this one)",
            CoverageStatus::Absent,
        ),
    }

    let stage = Stage::begin("user hives", style);
    let mut users_read = 0usize;
    let mut user_observations = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for user in enumerate_users(volume) {
        let profile = format!("{}\\{user}", paths::USERS);
        let default_startup = format!("{profile}\\{}", paths::USER_STARTUP_SUFFIX);

        let ntuser = format!("{profile}\\NTUSER.DAT");
        let hive = volume.read_capped(&ntuser, limits::HIVE).ok();

        let redirect = hive.as_ref().and_then(|bytes| {
            guarded(std::panic::AssertUnwindSafe(|| {
                mm_harvest::persistence::startup_redirect(
                    bytes,
                    &HiveSource::NtUser { user: user.clone() },
                )
            }))
            .unwrap_or(None)
        });
        startup.add(redirect, default_startup, Some(profile.clone()));

        if let Some(bytes) = hive {
            users_read += 1;
            let source = HiveSource::NtUser { user: user.clone() };
            let harvested = guarded(std::panic::AssertUnwindSafe(|| {
                let mut o = mm_harvest::persistence::harvest(&bytes, &source);
                o.extend(mm_harvest::useractivity::harvest(&bytes, &source));
                o
            }));
            match harvested {
                Ok(o) => {
                    user_observations += o.len();
                    out.extend(o);
                }
                Err(reason) => failures.push(format!("{user}: {reason}")),
            }
        }

        let usrclass =
            format!("{}\\{user}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", paths::USERS);
        if let Ok(bytes) = volume.read_capped(&usrclass, limits::HIVE) {
            let source = HiveSource::UsrClass { user: user.clone() };
            match guarded(std::panic::AssertUnwindSafe(|| {
                mm_harvest::persistence::harvest(&bytes, &source)
            })) {
                Ok(o) => {
                    user_observations += o.len();
                    out.extend(o);
                }
                Err(reason) => failures.push(format!("{user} (UsrClass): {reason}")),
            }
        }
    }
    settle(
        stage,
        coverage,
        format!("user hives ({users_read} profile{})", if users_read == 1 { "" } else { "s" }),
        if users_read == 0 {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: user_observations }
        },
    );
    for failure in failures {
        coverage.warn(format!("a user hive could not be parsed — {failure}"));
    }
    startup
}

fn withhold_other_volumes(
    observations: &mut Vec<Observation>,
    identity: &VolumeIdentity,
    coverage: &mut Coverage,
) {
    const MAX_VOLUMES: usize = 26;
    const MAX_PATHS_PER_VOLUME: usize = 64;

    let mut order: Vec<String> = Vec::new();
    let mut found: std::collections::HashMap<String, (VolumeRef, usize, Vec<ForeignPath>)> =
        std::collections::HashMap::new();

    observations.retain(|observation| {
        let Some(path) = &observation.path else {
            return true;
        };
        if identity.judge(path.volume()).resolvable_here() {
            return true;
        }
        let volume = path.volume().clone();
        let label = volume.label();
        let entry = found.entry(label.clone()).or_insert_with(|| {
            if order.len() < MAX_VOLUMES {
                order.push(label.clone());
            }
            (volume, 0, Vec::new())
        });
        entry.1 += 1;
        if entry.2.len() < MAX_PATHS_PER_VOLUME {
            entry.2.push(ForeignPath {
                path: path.raw().to_string(),
                source: observation.source.label(),
                claim: claim_of(&observation.kind),
            });
        }
        false
    });

    if found.is_empty() {
        return;
    }

    let quarantined: Vec<&ForeignPath> = found
        .values()
        .flat_map(|(_, _, paths)| paths.iter())
        .filter(|p| p.claim.starts_with("quarantined by"))
        .collect();
    if !quarantined.is_empty() {
        let names: Vec<&str> = quarantined.iter().map(|p| p.path.as_str()).collect();
        coverage.warn(format!(
            "{} quarantine entr{} name a file on another volume ({}). The payload is held \
             in Defender's quarantine store ON THIS VOLUME and was not extracted, because \
             this run cannot form a candidate for a file it cannot examine. Recover it by \
             hand from \\ProgramData\\Microsoft\\Windows Defender\\Quarantine.",
            quarantined.len(),
            if quarantined.len() == 1 { "y names" } else { "ies name" },
            names.join(", "),
        ));
    }

    let mut withheld = 0usize;
    for label in order {
        let Some((volume, count, paths)) = found.remove(&label) else {
            continue;
        };
        withheld += count;
        let identified_as = match volume {
            VolumeRef::Letter(letter) => identity.mounted_as(letter).map(str::to_string),
            _ => None,
        };
        coverage.other_volumes.push(OtherVolume {
            volume: label,
            identified_as,
            observations: count,
            paths,
        });
    }
    withheld += found.values().map(|(_, count, _)| *count).sum::<usize>();

    coverage.record(
        "paths recorded on a volume this run did not examine",
        CoverageStatus::Read { observations: withheld },
    );
}

fn claim_of(kind: &ObservationKind) -> String {
    match kind {
        ObservationKind::FileExists { .. } => "present on the volume that recorded it".into(),
        ObservationKind::FileDeleted { .. } => "recorded as deleted".into(),
        ObservationKind::Executed { .. } => "executed".into(),
        ObservationKind::Persistence { kind, .. } => {
            format!("wired to run again ({})", kind.label())
        }
        ObservationKind::DownloadedFrom { .. } => "carries a Mark of the Web".into(),
        ObservationKind::HashRecovered => "a hash was recovered".into(),
        ObservationKind::Signature(_) => "a signature verdict".into(),
        ObservationKind::ManagedAssembly => "a managed .NET assembly".into(),
        ObservationKind::NoVersionResource => "carries no version resource".into(),
        ObservationKind::RichHeaderChecksumInvalid { .. } => {
            "carries a Rich header the linker did not write".into()
        }
        ObservationKind::Quarantined { product, .. } => format!("quarantined by {product}"),
        ObservationKind::AvDetected { product, .. } => format!("detected by {product}"),
        _ => "recorded by an artifact on this volume".into(),
    }
}

fn harvest_startup_folders<R: Read + Seek>(
    volume: &Volume<R>,
    folders: &StartupFolders,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) {
    let stage = Stage::begin("Startup folders", style);

    let mut entries = 0usize;
    let mut observations = 0usize;
    let mut dangling: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    let mut budget = limits::STARTUP_TOTAL_BYTES;

    for (directory, profile) in &folders.dirs {
        for name in volume.list_directory(directory).into_iter().take(limits::STARTUP_ENTRIES) {
            let at = mm_harvest::startup::Location {
                directory: directory.clone(),
                name,
                profile: profile.clone(),
            };
            let is_link = at.name.to_ascii_lowercase().ends_with(".lnk");
            let want = if is_link { limits::STARTUP_LINK } else { 1 };
            let want = want.min(budget);
            let bytes = match volume.read_capped(&at.full_path(), want) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            budget = budget.saturating_sub(bytes.len());

            let entry = match guarded(std::panic::AssertUnwindSafe(|| {
                mm_harvest::startup::harvest(&at, &bytes)
            })) {
                Ok(entry) => entry,
                Err(reason) => {
                    unreadable.push(format!("{} — {reason}", at.full_path()));
                    continue;
                }
            };

            match entry {
                mm_harvest::startup::Entry::Link { observation, target, .. } => {
                    entries += 1;
                    observations += 1;
                    if !volume.exists(target.key()) {
                        dangling.push(format!("{} points at {}", at.full_path(), target.key()));
                    }
                    out.push(observation);
                }
                mm_harvest::startup::Entry::File { observation, .. } => {
                    entries += 1;
                    observations += 1;
                    out.push(observation);
                }
                mm_harvest::startup::Entry::UnreadableLink { reason } => {
                    entries += 1;
                    unreadable.push(format!("{} — {reason}", at.full_path()));
                }
                mm_harvest::startup::Entry::Ignored => {}
            }
        }
    }

    settle(
        stage,
        coverage,
        format!(
            "Startup folders ({} scope{})",
            folders.dirs.len(),
            if folders.dirs.len() == 1 { "" } else { "s" }
        ),
        if entries == 0 { CoverageStatus::Absent } else { CoverageStatus::Read { observations } },
    );

    for note in &folders.notes {
        coverage.warn(note.clone());
    }
    for link in unreadable {
        coverage.warn(format!(
            "a shortcut in a Startup folder could not be resolved — {link} (inspect it by hand)"
        ));
    }
    for link in dangling {
        coverage
            .warn(format!("a Startup shortcut names a file that is not on this volume — {link}"));
    }
}

fn harvest_amcache<R: Read + Seek>(
    volume: &Volume<R>,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) {
    if let Some(o) =
        read_hive(volume, paths::AMCACHE, limits::AMCACHE, coverage, "Amcache", style, |bytes| {
            mm_harvest::amcache::harvest(bytes)
        })
    {
        out.extend(o);
    }
}

fn harvest_prefetch<R: Read + Seek>(
    volume: &Volume<R>,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) {
    let stage = Stage::begin("Prefetch", style);
    let files = volume.read_directory_files(paths::PREFETCH, limits::PREFETCH, |name| {
        name.to_ascii_lowercase().ends_with(".pf")
    });

    if files.is_empty() {
        settle(stage, coverage, "Prefetch", CoverageStatus::Absent);
        return;
    }

    let mut count = 0;
    for (name, bytes) in files {
        if let Ok(o) =
            guarded(std::panic::AssertUnwindSafe(|| mm_harvest::prefetch::harvest(&bytes, &name)))
        {
            count += o.len();
            out.extend(o);
        }
    }
    settle(stage, coverage, "Prefetch", CoverageStatus::Read { observations: count });
}

fn harvest_pca<R: Read + Seek>(
    volume: &Volume<R>,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) {
    let stage = Stage::begin("PCA", style);

    let users = enumerate_users(volume);
    let sole_profile = match users.as_slice() {
        [only] => Some(format!("{}\\{only}", paths::USERS)),
        _ => None,
    };

    let mut count = 0;
    let mut rows = 0;
    let mut unattributed = 0;
    let mut malformed = 0;
    let mut read_any = false;

    for name in ["PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt"] {
        let path = format!("{}\\{name}", paths::PCA);
        let Ok(bytes) = volume.read_capped(&path, limits::PCA) else { continue };
        read_any = true;
        let launch_dic = name.contains("AppLaunch");
        let profile = sole_profile.clone();
        let harvested = guarded(std::panic::AssertUnwindSafe(move || {
            if launch_dic {
                mm_harvest::pca::harvest_app_launch(&bytes)
            } else {
                mm_harvest::pca::harvest_general_db(&bytes, profile.as_deref())
            }
        }));
        if let Ok(pca) = harvested {
            rows += pca.rows;
            unattributed += pca.unattributed;
            malformed += pca.malformed;
            count += pca.observations.len();
            out.extend(pca.observations);
        }
    }

    if !read_any {
        settle(stage, coverage, "PCA (Windows 11 only)", CoverageStatus::Absent);
        return;
    }

    let label = if unattributed > 0 {
        format!(
            "PCA ({rows} rows; {unattributed} name a user-profile path and this machine has \
             {} profiles, so which file they mean is undecidable and they were not used)",
            users.len()
        )
    } else if malformed > 0 {
        format!("PCA ({rows} rows, {malformed} malformed)")
    } else {
        format!("PCA ({rows} rows)")
    };
    settle(stage, coverage, &label, CoverageStatus::Read { observations: count });
}

pub(crate) fn harvest_tasks<R: Read + Seek>(
    volume: &Volume<R>,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) {
    let mut stage = Stage::begin("scheduled tasks", style);
    let mut count = 0;
    let mut visited = 0;
    let root = volume
        .resolve(paths::TASKS)
        .and_then(|record| volume.list_directory_entries_of_record(record).ok());
    let mut sweep = |path: &str, bytes: &[u8]| {
        visited += 1;
        stage.tick(visited, 0);
        if let Ok(o) =
            guarded(std::panic::AssertUnwindSafe(|| mm_harvest::tasks::harvest(bytes, path)))
        {
            count += o.len();
            out.extend(o);
        }
    };
    if let Some(entries) = root {
        walk_tasks(volume, paths::TASKS, entries, 0, &mut sweep);
    }

    settle(
        stage,
        coverage,
        "scheduled tasks",
        if visited == 0 {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: count }
        },
    );
}

fn walk_tasks<R: Read + Seek>(
    volume: &Volume<R>,
    directory: &str,
    entries: Vec<mm_raw::DirectoryEntry>,
    depth: usize,
    visit: &mut dyn FnMut(&str, &[u8]),
) {
    for entry in entries {
        let child = format!("{}\\{}", directory.trim_end_matches('\\'), entry.name);
        match volume.read_record_capped(entry.record, limits::TASK) {
            Ok(bytes) if !bytes.is_empty() => visit(&child, &bytes),
            _ if depth < limits::TASK_DEPTH => {
                if let Ok(children) = volume.list_directory_entries_of_record(entry.record) {
                    walk_tasks(volume, &child, children, depth + 1, visit);
                }
            }
            _ => {}
        }
    }
}

fn harvest_quarantine<R: Read + Seek>(
    volume: &Volume<R>,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) -> QuarantineStore {
    let stage = Stage::begin("Defender quarantine", style);
    let mut store = QuarantineStore::new();
    let entries =
        volume.read_directory_files(paths::QUARANTINE_ENTRIES, limits::QUARANTINE, |_| true);

    if entries.is_empty() {
        settle(stage, coverage, "Defender quarantine", CoverageStatus::Absent);
        return store;
    }

    let mut count = 0;
    for (_, bytes) in entries {
        if let Ok((o, recoverable)) = guarded(std::panic::AssertUnwindSafe(|| {
            mm_harvest::quarantine::harvest_entry_with_recovery(&bytes)
        })) {
            count += o.len();
            out.extend(o);
            store.add(recoverable);
        }
    }
    settle(stage, coverage, "Defender quarantine", CoverageStatus::Read { observations: count });

    coverage.record(
        "Defender quarantine payloads",
        if store.is_empty() {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: store.len() }
        },
    );
    store
}

fn harvest_recycle_bin<R: Read + Seek>(
    volume: &Volume<R>,
    identity: &VolumeIdentity,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) -> RecycleBinStore {
    const LABEL: &str = "recycle bin";
    let stage = Stage::begin(LABEL, style);
    let mut store = RecycleBinStore::new();

    let profiles = volume.list_directory_entries(paths::RECYCLE_BIN);
    if profiles.is_empty() {
        settle(stage, coverage, LABEL, CoverageStatus::Absent);
        return store;
    }

    let mut observations = 0usize;
    let mut stubs_read = 0usize;
    let mut unreadable = 0usize;
    let mut orphaned_stubs = 0usize;
    let mut capped = false;

    for profile in profiles.into_iter().take(limits::RECYCLE_PROFILES) {
        let Ok(entries) = volume.list_directory_entries_of_record(profile.record) else {
            coverage.warn(format!(
                "the recycle bin directory `{}` could not be listed, so any file deleted by that \
                 user is not accounted for",
                profile.name
            ));
            continue;
        };

        let names: HashSet<String> = entries.iter().map(|e| e.name.to_lowercase()).collect();

        for entry in &entries {
            if !mm_harvest::recycle_bin::is_info_name(&entry.name) {
                continue;
            }
            if stubs_read >= limits::RECYCLE_STUBS {
                capped = true;
                break;
            }
            stubs_read += 1;

            let Ok(bytes) = volume.read_record_capped(entry.record, limits::RECYCLE_INFO) else {
                unreadable += 1;
                continue;
            };
            let Ok(parsed) = guarded(std::panic::AssertUnwindSafe(|| {
                mm_harvest::recycle_bin::parse_info(&bytes)
            })) else {
                unreadable += 1;
                continue;
            };
            let Some(file) = parsed else {
                unreadable += 1;
                continue;
            };

            let info_path = format!("{}\\{}\\{}", paths::RECYCLE_BIN, profile.name, entry.name);

            let here = identity.judge(file.original.volume()).resolvable_here();

            if file.original.is_executable_extension() {
                out.push(Observation::about_path(
                    ArtifactSource::RecycleBin,
                    file.original.clone(),
                    ObservationKind::FileDeleted {
                        when: file.deleted,
                        record: None,
                        sequence: None,
                    },
                ));
                observations += 1;
            }

            if !here {
                continue;
            }
            let Some(data_name) = mm_harvest::recycle_bin::data_file_name(&entry.name) else {
                continue;
            };
            if !names.contains(&data_name.to_lowercase()) {
                orphaned_stubs += 1;
                continue;
            }
            store.add(
                &file.original,
                RecycledPointer {
                    data_path: format!("{}\\{}\\{}", paths::RECYCLE_BIN, profile.name, data_name),
                    info_path,
                    original_raw: file.original.raw().to_string(),
                    claimed_size: file.original_size,
                    deleted: file.deleted.map(mm_core::filetime::format),
                    layout: file.layout.label(),
                },
            );
        }
        if capped {
            break;
        }
    }

    if capped {
        coverage.warn(format!(
            "the recycle bin holds more than {} `$I` stubs, so it was read only that far — \
             whether anything was deleted beyond that point is unknown",
            limits::RECYCLE_STUBS
        ));
    }
    if unreadable > 0 {
        coverage.warn(format!(
            "{unreadable} of {stubs_read} `$Recycle.Bin` `$I` stub(s) could not be read or would \
             not parse, so where those files came from is unknown"
        ));
    }

    settle(stage, coverage, LABEL, CoverageStatus::Read { observations });

    coverage.record(
        "recycle bin payloads",
        if store.is_empty() {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: store.len() }
        },
    );
    if orphaned_stubs > 0 {
        coverage.warn(format!(
            "{orphaned_stubs} `$Recycle.Bin` stub(s) name a deleted file whose `$R` copy is no \
             longer in the bin — the original path and deletion time survive, the bytes do not"
        ));
    }
    store
}

fn harvest_defender_log<R: Read + Seek>(
    volume: &Volume<R>,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) {
    const LABEL: &str = "Defender event log";
    let stage = Stage::begin(LABEL, style);

    if !volume.exists(paths::DEFENDER_LOG) {
        settle(stage, coverage, LABEL, CoverageStatus::Absent);
        return;
    }

    let bytes = match volume.read_capped(paths::DEFENDER_LOG, limits::EVENT_LOG) {
        Ok(bytes) => bytes,
        Err(e) => {
            settle(stage, coverage, LABEL, CoverageStatus::Failed { reason: e.to_string() });
            return;
        }
    };

    match guarded(std::panic::AssertUnwindSafe(|| mm_harvest::defender_log::harvest(&bytes))) {
        Ok(observations) => {
            settle(
                stage,
                coverage,
                LABEL,
                CoverageStatus::Read { observations: observations.len() },
            );
            out.extend(observations);
        }
        Err(reason) => {
            settle(stage, coverage, LABEL, CoverageStatus::Failed { reason });
        }
    }
}

fn harvest_usn_journal<R: Read + Seek>(
    volume: &Volume<R>,
    observations: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) -> mm_harvest::usn_journal::Clock {
    const LABEL: &str = "USN change journal";
    let stage = Stage::begin(LABEL, style);

    let mut known: HashSet<String> = HashSet::new();
    let mut present: HashSet<String> = HashSet::new();
    for observation in observations.iter() {
        let Some(path) = observation.path.as_ref() else { continue };
        known.insert(path.key().to_string());
        if matches!(observation.kind, ObservationKind::FileExists { .. }) {
            present.insert(path.key().to_string());
        }
    }

    let paths = mm_harvest::usn_journal::KnownPaths { known: &known, present: &present };
    let harvested =
        guarded(std::panic::AssertUnwindSafe(|| mm_harvest::usn_journal::harvest(volume, &paths)));
    let harvest = match harvested {
        Ok(harvest) => harvest,
        Err(reason) => {
            coverage.warn(format!(
                "the USN change journal could not be read ({reason}). No deletion on this \
                 volume carries a driver-written time in this report, and that is a \
                 failure of this run rather than a fact about the disk"
            ));
            settle(stage, coverage, LABEL, CoverageStatus::Failed { reason });
            return mm_harvest::usn_journal::Clock::default();
        }
    };

    let status = match &harvest.state.verdict {
        mm_raw::usn::Verdict::NoJournal => CoverageStatus::Absent,
        _ => CoverageStatus::Read { observations: harvest.observations.len() },
    };
    settle(stage, coverage, format!("{LABEL} — {}", harvest.state.summary()), status);

    if !harvest.observations.is_empty() || harvest.unresolved > 0 || harvest.path_refilled > 0 {
        coverage.record(
            format!("USN deletion times — {}", harvest.corroboration_summary()),
            CoverageStatus::Read { observations: harvest.observations.len() },
        );
    }
    if !harvest.creations.is_empty() || harvest.creations_unresolved > 0 {
        coverage.record(
            format!("USN creation times — {}", harvest.creation_summary()),
            CoverageStatus::Read { observations: harvest.creations.len() },
        );
    }
    for limit in harvest.state.limits() {
        coverage.warn(limit);
    }

    let clock = harvest.clock();
    observations.extend(harvest.observations);
    clock
}

fn harvest_arrivals<R: Read + Seek>(
    volume: &Volume<R>,
    report: &mut Report,
    window: Option<(mm_core::Moment, mm_core::Moment)>,
    style: Style,
) {
    const LABEL: &str = "arrival timeline (change journal)";

    let mut by_key: std::collections::HashMap<String, (mm_core::CandidateId, f64)> =
        std::collections::HashMap::new();
    for candidate in &report.candidates {
        if let Some(path) = candidate.path.as_ref() {
            by_key.entry(path.key().to_string()).or_insert((candidate.id, candidate.probability()));
        }
    }

    let findings: HashSet<mm_core::CandidateId> = report.reportable().map(|c| c.id).collect();
    let threshold = report.threshold;

    let mut anchors: Vec<mm_harvest::arrival::Anchor> = Vec::new();
    for candidate in &report.candidates {
        let Some(path) = candidate.path.as_ref() else { continue };
        let is_finding = findings.contains(&candidate.id);
        if !is_finding && window.is_none() {
            continue;
        }
        let Some(record) = candidate.observations.iter().find_map(|o| match &o.kind {
            ObservationKind::FileExists { record, .. } => *record,
            _ => None,
        }) else {
            continue;
        };
        anchors.push(mm_harvest::arrival::Anchor {
            candidate: candidate.id,
            display_path: path.display_path().to_string(),
            key: path.key().to_string(),
            record,
            probability: candidate.probability(),
            is_finding,
        });
    }

    if anchors.is_empty() {
        report.coverage.record(
            format!(
                "{LABEL} — no candidate on this volume may anchor one: nothing is above the \
                 reporting threshold{}",
                if window.is_some() {
                    ", and no candidate below it carries an $MFT record inside the incident window"
                } else {
                    " and no incident window was found"
                }
            ),
            CoverageStatus::NotAvailableHere {
                reason: "no anchor — a section a clean machine does not have".to_string(),
            },
        );
        return;
    }

    let stage = Stage::begin(LABEL, style);
    let context = mm_harvest::arrival::Context { candidates: &by_key, threshold, window };
    let built = guarded(std::panic::AssertUnwindSafe(|| {
        mm_harvest::arrival::read(volume, &anchors, &context)
    }));
    let timeline = match built {
        Ok(timeline) => timeline,
        Err(reason) => {
            settle(stage, &mut report.coverage, LABEL, CoverageStatus::Failed { reason });
            return;
        }
    };

    match timeline {
        Some(timeline) => {
            let detail = format!(
                "{LABEL} — {} of the journal's {} row(s) admitted, naming {} file(s) around \
                 {} anchor(s): a file is listed when it is a finding, when it is a candidate \
                 whose journal moment falls inside the incident window, or when it arrived \
                 in the same directory within {} s of one of those. Nothing here is scored",
                timeline.rows_admitted,
                timeline.rows_in_journal,
                timeline.files_named,
                timeline.anchors.len(),
                timeline.radius_seconds,
            );
            let observations = timeline.files_named;
            settle(stage, &mut report.coverage, detail, CoverageStatus::Read { observations });
            report.set_arrival_timeline(timeline);
        }
        None => {
            settle(
                stage,
                &mut report.coverage,
                LABEL,
                CoverageStatus::NotAvailableHere {
                    reason: "the change journal holds no row for any of these files, so how \
                             they arrived is UNKNOWN rather than answered"
                        .to_string(),
                },
            );
        }
    }
}

fn read_hive<R: Read + Seek, F>(
    volume: &Volume<R>,
    path: &str,
    cap: usize,
    coverage: &mut Coverage,
    label: &str,
    style: Style,
    harvest: F,
) -> Option<Vec<Observation>>
where
    F: FnOnce(&[u8]) -> Vec<Observation>,
{
    let stage = Stage::begin(label, style);
    match volume.read_capped(path, cap) {
        Ok(bytes) => match guarded(std::panic::AssertUnwindSafe(move || harvest(&bytes))) {
            Ok(observations) => {
                let status = CoverageStatus::Read { observations: observations.len() };
                settle(stage, coverage, label, status);
                Some(observations)
            }
            Err(reason) => {
                settle(stage, coverage, label, CoverageStatus::Failed { reason });
                None
            }
        },
        Err(e) => {
            settle(stage, coverage, label, CoverageStatus::Failed { reason: e.to_string() });
            None
        }
    }
}

fn enumerate_users<R: Read + Seek>(volume: &Volume<R>) -> Vec<String> {
    volume
        .list_directory(paths::USERS)
        .into_iter()
        .filter(|name| !NON_PROFILE_DIRECTORIES.contains(&name.to_ascii_lowercase().as_str()))
        .collect()
}

struct Walk {
    baseline: Baseline,
    out_of_band: HashSet<String>,
    junctions: Vec<filesystem::Junction>,
    orphans: crate::acquire::OrphanIndex,
    enumeration: mm_core::Enumeration,
    mass_encryption: Option<mm_core::MassEncryption>,
}

const MAX_JUNCTION_NOTES: usize = 12;

const MAX_JUNCTION_HOPS: usize = 8;

pub(crate) fn canonicalize_through_junctions<R: Read + Seek>(
    volume: &Volume<R>,
    junctions: &[filesystem::Junction],
    observations: &mut Vec<Observation>,
    coverage: &mut Coverage,
) {
    if junctions.is_empty() {
        coverage.record("junctions and directory symlinks", CoverageStatus::Absent);
        return;
    }

    let mut rules: Vec<(String, &str)> = junctions
        .iter()
        .filter_map(|j| Some((format!("{}\\", j.at.as_ref()?), j.target.as_deref()?)))
        .collect();
    rules.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));

    let refused: Vec<&filesystem::Junction> =
        junctions.iter().filter(|j| j.target.is_none()).collect();

    let translate = |key: &str| -> Option<String> {
        let mut current = key.to_string();
        let mut hops = 0;
        while hops < MAX_JUNCTION_HOPS {
            let Some((prefix, target)) =
                rules.iter().find(|(p, _)| current.starts_with(p.as_str()))
            else {
                break;
            };
            current = format!("{target}\\{}", &current[prefix.len()..]);
            hops += 1;
        }
        (hops > 0 && current != key).then_some(current)
    };

    let mut notes: Vec<String> = Vec::new();
    let mut translated = 0usize;
    let mut rewritten_keys: HashSet<String> = HashSet::new();
    let mut crossed_a_refusal: HashSet<String> = HashSet::new();

    let mut resolved: std::collections::HashMap<String, (String, u64)> =
        std::collections::HashMap::new();
    let mut refused_target: HashSet<String> = HashSet::new();
    for observation in observations.iter() {
        let Some(path) = observation.path.as_ref() else { continue };
        if observation.source == ArtifactSource::Mft {
            continue;
        }
        let key = path.key();
        for junction in &refused {
            if let Some(at) = junction.at.as_deref() {
                if key.len() > at.len() && key.starts_with(at) && key.as_bytes()[at.len()] == b'\\'
                {
                    crossed_a_refusal.insert(at.to_string());
                }
            }
        }
        if resolved.contains_key(key) || refused_target.contains(key) {
            continue;
        }
        let Some(canonical) = translate(key) else { continue };
        match volume.resolve(&canonical) {
            Some(record) => {
                resolved.insert(key.to_string(), (canonical, record));
            }
            None => {
                refused_target.insert(key.to_string());
            }
        }
    }

    for observation in observations.iter_mut() {
        if observation.source == ArtifactSource::Mft {
            continue;
        }
        let Some(path) = observation.path.as_ref() else { continue };
        let Some((canonical, _)) = resolved.get(path.key()) else { continue };
        let Some(rebased) = path.rebased(canonical) else { continue };
        if notes.len() < MAX_JUNCTION_NOTES && !rewritten_keys.contains(canonical) {
            notes.push(format!("{} -> {canonical}", path.key()));
        }
        rewritten_keys.insert(canonical.to_string());
        translated += 1;
        observation.path = Some(rebased);
    }

    let already: HashSet<String> = observations
        .iter()
        .filter(|o| o.source == ArtifactSource::Mft)
        .filter_map(|o| o.path.as_ref())
        .map(|p| p.key().to_string())
        .collect();
    let mut recovered = 0usize;
    for (canonical, record) in resolved.values() {
        if already.contains(canonical) || !rewritten_keys.contains(canonical) {
            continue;
        }
        let Some(facts) = filesystem::facts_for_record(volume, *record) else { continue };
        let Some(path) = mm_core::NormalizedPath::parse(canonical) else { continue };
        let found = filesystem::observations_for(&path, &facts);
        recovered += found.len();
        observations.extend(found);
    }
    if !refused_target.is_empty() {
        coverage.warn(format!(
            "{} artifact path(s) run through a junction whose target does not resolve on this \
             volume; they were left spelled as the artifact recorded them, and an absence \
             reported for one of them is UNKNOWN rather than a finding",
            refused_target.len()
        ));
    }

    coverage.record(
        format!(
            "junctions and directory symlinks ({} followed, {} not)",
            junctions.len() - refused.len(),
            refused.len()
        ),
        CoverageStatus::Read { observations: junctions.len() },
    );
    coverage.record(
        "artifact paths translated through a junction",
        if translated == 0 {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: translated }
        },
    );
    if translated > 0 {
        for note in &notes {
            coverage.warn(format!(
                "an artifact recorded a path through a junction; it names the same file as \
                 {note}, and was joined there rather than being reported missing"
            ));
        }
        if translated > notes.len() {
            coverage.warn(format!(
                "{} further artifact path(s) were translated the same way and are not listed \
                 individually",
                translated - notes.len()
            ));
        }
    }
    if recovered > 0 {
        coverage.record(
            "files found only after junction translation",
            CoverageStatus::Read { observations: recovered },
        );
    }
    for at in &crossed_a_refusal {
        let why = junctions
            .iter()
            .find(|j| j.at.as_deref() == Some(at.as_str()))
            .and_then(|j| j.refusal)
            .unwrap_or("the walk could not follow it");
        coverage.warn(format!(
            "an artifact named a path under `{at}`, which is a reparse point this run could not \
             follow — {why}. Nothing on the volume under that path was checked, so an absence \
             reported there is UNKNOWN and not a finding"
        ));
    }
}

fn walk_filesystem<R: Read + Seek>(
    volume: &Volume<R>,
    referenced: &HashSet<String>,
    out: &mut Vec<Observation>,
    coverage: &mut Coverage,
    style: Style,
) -> Walk {
    let mut builder = BaselineBuilder::new();
    let mut emitted = Vec::new();
    let mut marks_of_the_web = 0usize;
    let mut out_of_band: HashSet<String> = HashSet::new();
    let mut compact_os: std::collections::BTreeMap<&'static str, u64> =
        std::collections::BTreeMap::new();
    let mut compact_os_executables = 0u64;
    let mut encryption = mm_harvest::mass_encryption::Scan::new();

    let mut stage = Stage::begin("$MFT", style);
    let walked = filesystem::enumerate_with_progress(
        volume,
        &mut |path, facts| {
            builder.observe_file(path, facts.compact_os.is_some());
            encryption.observe(path, facts);
            if let Some(backing) = facts.compact_os {
                *compact_os.entry(backing.algorithm_name()).or_default() += 1;
                if path.is_executable_extension() {
                    compact_os_executables += 1;
                }
            }

            if worth_observing(path, facts, referenced) {
                if let Some(arrival) = out_of_band_arrival(path, facts) {
                    if !referenced.contains(path.key()) {
                        out_of_band.insert(path.key().to_string());
                    }
                    emitted.push(Observation::about_path(
                        ArtifactSource::Mft,
                        path.clone(),
                        ObservationKind::ArrivedOutOfBand(arrival),
                    ));
                }
                emitted.extend(filesystem::observations_for(path, facts));
                let motw = filesystem::motw_observations(volume, path, facts);
                marks_of_the_web += motw.len();
                emitted.extend(motw);
            }
        },
        &mut |done, total| stage.tick(done, total),
    );

    let junctions = walked.as_ref().map(|report| report.junctions.clone()).unwrap_or_default();

    let orphans = crate::acquire::OrphanIndex::build(
        walked.as_ref().map(|report| report.orphans.as_slice()).unwrap_or(&[]),
    );

    let enumeration = match &walked {
        Ok(report) => report.stats.enumeration(),
        Err(_) => mm_core::Enumeration::not_attempted(),
    };

    match walked {
        Ok(report) => {
            let stats = report.stats;
            coverage.files_enumerated = stats.files_seen;
            coverage.deleted_records_seen = stats.deleted_seen;
            settle(stage, coverage, "$MFT", CoverageStatus::Read { observations: emitted.len() });
            coverage.record(
                "executables installed out of band",
                CoverageStatus::Read { observations: out_of_band.len() },
            );
            coverage.record(
                "files reached through a second hard link",
                CoverageStatus::Read { observations: stats.extra_links_seen as usize },
            );
            let lost = stats.unresolved + stats.unparsable;
            coverage.record(
                "$MFT records the walk could not place",
                if lost == 0 {
                    CoverageStatus::Absent
                } else {
                    CoverageStatus::Read { observations: lost as usize }
                },
            );
            coverage.record(
                "$MFT records skipped (slack, or unreadable)",
                CoverageStatus::Read { observations: stats.records_skipped as usize },
            );
            coverage.record(
                "$MFT records the device would not return",
                if stats.records_unreadable == 0 {
                    CoverageStatus::Absent
                } else {
                    CoverageStatus::Read { observations: stats.records_unreadable as usize }
                },
            );
            if stats.records_unreadable > 0 {
                coverage.warn(format!(
                    "{} $MFT record(s) could not be read from the device at all; those are \
                     places this volume has and this run did not see, so each was counted \
                     into the base rate rather than sharpening it by its absence",
                    stats.records_unreadable
                ));
            }
            coverage.record(
                "$MFT extension records (attributes spilled out of a base record)",
                CoverageStatus::Read { observations: stats.extension_records as usize },
            );
            coverage.record(
                "$MFT names recovered from an extension record",
                if stats.names_recovered == 0 {
                    CoverageStatus::Absent
                } else {
                    CoverageStatus::Read { observations: stats.names_recovered as usize }
                },
            );
            coverage.record(
                "$MFT records with an $ATTRIBUTE_LIST (bound on unread spilled streams)",
                CoverageStatus::Read { observations: stats.attribute_lists_seen as usize },
            );
            coverage.record(
                "$MFT records that would not parse",
                if stats.unparsable == 0 {
                    CoverageStatus::Absent
                } else {
                    CoverageStatus::Read { observations: stats.unparsable as usize }
                },
            );
            coverage.record(
                "directories the walk could not reconstruct",
                if stats.unresolved_directories == 0 {
                    CoverageStatus::Absent
                } else {
                    CoverageStatus::Read { observations: stats.unresolved_directories as usize }
                },
            );
            if stats.unresolved_links > 0 {
                let places = stats.unresolved_directories;
                coverage.warn(format!(
                    "{} name(s) could not be placed, in {} distinct director{}; \
                     {} of the records behind them have no other name that could \
                     be placed either",
                    stats.unresolved_links,
                    places,
                    if places == 1 { "y" } else { "ies" },
                    stats.unresolved,
                ));
                let live = stats.unresolved_live();
                let deleted = stats.unresolved_files_deleted;
                if live > 0 {
                    coverage.warn(format!(
                        "{live} of those file(s) have $MFT records that are still IN \
                         USE: each one is a file on this volume that this run did not \
                         place, and anything an artifact says ran from one of them will \
                         look absent from the volume when it is not. This is the number \
                         that enlarges the population the base rate is taken over"
                    ));
                }
                if deleted > 0 {
                    coverage.warn(format!(
                        "{deleted} of those file(s) have records that are NOT in use: \
                         deleted files, whose directory was usually deleted with them. \
                         Those are the remains of an uninstall or an update and not a \
                         hole in this run -- no file is sitting at those paths, so \
                         nothing an artifact names can be hiding there, and they are \
                         excluded from the population the base rate is taken over. \
                         They are NOT excluded from recovery: see the line below"
                    ));
                }
                coverage.record(
                    "deleted executables with no directory (recoverable by $MFT record)",
                    if stats.orphaned_executables == 0 {
                        CoverageStatus::Absent
                    } else {
                        CoverageStatus::Read { observations: stats.orphaned_executables as usize }
                    },
                );
                if stats.orphaned_executables > stats.orphans_kept {
                    coverage.warn(format!(
                        "{} deleted executable(s) with no directory were found and {} \
                         were carried; the rest are past this run's cap and cannot be \
                         recovered by name in this report",
                        stats.orphaned_executables, stats.orphans_kept
                    ));
                }
                if stats.unresolved_deleted != deleted {
                    coverage.record(
                        "unplaceable names belonging to deleted records",
                        CoverageStatus::Read { observations: stats.unresolved_deleted as usize },
                    );
                }
            }
            if stats.parent_links_seen > 0 {
                coverage.record(
                    "parent references naming a record that has since been reused",
                    if stats.stale_parent_links == 0 {
                        CoverageStatus::Absent
                    } else {
                        CoverageStatus::Read { observations: stats.stale_parent_links as usize }
                    },
                );
                if !stats.sequence_check_applied {
                    coverage.warn(format!(
                        "{} of {} parent reference(s) name a sequence number the \
                         record they point at does not carry. That is too many to \
                         be leftovers of deleted directories, so this run did NOT \
                         act on the sequence number and resolved paths from the \
                         record number alone: a path here may belong to a directory \
                         that has since been replaced",
                        stats.stale_parent_links, stats.parent_links_seen,
                    ));
                }
            }
            for (reason, places, names) in &report.lost_reasons {
                coverage.record(
                    format!("places lost because {}", reason.describe()),
                    CoverageStatus::Read { observations: *places as usize },
                );
                coverage.warn(format!(
                    "{names} name(s) in {places} place(s) could not be placed because                      {}",
                    reason.describe()
                ));
            }
            for lost in &report.lost {
                let name = match &lost.broken_name {
                    Some(name) => format!(" (`{name}`)"),
                    None => String::new(),
                };
                let reached = if lost.reached.is_empty() {
                    "nothing above it resolved".to_string()
                } else {
                    format!("the walk got as far as `{}`", lost.reached)
                };
                let sequences = match lost.stale {
                    Some((expected, found)) => format!(
                        " (the name expects sequence {expected}, the record carries {found})"
                    ),
                    None => String::new(),
                };
                let via = if lost.broke_at == lost.parent {
                    String::new()
                } else {
                    format!(" (named as the parent of those files by record {})", lost.parent)
                };
                coverage.warn(format!(
                    "{} name(s) could not be placed because $MFT record \
                     {}{name}{via} could not be placed: {}{sequences}; {reached}",
                    lost.files_lost,
                    lost.broke_at,
                    lost.reason.describe()
                ));
            }
            coverage.record(
                "Zone.Identifier (MotW)",
                CoverageStatus::Read { observations: marks_of_the_web },
            );
            let compact_os_total: u64 = compact_os.values().sum();
            let census = if compact_os.is_empty() {
                "nothing on this volume is stored compressed".to_string()
            } else {
                format!(
                    "{}; {compact_os_executables} executable(s)",
                    compact_os
                        .iter()
                        .map(|(name, n)| format!("{n} {name}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            coverage.record(
                format!("Compact OS (WOF) — {census}"),
                CoverageStatus::Read { observations: compact_os_total as usize },
            );
            if compact_os_executables > 0 {
                let undecodable: u64 = compact_os
                    .iter()
                    .filter(|(name, _)| !decodes_compact_os(name))
                    .map(|(_, n)| *n)
                    .sum();
                if undecodable > 0 {
                    coverage.warn(format!(
                        "{undecodable} file(s) on this volume are stored Compact-OS \
                         compressed in a way this build cannot decode (projected from a \
                         WIM, or an algorithm number no version of Windows has used \
                         yet); their bytes could not be produced, so anything said \
                         about their contents is UNKNOWN rather than checked"
                    ));
                }
            }
            if stats.unparsable > stats.records_read / 10 && stats.records_read > 0 {
                coverage.warn(format!(
                    "{} of {} MFT records could not be parsed; the filesystem is damaged and \
                     this run has an incomplete view of it",
                    stats.unparsable, stats.records_read
                ));
            }
        }
        Err(e) => {
            settle(stage, coverage, "$MFT", CoverageStatus::Failed { reason: e.to_string() });
            coverage.warn(
                "the $MFT could not be walked, so machine-relative scoring and deleted-file \
                 recovery were both unavailable",
            );
        }
    }

    out.extend(emitted);
    Walk {
        baseline: builder.build(),
        out_of_band,
        junctions,
        orphans,
        enumeration,
        mass_encryption: encryption.finish(),
    }
}

fn worth_observing(
    path: &NormalizedPath,
    facts: &filesystem::FileFacts,
    referenced: &HashSet<String>,
) -> bool {
    if referenced.contains(path.key()) {
        return true;
    }
    if !facts.in_use && path.is_executable_extension() {
        return true;
    }
    if filesystem::timestomp_detail(facts).is_some() {
        return true;
    }
    if path.is_executable_extension()
        && matches!(zone::classify(path), zone::Zone::VolumeRoot | zone::Zone::WindowsTemp)
    {
        return true;
    }
    arrived_out_of_band(path, facts)
}

const OUT_OF_BAND_GAP_SECONDS: i64 = 7 * 24 * 60 * 60;

const DRIVER_STORE_SEGMENTS: &[&str] = &["driverstore", "drvstore"];

const PE_IMAGE_EXTENSIONS: &[&str] = &[".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"];

fn arrived_out_of_band(path: &NormalizedPath, facts: &filesystem::FileFacts) -> bool {
    out_of_band_arrival(path, facts).is_some()
}

fn out_of_band_arrival(
    path: &NormalizedPath,
    facts: &filesystem::FileFacts,
) -> Option<OutOfBandArrival> {
    if !facts.in_use || !names_a_pe_image(path) {
        return None;
    }
    match zone::classify(path) {
        zone::Zone::SystemDir => (facts.hard_links == 1 && !in_driver_store(path))
            .then_some(OutOfBandArrival::NotAComponentStoreLink { hard_links: facts.hard_links }),
        zone::Zone::ProgramFiles => match (facts.si_created, facts.parent_created) {
            (Some(created), Some(directory)) => {
                let gap = created - directory;
                (gap.num_seconds() > OUT_OF_BAND_GAP_SECONDS)
                    .then(|| OutOfBandArrival::AfterItsDirectory { days_later: gap.num_days() })
            }
            _ => None,
        },
        _ => None,
    }
}

fn names_a_pe_image(path: &NormalizedPath) -> bool {
    let key = path.key();
    PE_IMAGE_EXTENSIONS
        .iter()
        .any(|extension| key.len() > extension.len() && key.ends_with(extension))
}

fn in_driver_store(path: &NormalizedPath) -> bool {
    path.key().split('\\').any(|segment| DRIVER_STORE_SEGMENTS.contains(&segment))
}

fn com_target_is_ordinary(path: &NormalizedPath) -> bool {
    matches!(
        zone::classify(path),
        zone::Zone::SystemDir
            | zone::Zone::WindowsOther
            | zone::Zone::WinSxs
            | zone::Zone::ProgramFiles
            | zone::Zone::ProgramData
            | zone::Zone::Unlocated
    )
}

fn is_deferrable_com(observation: &Observation) -> bool {
    match &observation.kind {
        ObservationKind::Persistence { kind: mm_core::PersistenceKind::ComServer, raw_value } => {
            if raw_value.starts_with(DELETED_PERSISTENCE_MARK) {
                return false;
            }
            observation.path.as_ref().is_some_and(com_target_is_ordinary)
        }
        _ => false,
    }
}

const DELETED_PERSISTENCE_MARK: &str = "[deleted]";

fn promote_com_hijacks(observations: &mut [Observation]) -> usize {
    use std::collections::HashMap;

    let mut machine: HashMap<String, HashSet<String>> = HashMap::new();
    for o in observations.iter() {
        let Some((hive, key)) = registry_source(o) else { continue };
        if !hive_is_machine_wide(hive) || !is_com_server(o) || is_deleted_persistence(o) {
            continue;
        }
        let (Some(clsid), Some(path)) = (clsid_of(key), o.path.as_ref()) else {
            continue;
        };
        machine.entry(clsid).or_default().insert(path.key().to_string());
    }
    if machine.is_empty() {
        return 0;
    }

    let mut promoted = 0;
    for o in observations.iter_mut() {
        let Some((hive, key)) = registry_source(o) else { continue };
        if hive_is_machine_wide(hive) || !is_com_server(o) || is_deleted_persistence(o) {
            continue;
        }
        let (Some(clsid), Some(path)) = (clsid_of(key), o.path.as_ref()) else {
            continue;
        };
        let Some(targets) = machine.get(&clsid) else { continue };
        if targets.contains(path.key()) {
            continue;
        }
        if let ObservationKind::Persistence { kind, .. } = &mut o.kind {
            *kind = mm_core::PersistenceKind::ComHijack;
            promoted += 1;
        }
    }
    promoted
}

fn is_deleted_persistence(observation: &Observation) -> bool {
    match &observation.kind {
        ObservationKind::Persistence { raw_value, .. } => {
            raw_value.starts_with(DELETED_PERSISTENCE_MARK)
        }
        _ => false,
    }
}

const SUPERSEDED_PERSISTENCE_MARK: &str = "[superseded] ";

fn relabel_superseded_com_registrations(observations: &mut [Observation]) -> usize {
    use std::collections::HashMap;

    let mut survivors: HashMap<String, HashSet<String>> = HashMap::new();
    for o in observations.iter() {
        let Some((hive, key)) = registry_source(o) else { continue };
        if !hive_is_machine_wide(hive) || !is_com_server(o) || is_deleted_persistence(o) {
            continue;
        }
        let (Some(clsid), Some(path)) = (clsid_of(key), o.path.as_ref()) else {
            continue;
        };
        if !zone::classify(path).is_conventional_for_executables() {
            continue;
        }
        let Some(name) = path.file_name() else { continue };
        survivors.entry(clsid).or_default().insert(name.to_ascii_lowercase());
    }
    if survivors.is_empty() {
        return 0;
    }

    let mut relabelled = 0;
    for o in observations.iter_mut() {
        let Some((_, key)) = registry_source(o) else { continue };
        if !is_com_server(o) || !is_deleted_persistence(o) {
            continue;
        }
        let (Some(clsid), Some(path)) = (clsid_of(key), o.path.as_ref()) else {
            continue;
        };
        let Some(name) = path.file_name().map(|n| n.to_ascii_lowercase()) else {
            continue;
        };
        if !survivors.get(&clsid).is_some_and(|names| names.contains(&name)) {
            continue;
        }
        if let ObservationKind::Persistence { raw_value, .. } = &mut o.kind {
            let rest = raw_value[DELETED_PERSISTENCE_MARK.len()..].trim_start().to_string();
            *raw_value = format!("{SUPERSEDED_PERSISTENCE_MARK}{rest}");
            relabelled += 1;
        }
    }
    relabelled
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
    let present: HashSet<&str> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key()).collect();
    let rejoining: Vec<Observation> = deferred
        .into_iter()
        .filter(|o| o.path.as_ref().is_some_and(|p| present.contains(p.key())))
        .collect();
    observations.extend(rejoining);
}

fn defer_defender_log(observations: &mut Vec<Observation>) -> Vec<Observation> {
    let mut deferred = Vec::new();
    let mut kept = Vec::with_capacity(observations.len());
    for o in observations.drain(..) {
        if is_defender_log(&o) {
            deferred.push(o);
        } else {
            kept.push(o);
        }
    }
    *observations = kept;
    deferred
}

fn defer_deleted_registry_values(observations: &mut Vec<Observation>) -> Vec<Observation> {
    let mut deferred = Vec::new();
    let mut kept = Vec::with_capacity(observations.len());
    for o in observations.drain(..) {
        if matches!(o.kind, ObservationKind::DeletedRegistryValue { .. }) {
            deferred.push(o);
        } else {
            kept.push(o);
        }
    }
    *observations = kept;
    deferred
}

fn reattach_deleted_registry_values(
    observations: &mut Vec<Observation>,
    deferred: Vec<Observation>,
    coverage: &mut Coverage,
) {
    if deferred.is_empty() {
        return;
    }
    let total = deferred.len();
    let present: HashSet<&str> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key()).collect();
    let rejoining: Vec<Observation> = deferred
        .into_iter()
        .filter(|o| o.path.as_ref().is_some_and(|p| present.contains(p.key())))
        .collect();

    coverage.record(
        "deleted registry values recovered (key not recoverable)",
        CoverageStatus::Read { observations: total },
    );
    let unmatched = total.saturating_sub(rejoining.len());
    if unmatched > 0 {
        coverage.warn(format!(
            "{unmatched} deleted registry value(s) name a path nothing else on this \
             volume knows about. They score nothing and create nothing — the key each \
             was under is not recoverable from a freed cell, so what the value MEANT is \
             unknown"
        ));
    }
    observations.extend(rejoining);
}

const MAX_UNMATCHED_DETECTIONS_SHOWN: usize = 8;

fn unmatched_paths(kept: &HashSet<String>, all: &[String]) -> Vec<String> {
    all.iter().filter(|p| !kept.contains(*p)).map(|p| truncate_path(p)).collect()
}

fn truncate_path(p: &str) -> String {
    const MOST: usize = 160;
    if p.chars().count() <= MOST {
        return p.to_string();
    }
    let head: String = p.chars().take(MOST).collect();
    format!("{head}... (truncated)")
}

fn is_defender_log(o: &Observation) -> bool {
    matches!(&o.source, ArtifactSource::DefenderLog { .. })
}

fn reattach_defender_log(
    observations: &mut Vec<Observation>,
    deferred: Vec<Observation>,
    coverage: &mut Coverage,
) {
    if deferred.is_empty() {
        return;
    }
    let total = deferred.len();
    let present: HashSet<&str> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key()).collect();
    let deferred_paths: Vec<String> =
        deferred.iter().filter_map(|o| o.path.as_ref()).map(|p| p.raw().to_string()).collect();
    let kept_keys: HashSet<String> = deferred
        .iter()
        .filter_map(|o| o.path.as_ref())
        .filter(|p| present.contains(p.key()))
        .map(|p| p.raw().to_string())
        .collect();
    let rejoining: Vec<Observation> = deferred
        .into_iter()
        .filter(|o| o.path.as_ref().is_some_and(|p| present.contains(p.key())))
        .collect();

    coverage.record(
        "Defender detections matched to a file on this volume",
        if rejoining.is_empty() {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: rejoining.len() }
        },
    );
    let unmatched = total.saturating_sub(rejoining.len());
    if unmatched > 0 {
        let mut named: Vec<String> = unmatched_paths(&kept_keys, &deferred_paths);
        named.sort();
        named.dedup();
        let shown = named.len().min(MAX_UNMATCHED_DETECTIONS_SHOWN);
        coverage.warn(format!(
            "{unmatched} Defender detection(s) name a path this volume does not have — \
             already removed, on another drive, or from an earlier install. They score \
             nothing, and they are:{}{}",
            named.iter().take(shown).map(|p| format!("\n      {p}")).collect::<String>(),
            if named.len() > shown {
                format!("\n      ...and {} more", named.len() - shown)
            } else {
                String::new()
            }
        ));
    }
    observations.extend(rejoining);
}

fn count_com_registrations(observations: &[Observation]) -> usize {
    observations
        .iter()
        .filter(|o| {
            matches!(
                &o.kind,
                ObservationKind::Persistence {
                    kind: mm_core::PersistenceKind::ComServer | mm_core::PersistenceKind::ComHijack,
                    ..
                }
            )
        })
        .count()
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
        ObservationKind::Persistence { kind: mm_core::PersistenceKind::ComServer, .. }
    )
}

fn hive_is_machine_wide(hive: &str) -> bool {
    hive.eq_ignore_ascii_case("SOFTWARE") || hive.eq_ignore_ascii_case("SYSTEM")
}

fn clsid_of(key: &str) -> Option<String> {
    key.split('\\')
        .find(|segment| segment.len() > 2 && segment.starts_with('{') && segment.ends_with('}'))
        .map(|segment| segment.to_ascii_lowercase())
}

fn build_and_score(
    observations: Vec<Observation>,
    baseline: &Baseline,
    weights: &Weights,
    enumeration: &mm_core::Enumeration,
) -> Vec<Candidate> {
    let mut candidates = mm_score::graph::build(observations, 0.0);
    mm_score::graph::link_shared_digests(&mut candidates);
    let prior = enumeration
        .prior_log_odds(candidates.len())
        .unwrap_or_else(|| prior_log_odds(candidates.len()));

    for candidate in &mut candidates {
        candidate.prior_log_odds = prior;
        candidate.evidence = mm_score::extract(candidate, baseline, weights);
    }
    candidates
}

fn create_if(wanted: bool, path: &std::path::Path) -> std::io::Result<()> {
    if wanted {
        std::fs::create_dir_all(path)
    } else {
        Ok(())
    }
}

fn prior_log_odds(candidate_count: usize) -> f64 {
    mm_core::log_odds_of_one_in(candidate_count as f64)
}

fn verify_signatures<R: Read + Seek>(
    volume: &Volume<R>,
    candidates: &mut [Candidate],
    baseline: &Baseline,
    weights: &Weights,
    options: &Options,
    out_of_band: &HashSet<String>,
    coverage: &mut Coverage,
) {
    let style = options.progress;
    let selecting = Stage::begin("signature shortlist", style);
    let selected =
        select_for_verification(volume, candidates, weights, options.verify_top, out_of_band);
    settle(
        selecting,
        coverage,
        "signature shortlist",
        CoverageStatus::Read { observations: selected.len() },
    );
    if selected.is_empty() {
        coverage.record_timed("code signatures", CoverageStatus::Read { observations: 0 }, 0.0);
        return;
    }

    let trust = mm_sign::TrustStore::embedded();
    let now = mm_sign::now();
    let shortlist = selected.len() as u64;
    let mut verifying = Stage::begin(format!("code signatures ({shortlist} files)"), style);

    let mut settled: Vec<(usize, NormalizedPath, SignatureStatus)> = Vec::new();
    let mut pending: Vec<(usize, NormalizedPath, mm_sign::Verdict)> = Vec::new();
    let mut structure: Vec<(usize, Vec<Observation>)> = Vec::new();
    let mut images_examined = 0usize;
    for (done, index_of_candidate) in selected.into_iter().enumerate() {
        verifying.tick(done as u64, shortlist);
        let Some(path) = candidates[index_of_candidate].path.clone() else { continue };

        match read_for_verification(volume, &path) {
            Err(status) => settled.push((index_of_candidate, path, status)),
            Ok(bytes) => {
                images_examined += 1;
                match guarded(std::panic::AssertUnwindSafe(|| {
                    mm_harvest::pe::harvest(&bytes, &path)
                })) {
                    Ok(found) if !found.is_empty() => structure.push((index_of_candidate, found)),
                    Ok(_) => {}
                    Err(reason) => coverage.warn(format!(
                        "the PE headers of {} could not be examined — {reason}",
                        path.key()
                    )),
                }

                let half = guarded(std::panic::AssertUnwindSafe(|| {
                    mm_sign::verify_embedded_first(&bytes, &trust, now)
                }));
                match half {
                    Ok(mm_sign::FileVerdict::Settled(verdict)) => {
                        settled.push((index_of_candidate, path, verdict.to_status()))
                    }
                    Ok(mm_sign::FileVerdict::NeedsCatalog(embedded)) => {
                        pending.push((index_of_candidate, path, embedded))
                    }
                    Err(reason) => settled.push((
                        index_of_candidate,
                        path,
                        SignatureStatus::Unknown { reason },
                    )),
                }
            }
        }
    }

    if !pending.is_empty() {
        let catalogs = Stage::begin(format!("catalog store ({} files)", pending.len()), style);
        let mut catalogs = catalogs;
        let index = guarded(std::panic::AssertUnwindSafe(|| {
            mm_sign::catroot::index_volume_with_progress(volume, &trust, &mut |done, total| {
                catalogs.tick(done, total)
            })
        }))
        .unwrap_or_else(|reason| {
            coverage.warn(format!("the catalog index could not be built — {reason}"));
            mm_sign::catalog::CatalogIndex::new()
        });
        verifying.exclude(record_catalog_coverage(&index, catalogs, coverage));

        for (index_of_candidate, path, embedded) in pending {
            let status = match read_for_verification(volume, &path) {
                Err(status) => status,
                Ok(bytes) => guarded(std::panic::AssertUnwindSafe(|| {
                    mm_sign::finish_with_catalog(embedded, &bytes, &index).to_status()
                }))
                .unwrap_or_else(|reason| SignatureStatus::Unknown { reason }),
            };
            settled.push((index_of_candidate, path, status));
        }
    } else {
        coverage.record_timed(
            "catalog store",
            CoverageStatus::NotAvailableHere {
                reason: "not needed — every candidate the answer could turn on carried a valid \
                         signature of its own"
                    .into(),
            },
            0.0,
        );
    }

    let mut structural_findings = 0usize;
    for (index_of_candidate, found) in structure {
        structural_findings +=
            found.iter().filter(|o| matches!(o.kind, ObservationKind::PeAnomaly { .. })).count();
        for observation in found {
            candidates[index_of_candidate].observe(observation);
        }
    }
    coverage.record(
        format!("PE section entropy ({images_examined} images)"),
        CoverageStatus::Read { observations: structural_findings },
    );

    let compact_os_unread = settled
        .iter()
        .filter(|(_, _, status)| match status {
            SignatureStatus::Unknown { reason } => {
                mm_raw::wof::describes_a_compact_os_failure(reason)
            }
            _ => false,
        })
        .count();
    let compact_os_lzx = settled
        .iter()
        .filter(|(_, _, status)| match status {
            SignatureStatus::Unknown { reason } => mm_raw::wof::describes_lzx(reason),
            _ => false,
        })
        .count();
    if compact_os_unread > 0 {
        coverage.record(
            format!("Compact OS (WOF) files left unread ({compact_os_lzx} LZX)"),
            CoverageStatus::Read { observations: compact_os_unread },
        );
        coverage.warn(format!(
            "{compact_os_unread} of the {shortlist} files shortlisted for signature \
             verification are Compact-OS compressed with an algorithm this build does \
             not decode ({compact_os_lzx} of them LZX), so their signatures are UNKNOWN \
             rather than checked"
        ));
    }

    let unaccounted = settled
        .iter()
        .filter(|(_, _, status)| match status {
            SignatureStatus::Unknown { reason } => {
                mm_raw::describes_an_unaccounted_attribute_list(reason)
            }
            _ => false,
        })
        .count();
    if unaccounted > 0 {
        coverage.record(
            "files whose $ATTRIBUTE_LIST would not be followed".to_string(),
            CoverageStatus::Read { observations: unaccounted },
        );
        coverage.warn(format!(
            "{unaccounted} of the {shortlist} files shortlisted for signature verification \
             carry an $ATTRIBUTE_LIST naming records that do not claim them, or more records \
             than any file has, so some attribute of each is unaccounted for and their bytes \
             were not read. NTFS does not write that: on a volume this tool is pointed at it \
             means corruption or a deliberate write, and either is worth looking at directly"
        ));
    }

    let verified = settled.len();
    let rescoring = settled.len() as u64;
    for (done, (index_of_candidate, path, status)) in settled.into_iter().enumerate() {
        verifying.tick(done as u64, rescoring);
        candidates[index_of_candidate].observe(Observation::about_path(
            ArtifactSource::FileContent,
            path,
            ObservationKind::Signature(status),
        ));
        let rescored = mm_score::extract(&candidates[index_of_candidate], baseline, weights);
        candidates[index_of_candidate].evidence = rescored;
    }

    settle(
        verifying,
        coverage,
        format!("code signatures ({shortlist} files)"),
        CoverageStatus::Read { observations: verified },
    );
}

fn read_for_verification<R: Read + Seek>(
    volume: &Volume<R>,
    path: &NormalizedPath,
) -> std::result::Result<Vec<u8>, SignatureStatus> {
    if volume.path_is_efs_encrypted(path.key()) {
        return Err(SignatureStatus::Unknown {
            reason: "the file is EFS-encrypted, so its bytes are ciphertext and its signature \
                     could not be read"
                .into(),
        });
    }

    match volume.read_capped(path.key(), limits::VERIFY) {
        Ok(bytes) if bytes.len() >= limits::VERIFY => Err(SignatureStatus::Unknown {
            reason: format!(
                "the file is at or past the {} MB verification limit, so its signature could \
                 not be read",
                limits::VERIFY / (1024 * 1024)
            ),
        }),
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(SignatureStatus::Unknown { reason: e.to_string() }),
    }
}

#[must_use]
fn record_catalog_coverage(
    index: &mm_sign::catalog::CatalogIndex,
    stage: Stage,
    coverage: &mut Coverage,
) -> f64 {
    if index.is_usable() {
        let seconds = settle(
            stage,
            coverage,
            format!(
                "catalog store ({} catalogs, {} members)",
                index.catalogs().len(),
                index.member_count()
            ),
            CoverageStatus::Read { observations: index.member_count() },
        );
        let unreadable = index.stats().unreadable;
        if unreadable > 0 {
            coverage.warn(format!(
                "{unreadable} catalog file(s) under \\Windows\\System32\\CatRoot could not \
                 be read, and the store was used anyway. A file whose signature lived only in \
                 one of those reads here as UNSIGNED, which is evidence against it. That \
                 evidence is this run's blind spot and not a fact about the file"
            ));
        }
        return seconds;
    }
    let seconds = settle(
        stage,
        coverage,
        "catalog store",
        CoverageStatus::Failed {
            reason: "no catalog under \\Windows\\System32\\CatRoot could be read".into(),
        },
    );
    coverage.warn(
        "the catalog store could not be read, so catalog-signed files — which is most of \
         Windows — are reported as UNKNOWN rather than unsigned, and carry no signature \
         evidence either way",
    );
    seconds
}

fn select_for_verification<R: Read + Seek>(
    volume: &Volume<R>,
    candidates: &[Candidate],
    weights: &Weights,
    floor: usize,
    out_of_band: &HashSet<String>,
) -> Vec<usize> {
    let mut selected = verification_band(candidates, weights, floor);
    if !out_of_band.is_empty() {
        let already: HashSet<usize> = selected.iter().copied().collect();
        for (index, candidate) in candidates.iter().enumerate() {
            if already.contains(&index) || !is_verifiable_shape(candidate) {
                continue;
            }
            if candidate.path.as_ref().is_some_and(|p| out_of_band.contains(p.key())) {
                selected.push(index);
            }
        }
    }
    selected
        .into_iter()
        .filter(|&index| candidates[index].path.as_ref().is_some_and(|p| volume.exists(p.key())))
        .collect()
}

fn verification_band(candidates: &[Candidate], weights: &Weights, floor: usize) -> Vec<usize> {
    let headroom = weights.max_log_lr_in_group(group::SIGNATURE);
    let threshold_logit = logit(mm_report::DEFAULT_THRESHOLD);

    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by(|&a, &b| {
        candidates[b]
            .logit()
            .partial_cmp(&candidates[a].logit())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| candidates[a].id.cmp(&candidates[b].id))
    });

    let mut selected = Vec::new();
    for (rank, index) in order.into_iter().enumerate() {
        let in_reach = candidates[index].logit() + headroom >= threshold_logit;
        if rank >= floor && !in_reach {
            break;
        }
        if is_verifiable_shape(&candidates[index]) {
            selected.push(index);
        }
    }
    selected
}

fn is_verifiable_shape(candidate: &Candidate) -> bool {
    candidate.path.as_ref().is_some_and(|p| p.is_located() && p.is_executable_extension())
}

fn logit(probability: f64) -> f64 {
    (probability / (1.0 - probability)).ln()
}

fn apply_incident_window(
    candidates: &mut [Candidate],
    baseline: &Baseline,
    weights: &Weights,
    journal: &mm_harvest::usn_journal::Clock,
    coverage: &mut Coverage,
    style: Style,
) -> (Option<(mm_core::Moment, mm_core::Moment)>, Option<mm_score::IncidentWindow>) {
    let stage = Stage::begin("incident window", style);
    let detection = mm_score::IncidentWindow::detect(candidates, mm_report::DEFAULT_THRESHOLD);

    let Some(window) = detection.window() else {
        settle(
            stage,
            coverage,
            "incident window",
            CoverageStatus::NotAvailableHere { reason: detection.describe() },
        );
        return (None, None);
    };
    let kept = window.clone();

    for candidate in candidates.iter_mut() {
        candidate.evidence =
            mm_score::extract_with_window(candidate, baseline, weights, Some(window));
    }

    settle(
        stage,
        coverage,
        format!("incident window ({})", window.describe()),
        CoverageStatus::Read { observations: window.members() },
    );

    if let Some(line) = corroborate_window(candidates, window, journal) {
        coverage.record(
            format!("incident window, checked against the change journal — {line}"),
            CoverageStatus::Read { observations: window.members() },
        );
    }

    (Some((window.start(), window.end())), Some(kept))
}

fn relink_shared_digests_after_acquisition(
    candidates: &mut [Candidate],
    baseline: &Baseline,
    weights: &Weights,
    window: Option<&mm_score::IncidentWindow>,
    coverage: &mut Coverage,
    style: Style,
) {
    fn shared(candidate: &Candidate) -> Vec<String> {
        candidate
            .observations
            .iter()
            .filter_map(|o| match &o.kind {
                mm_core::ObservationKind::SharedDigestElsewhere { path, algorithm, copies } => {
                    Some(format!("{} {algorithm} {copies}", path.key()))
                }
                _ => None,
            })
            .collect()
    }

    let before: Vec<Vec<String>> = candidates.iter().map(shared).collect();
    let stage = Stage::begin("shared digests", style);
    mm_score::graph::link_shared_digests(candidates);

    let mut changed = 0usize;
    for index in 0..candidates.len() {
        if shared(&candidates[index]) == before[index] {
            continue;
        }
        changed += 1;
        candidates[index].evidence =
            mm_score::extract_with_window(&candidates[index], baseline, weights, window);
    }

    let total = candidates.iter().filter(|c| !shared(c).is_empty()).count();
    settle(
        stage,
        coverage,
        format!(
            "shared digests ({total} candidate(s) whose bytes are also at another path;              {changed} learned it only after acquisition)"
        ),
        CoverageStatus::Read { observations: total },
    );
}

fn corroborate_window(
    candidates: &[Candidate],
    window: &mm_score::IncidentWindow,
    journal: &mm_harvest::usn_journal::Clock,
) -> Option<String> {
    if journal.is_silent() {
        return None;
    }
    let (mut asked, mut confirmed, mut contradicted, mut predates, mut unseen) = (0, 0, 0, 0, 0);
    let mut worst: Option<(String, i64)> = None;
    for candidate in candidates {
        let is_seed = window.seeds().binary_search(&candidate.id).is_ok();
        if !is_seed && window.membership(candidate).is_none() {
            continue;
        }
        let Some(path) = candidate.path.as_ref() else { continue };
        let created = candidate
            .observations
            .iter()
            .filter_map(|o| match &o.kind {
                ObservationKind::FileExists { created, .. } => *created,
                _ => None,
            })
            .min();
        let Some(created) = created else { continue };
        asked += 1;
        match journal.created(path.key()) {
            Some(driver) => {
                let delta = driver - created;
                if delta.num_milliseconds().abs() <= 1_000 {
                    confirmed += 1;
                } else {
                    contradicted += 1;
                    let seconds = delta.num_seconds();
                    if worst.as_ref().is_none_or(|(_, w)| seconds.abs() > w.abs()) {
                        worst = Some((path.display_path().to_string(), seconds));
                    }
                }
            }
            None if journal.oldest().is_some_and(|first| created < first) => predates += 1,
            None => unseen += 1,
        }
    }
    if asked == 0 {
        return None;
    }
    let mut text = format!(
        "{confirmed} of the {asked} creation time(s) this window rests on are confirmed to          the second by the change journal, which SetFileTime does not reach"
    );
    if contradicted > 0 {
        text.push_str(&format!("; {contradicted} DISAGREE with it"));
        if let Some((path, seconds)) = worst {
            text.push_str(&format!(
                " (the largest by {seconds} s, {path}) - a file whose $SI creation time is not                  the moment the driver recorded is a file whose $SI creation time somebody                  wrote"
            ));
        }
    }
    if predates > 0 {
        text.push_str(&format!(
            "; {predates} predate the journal's oldest record{} and are UNKNOWN rather than              confirmed",
            journal
                .oldest()
                .map(|t| format!(" ({})", mm_core::filetime::format(t)))
                .unwrap_or_default(),
        ));
    }
    if unseen > 0 {
        text.push_str(&format!(
            "; {unseen} fall inside the journal's reach and carry no creation row there, which              is a hole in this reading rather than a fact about the file"
        ));
    }
    text.push_str(
        ". Nothing here is scored: it is a check on the window's evidence, not more of it",
    );
    Some(text)
}

pub(crate) const MAX_UNRANKED_ACQUISITIONS: usize = 64;
const _: () = assert!(MAX_UNRANKED_ACQUISITIONS >= 47 && MAX_UNRANKED_ACQUISITIONS <= 128);
const _: () = assert!(MAX_UNRANKED_BYTES <= 256 * 1024 * 1024);

pub(crate) const MAX_UNRANKED_BYTES: u64 = 256 * 1024 * 1024;

fn matches_an_unranked_rule(
    candidate: &Candidate,
    index_slack: &crate::index_slack::RecoveredNames,
) -> bool {
    carveable_deleted_executable(candidate)
        || ran_from_a_scratch_root_and_vanished(candidate)
        || index_slack_named_its_record(candidate, index_slack)
}

fn index_slack_named_its_record(
    candidate: &Candidate,
    index_slack: &crate::index_slack::RecoveredNames,
) -> bool {
    let Some(path) = candidate.path.as_ref() else { return false };
    if !path.is_executable_extension() {
        return false;
    }
    if candidate.observations.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. })) {
        return false;
    }
    index_slack.get(path).is_some_and(|found| found.carveable())
}

fn carveable_deleted_executable(candidate: &Candidate) -> bool {
    let Some(path) = candidate.path.as_ref() else { return false };
    if !path.is_executable_extension() {
        return false;
    }
    candidate
        .observations
        .iter()
        .any(|o| matches!(o.kind, ObservationKind::FileDeleted { record: Some(_), .. }))
}

fn ran_from_a_scratch_root_and_vanished(candidate: &Candidate) -> bool {
    let Some(path) = candidate.path.as_ref() else { return false };
    if !path.is_executable_extension() || !path.is_located() {
        return false;
    }
    let mut executed = false;
    for o in &candidate.observations {
        match o.kind {
            ObservationKind::Executed { .. } => executed = true,
            ObservationKind::FileExists { .. } => return false,
            _ => {}
        }
    }
    executed && zone::is_immediately_in_a_scratch_root(path)
}

fn harvest_index_slack<R: Read + Seek>(
    volume: &Volume<R>,
    observations: &[Observation],
    coverage: &mut Coverage,
    style: Style,
) -> crate::index_slack::RecoveredNames {
    let stage = Stage::begin("index slack", style);
    let located: HashSet<&str> = observations
        .iter()
        .filter(|o| matches!(o.kind, ObservationKind::FileExists { .. }))
        .filter_map(|o| o.path.as_ref())
        .map(|p| p.key())
        .collect();
    let wanted: Vec<&NormalizedPath> = observations
        .iter()
        .filter_map(|o| o.path.as_ref())
        .filter(|p| !located.contains(p.key()))
        .collect();

    let found = crate::index_slack::harvest(volume, wanted);
    let stats = found.stats;
    settle(
        stage,
        coverage,
        "index slack (deleted entries in the parent directory)",
        CoverageStatus::Read { observations: stats.matched },
    );
    coverage.record(
        "directories swept for index slack",
        CoverageStatus::Read { observations: stats.resolved },
    );
    if stats.directories > stats.resolved {
        coverage.record(
            "directories holding a vanished file that no longer exist themselves",
            CoverageStatus::Read {
                observations: stats.directories - stats.resolved - stats.declined,
            },
        );
    }
    coverage.record(
        "deleted files given an $MFT record by index slack (carveable)",
        if stats.carveable == 0 {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: stats.carveable }
        },
    );
    coverage.record(
        "deleted files whose $MFT record index slack proves was reallocated",
        if stats.reallocated == 0 {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: stats.reallocated }
        },
    );
    if stats.live_refused > 0 {
        coverage.record(
            "live index entries this run's own validator refused (its self-check)",
            CoverageStatus::Read { observations: stats.live_refused as usize },
        );
    }
    if stats.ambiguous > 0 {
        coverage.warn(format!(
            "{} deleted index entr{} recovered under a name two different $MFT records \
             claim, and nothing on this volume says which record was the file — so none of \
             them was used to aim a carve",
            stats.ambiguous,
            if stats.ambiguous == 1 { "y was" } else { "ies were" }
        ));
    }
    if stats.declined > 0 {
        coverage.warn(format!(
            "{} director{} holding a file this run could not find were NOT swept for index \
             slack: this run had already swept its cap. Those directories may still hold the \
             deleted entries of files named in this report",
            stats.declined,
            if stats.declined == 1 { "y" } else { "ies" }
        ));
    }
    found
}

#[allow(clippy::too_many_arguments)]
fn acquire_samples<R: Read + Seek>(
    volume: &Volume<R>,
    quarantine: &QuarantineStore,
    recycle_bin: &RecycleBinStore,
    orphans: &crate::acquire::OrphanIndex,
    index_slack: &crate::index_slack::RecoveredNames,
    candidates: &mut [Candidate],
    options: &Options,
    coverage: &mut Coverage,
    style: Style,
) {
    let stage = Stage::begin("sample acquisition", style);
    let sample_root = options.output_dir.join("sample");
    if let Err(e) = create_if(options.write_samples, &sample_root) {
        coverage.warn(format!("could not create the sample directory: {e}"));
        settle(
            stage,
            coverage,
            "sample acquisition",
            CoverageStatus::Failed { reason: "no sample directory".into() },
        );
        return;
    }
    let reported = crate::acquire::SampleDir {
        path: sample_root.clone(),
        relative: "sample",
        write_out: options.write_samples,
    };
    let mut clusters = ClusterMap::new();

    let shadows = crate::acquire::ShadowStore::open(volume);
    coverage.record(shadows.coverage_line(), shadows.coverage_status());
    for refusal in shadows.refusals() {
        coverage.warn(format!("shadow copy: {refusal}"));
    }

    let ghosts = crate::acquire::GhostIndex::build(volume);
    coverage.record(ghosts.coverage_line(), ghosts.coverage_status());

    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by(|&a, &b| {
        candidates[b]
            .probability()
            .partial_cmp(&candidates[a].probability())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut acquired = 0usize;
    let mut done: HashSet<usize> = HashSet::new();
    for &index in order.iter().take(options.acquire_top) {
        if candidates[index].probability() < mm_report::DEFAULT_THRESHOLD {
            break;
        }
        let acquisition = crate::acquire::acquire(
            volume,
            quarantine,
            recycle_bin,
            &shadows,
            orphans,
            index_slack,
            &ghosts,
            &mut clusters,
            &mut candidates[index],
            &reported,
        );
        candidates[index].acquisition = acquisition;
        done.insert(index);
        acquired += 1;
    }

    let mut unranked = 0usize;
    let mut declined = 0usize;
    let mut spent: u64 = 0;
    let mut unranked_dir: Option<crate::acquire::SampleDir> = None;
    for &index in &order {
        if done.contains(&index) {
            continue;
        }
        if !matches_an_unranked_rule(&candidates[index], index_slack) {
            continue;
        }
        if unranked >= MAX_UNRANKED_ACQUISITIONS || spent >= MAX_UNRANKED_BYTES {
            declined += 1;
            continue;
        }
        if unranked_dir.is_none() {
            let path = sample_root.join("unranked");
            if let Err(e) = create_if(options.write_samples, &path) {
                coverage.warn(format!(
                    "could not create the unranked sample directory, so \
                     {} recovery attempt(s) that the score did not reach were not made: {e}",
                    order.len() - done.len()
                ));
                break;
            }
            unranked_dir = Some(crate::acquire::SampleDir {
                path,
                relative: "sample/unranked",
                write_out: options.write_samples,
            });
        }
        let Some(dir) = unranked_dir.as_ref() else { break };
        let acquisition = crate::acquire::acquire(
            volume,
            quarantine,
            recycle_bin,
            &shadows,
            orphans,
            index_slack,
            &ghosts,
            &mut clusters,
            &mut candidates[index],
            dir,
        );
        match &acquisition {
            mm_core::Acquisition::Bytes { size, .. }
            | mm_core::Acquisition::Withheld { size, .. } => {
                spent = spent.saturating_add(*size);
            }
            _ => {}
        }
        candidates[index].acquisition = acquisition;
        unranked += 1;
    }

    settle(stage, coverage, "sample acquisition", CoverageStatus::Read { observations: acquired });

    deep_carve(
        volume,
        &mut clusters,
        candidates,
        &order,
        options,
        coverage,
        &sample_root,
        &reported,
        style,
    );
    coverage.record(
        "bytes recovered below the reporting threshold (sample/unranked)",
        if unranked == 0 {
            CoverageStatus::Absent
        } else {
            CoverageStatus::Read { observations: unranked }
        },
    );
    if declined > 0 {
        coverage.warn(format!(
            "{declined} further candidate(s) matched a recovery rule and were NOT \
             attempted: this run had already written {unranked} unranked sample(s) and \
             {spent} byte(s), which is its cap. Those files are recoverable and this \
             report does not hold their bytes"
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn deep_carve<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    candidates: &mut [Candidate],
    order: &[usize],
    options: &Options,
    coverage: &mut Coverage,
    sample_root: &std::path::Path,
    reported: &crate::acquire::SampleDir,
    style: Style,
) {
    const LABEL: &str = "unallocated clusters searched for missing samples (--deep)";
    if !options.deep {
        coverage.record(
            LABEL,
            CoverageStatus::NotAvailableHere {
                reason: "not asked for; re-run with --deep to search the volume's free space \
                         for the bytes of files the recovery chain could not reach"
                    .to_string(),
            },
        );
        return;
    }

    let targets = crate::deep::targets(candidates, order);
    let over_the_cap = crate::deep::over_the_cap(candidates, order);
    let unsearchable = crate::deep::unsearchable(candidates, order);
    if !unsearchable.is_empty() {
        const NAMED: usize = 20;
        let named: Vec<&str> = unsearchable.iter().take(NAMED).map(String::as_str).collect();
        coverage.warn(format!(
            "--deep could not search for {} candidate(s) that have no recovered bytes and no \
             live file, because no artifact recorded a digest of them and a carved executable \
             with nothing to check it against cannot be shown to be the file: {}{}. Their bytes \
             may still be in unallocated space; this run did not look, and that is UNKNOWN, not \
             absence",
            unsearchable.len(),
            named.join(", "),
            if unsearchable.len() > NAMED {
                format!(" and {} more", unsearchable.len() - NAMED)
            } else {
                String::new()
            }
        ));
    }
    if targets.is_empty() {
        coverage.record(LABEL, CoverageStatus::Absent);
        return;
    }

    let stage = Stage::begin("deep carve of unallocated space", style);
    let Some(scan) = crate::deep::scan(volume, clusters, &targets) else {
        settle(
            stage,
            coverage,
            LABEL,
            CoverageStatus::Failed {
                reason: "$Bitmap could not be read, so which clusters are free is unknown and \
                         none was searched"
                    .into(),
            },
        );
        return;
    };

    let unranked_dir = crate::acquire::SampleDir {
        path: sample_root.join("unranked"),
        relative: "sample/unranked",
        write_out: reported.write_out,
    };
    let mut found = 0usize;
    for target in &targets {
        match scan.hits.iter().find(|hit| hit.index == target.index) {
            Some(hit) => {
                let dir = if candidates[target.index].probability() >= mm_report::DEFAULT_THRESHOLD
                {
                    reported
                } else {
                    if create_if(unranked_dir.write_out, &unranked_dir.path).is_err() {
                        continue;
                    }
                    &unranked_dir
                };
                candidates[target.index].acquisition =
                    crate::deep::adopt(&mut candidates[target.index], hit, dir);
                found += 1;
            }
            None => {
                if let mm_core::Acquisition::Failed { reason } =
                    &candidates[target.index].acquisition
                {
                    let extended = crate::deep::no_hit_reason(target, &scan, reason);
                    candidates[target.index].acquisition =
                        mm_core::Acquisition::Failed { reason: extended };
                }
            }
        }
    }

    settle(stage, coverage, LABEL, CoverageStatus::Read { observations: found });
    coverage.warn(format!(
        "--deep searched {} of the {} cluster(s) $Bitmap marks free for {} candidate(s) with a \
         recorded digest, read {} MB, followed {} PE header(s), hashed {} image(s), and \
         recovered {} of them in {:.1} s.{}",
        scan.scanned_clusters,
        scan.free_clusters,
        targets.len(),
        scan.bytes_read / (1024 * 1024),
        scan.headers,
        scan.hashed,
        found,
        scan.elapsed.as_secs_f64(),
        if scan.exhaustive() {
            String::new()
        } else {
            match &scan.stopped {
                Some(why) => format!(
                    " The search was NOT exhaustive: {why}. What it did not reach is UNKNOWN"
                ),
                None => String::new(),
            }
        }
    ));
    if over_the_cap > 0 {
        coverage.warn(format!(
            "--deep qualified {} further candidate(s) — no bytes, no live file, and a recorded \
             digest — and did NOT search for them: the search list is capped at {}, and these \
             ranked below it. The sweep cost the same either way; what is missing is the \
             comparison, not the read. Their bytes are UNKNOWN, not absent",
            over_the_cap,
            crate::deep::MAX_TARGETS
        ));
    }
    coverage.warn(
        "--deep's recovery rate on real hardware is UNMEASURED. This tool's carve is verified \
         end to end on a synthetic NTFS volume, and no dataset this project holds can test the \
         yield: every image it has is a sparse VMDK, whose unallocated grains are not stored at \
         all and read back as zeros, and on an SSD Windows issues TRIM on delete, so the free \
         space this sweep depends on may have been zeroed by the drive. Finding nothing here is \
         therefore consistent with the bytes still being on the disk, and is NOT a finding about \
         the disk"
            .to_string(),
    );
    let missed: Vec<&str> = targets
        .iter()
        .filter(|t| !scan.hits.iter().any(|hit| hit.index == t.index))
        .map(|t| t.label.as_str())
        .collect();
    if !missed.is_empty() {
        coverage.warn(format!(
            "--deep searched unallocated space for these and did NOT find them: {}. That is not \
             a finding about the disk: the sweep reads contiguous free runs and measures each \
             image by its own PE headers, so a fragmented file and a file with data appended \
             past its last section are both invisible to it",
            missed.join(", ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mm_core::{ArtifactSource, CandidateId, FileHash, ObservationKind};
    use mm_harvest::filesystem::FileFacts;

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).unwrap()
    }

    fn facts(in_use: bool) -> FileFacts {
        FileFacts {
            record: 100,
            size: 4096,
            is_directory: false,
            in_use,
            si_created: None,
            si_modified: None,
            si_mft_modified: None,
            fn_created: None,
            compact_os: None,
            has_ads: false,
            hard_links: 2,
            parent_created: None,
        }
    }

    #[test]
    fn ordinary_untouched_files_are_not_candidates() {
        let referenced = HashSet::new();
        for p in [
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Users\\bob\\Documents\\notes.txt",
            "C:\\Program Files\\App\\app.exe",
            "C:\\Users\\bob\\AppData\\Roaming\\thing.exe",
        ] {
            assert!(!worth_observing(&path(p), &facts(true), &referenced), "{p} should be skipped");
        }
    }

    #[test]
    fn the_tools_own_case_directory_cannot_become_a_candidate() {
        let referenced = HashSet::new();
        for p in [
            "D:\\case\\report.json",
            "D:\\case\\report.txt",
            "D:\\case\\sample\\C1788.bin",
            "C:\\Users\\analyst\\Desktop\\malmathic-case\\sample\\C1.bin",
        ] {
            assert!(
                !worth_observing(&path(p), &facts(true), &referenced),
                "{p} is something malmathic wrote; it must not become a candidate"
            );
            assert!(
                !path(p).is_executable_extension(),
                "{p} would be admissible the moment it had an executable \
                 extension — acquisition must keep renaming samples to `.bin`"
            );
        }

        for (mine, neutral) in [
            ("C:\\Windows\\Temp\\malmathic.exe", "C:\\Windows\\Temp\\x.exe"),
            ("C:\\malmathic.exe", "C:\\x.exe"),
            ("C:\\malmathic-case\\sample\\payload.exe", "C:\\some-other-dir\\sample\\payload.exe"),
        ] {
            assert_eq!(
                worth_observing(&path(mine), &facts(true), &referenced),
                worth_observing(&path(neutral), &facts(true), &referenced),
                "{mine} was treated differently from {neutral}; nothing may be \
                 admitted or skipped for being named like this tool"
            );
        }
        assert!(worth_observing(
            &path("C:\\Windows\\Temp\\malmathic.exe"),
            &facts(true),
            &referenced
        ));
        assert!(worth_observing(&path("C:\\malmathic.exe"), &facts(true), &referenced));
    }

    #[test]
    fn a_file_an_artifact_pointed_at_is_always_observed() {
        let mut referenced = HashSet::new();
        referenced.insert("\\users\\bob\\appdata\\roaming\\thing.exe".to_string());
        assert!(worth_observing(
            &path("C:\\Users\\bob\\AppData\\Roaming\\thing.exe"),
            &facts(true),
            &referenced
        ));
    }

    #[test]
    fn deleted_executables_are_always_observed() {
        let referenced = HashSet::new();
        assert!(worth_observing(&path("C:\\Users\\bob\\gone.exe"), &facts(false), &referenced));
        assert!(!worth_observing(&path("C:\\Users\\bob\\gone.txt"), &facts(false), &referenced));
    }

    #[test]
    fn executables_in_places_software_is_never_installed_are_observed() {
        let referenced = HashSet::new();
        assert!(worth_observing(&path("C:\\payload.exe"), &facts(true), &referenced));
        assert!(worth_observing(&path("C:\\Windows\\Temp\\x.exe"), &facts(true), &referenced));
    }

    fn aged(days: i64) -> FileFacts {
        const DIRECTORY: u64 = 133_484_160_000_000_000;
        const TICKS_PER_DAY: i64 = 864_000_000_000;
        let created = (DIRECTORY as i64 + days * TICKS_PER_DAY) as u64;
        FileFacts {
            si_created: mm_core::from_filetime(created),
            parent_created: mm_core::from_filetime(DIRECTORY),
            ..facts(true)
        }
    }

    fn linked(count: u16) -> FileFacts {
        FileFacts { hard_links: count, ..facts(true) }
    }

    #[test]
    fn an_unlinked_executable_in_the_system_directory_is_observed() {
        let referenced = HashSet::new();
        let dropped = path("C:\\Windows\\System32\\sspisrv.dll");
        assert!(worth_observing(&dropped, &linked(1), &referenced));
        assert!(!worth_observing(&dropped, &linked(2), &referenced));
        assert!(!worth_observing(&dropped, &linked(9), &referenced));
        assert!(!worth_observing(&dropped, &linked(0), &referenced));
        assert!(!worth_observing(
            &path("C:\\Windows\\System32\\drivers\\etc\\hosts"),
            &linked(1),
            &referenced
        ));
    }

    #[test]
    fn each_rule_reports_the_anomaly_it_actually_found() {
        assert_eq!(
            out_of_band_arrival(&path("C:\\Windows\\System32\\sspisrv.dll"), &linked(1)),
            Some(OutOfBandArrival::NotAComponentStoreLink { hard_links: 1 })
        );
        assert_eq!(
            out_of_band_arrival(&path("C:\\Windows\\System32\\sspisrv.dll"), &linked(2)),
            None
        );
        assert_eq!(
            out_of_band_arrival(&path("C:\\Program Files\\Vendor\\uxtheme.dll"), &aged(180)),
            Some(OutOfBandArrival::AfterItsDirectory { days_later: 180 })
        );
        assert_eq!(
            out_of_band_arrival(&path("C:\\Program Files\\Vendor\\uxtheme.dll"), &aged(3)),
            None
        );
        assert_eq!(
            out_of_band_arrival(&path("C:\\Program Files\\Vendor\\uxtheme.dll"), &aged(-40)),
            None
        );
    }

    #[test]
    fn the_driver_store_is_excluded_from_the_hard_link_rule() {
        let referenced = HashSet::new();
        for p in [
            "C:\\Windows\\System32\\DriverStore\\FileRepository\\oem9.inf_amd64_a1\\oemdrv.sys",
            "C:\\Windows\\System32\\DRVSTORE\\pkg\\oemdrv.sys",
        ] {
            assert!(!worth_observing(&path(p), &linked(1), &referenced), "{p}");
        }
        assert!(worth_observing(
            &path("C:\\Windows\\System32\\driverstore.dll"),
            &linked(1),
            &referenced
        ));
    }

    #[test]
    fn the_component_store_is_not_subject_to_the_hard_link_rule() {
        let referenced = HashSet::new();
        assert!(!worth_observing(
            &path("C:\\Windows\\WinSxS\\amd64_comctl32_deadbeef\\comctl32.dll"),
            &linked(1),
            &referenced
        ));
    }

    #[test]
    fn an_executable_that_arrived_long_after_its_directory_is_observed() {
        let referenced = HashSet::new();
        let p = path("C:\\Program Files\\Vendor\\Reader\\version.dll");
        assert!(worth_observing(&p, &aged(90), &referenced));
        assert!(worth_observing(&p, &aged(8), &referenced));
        assert!(!worth_observing(&p, &aged(7), &referenced));
        assert!(!worth_observing(&p, &aged(0), &referenced));
        assert!(!worth_observing(&p, &aged(-400), &referenced));
    }

    #[test]
    fn an_undated_program_files_executable_is_not_observed() {
        let referenced = HashSet::new();
        let p = path("C:\\Program Files\\Vendor\\Reader\\version.dll");
        let mut no_parent = aged(90);
        no_parent.parent_created = None;
        assert!(!worth_observing(&p, &no_parent, &referenced));
        let mut no_self = aged(90);
        no_self.si_created = None;
        assert!(!worth_observing(&p, &no_self, &referenced));
    }

    #[test]
    fn the_out_of_band_rule_only_admits_files_that_still_exist() {
        let deleted = FileFacts { in_use: false, ..linked(1) };
        assert!(!arrived_out_of_band(&path("C:\\Windows\\System32\\sspisrv.dll"), &deleted));
    }

    #[test]
    fn scripts_are_not_admitted_by_the_out_of_band_rule() {
        let referenced = HashSet::new();
        for p in [
            r"C:\Program Files\WindowsPowerShell\Modules\Pester\Context.ps1",
            r"C:\Program Files\Vendor\install.bat",
            r"C:\Program Files\Vendor\node_modules\index.js",
        ] {
            assert!(!worth_observing(&path(p), &aged(90), &referenced), "{p}");
        }
        assert!(worth_observing(&path(r"C:\Windows\System32\imdisk.cpl"), &linked(1), &referenced));
        assert!(worth_observing(
            &path(r"C:\Program Files\Vendor\screensaver.scr"),
            &aged(90),
            &referenced
        ));
    }

    #[test]
    fn zones_outside_the_measured_two_are_not_admitted() {
        let referenced = HashSet::new();
        for p in [
            "C:\\Windows\\assembly\\GAC_MSIL\\System\\v4.0\\System.dll",
            "C:\\ProgramData\\Vendor\\helper.dll",
            "C:\\Users\\bob\\AppData\\Roaming\\thing.dll",
        ] {
            let mut facts = aged(90);
            facts.hard_links = 1;
            assert!(!worth_observing(&path(p), &facts, &referenced), "{p}");
        }
    }

    const CLSID: &str = "{0002df01-0000-0000-c000-000000000046}";

    fn com_at(hive: &str, key: &str, target: &str) -> Observation {
        Observation::about_path(
            ArtifactSource::Registry { hive: hive.into(), key: key.into() },
            path(target),
            ObservationKind::Persistence {
                kind: mm_core::PersistenceKind::ComServer,
                raw_value: target.into(),
            },
        )
    }

    fn machine_com(clsid: &str, target: &str) -> Observation {
        com_at("SOFTWARE", &format!("Classes\\CLSID\\{clsid}\\InprocServer32\\(Default)"), target)
    }

    fn wow_com(clsid: &str, target: &str) -> Observation {
        com_at(
            "SOFTWARE",
            &format!("Classes\\Wow6432Node\\CLSID\\{clsid}\\InprocServer32\\(Default)"),
            target,
        )
    }

    fn user_com(clsid: &str, target: &str) -> Observation {
        com_at("UsrClass.dat (bob)", &format!("CLSID\\{clsid}\\InprocServer32\\(Default)"), target)
    }

    fn kind_of(o: &Observation) -> mm_core::PersistenceKind {
        match &o.kind {
            ObservationKind::Persistence { kind, .. } => *kind,
            other => panic!("not a persistence observation: {other:?}"),
        }
    }

    fn deleted(mut o: Observation) -> Observation {
        if let ObservationKind::Persistence { raw_value, .. } = &mut o.kind {
            *raw_value = format!("[deleted] {raw_value}");
        }
        o
    }

    fn raw_of(o: &Observation) -> String {
        match &o.kind {
            ObservationKind::Persistence { raw_value, .. } => raw_value.clone(),
            other => panic!("not a persistence observation: {other:?}"),
        }
    }

    #[test]
    fn a_registration_recovered_from_a_freed_cell_is_never_a_hijack() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll"),
            deleted(user_com(CLSID, "C:\\Users\\bob\\AppData\\Roaming\\evil\\hijack.dll")),
        ];
        assert_eq!(promote_com_hijacks(&mut observations), 0);
        assert_eq!(kind_of(&observations[1]), mm_core::PersistenceKind::ComServer);
    }

    #[test]
    fn a_deleted_machine_wide_registration_cannot_be_redirected_away_from() {
        let mut observations = vec![
            deleted(machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll")),
            user_com(CLSID, "C:\\Users\\bob\\AppData\\Roaming\\evil\\hijack.dll"),
        ];
        assert_eq!(promote_com_hijacks(&mut observations), 0);
    }

    #[test]
    fn a_live_per_user_registration_is_still_promoted() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll"),
            user_com(CLSID, "C:\\Users\\bob\\AppData\\Roaming\\evil\\hijack.dll"),
        ];
        assert_eq!(promote_com_hijacks(&mut observations), 1);
    }

    #[test]
    fn a_registration_a_live_machine_wide_one_superseded_stops_reading_as_deleted() {
        let mut observations = vec![
            machine_com(
                CLSID,
                "C:\\Program Files (x86)\\Microsoft OneDrive\\23.038.0219.0001\\FileCoAuth.exe",
            ),
            deleted(user_com(
                CLSID,
                "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\21.220.1024.0005\\FileCoAuth.exe",
            )),
        ];
        assert_eq!(relabel_superseded_com_registrations(&mut observations), 1);
        assert!(
            raw_of(&observations[1]).starts_with(SUPERSEDED_PERSISTENCE_MARK),
            "{}",
            raw_of(&observations[1])
        );
        assert!(!raw_of(&observations[1]).contains(DELETED_PERSISTENCE_MARK));
    }

    #[test]
    fn a_removed_registration_naming_a_different_module_is_still_deleted() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll"),
            deleted(user_com(CLSID, "C:\\Users\\bob\\AppData\\Roaming\\evil\\hijack.dll")),
        ];
        assert_eq!(relabel_superseded_com_registrations(&mut observations), 0);
        assert!(raw_of(&observations[1]).starts_with(DELETED_PERSISTENCE_MARK));
    }

    #[test]
    fn a_per_user_registration_cannot_supersede_another() {
        let mut observations = vec![
            user_com(CLSID, "C:\\Users\\bob\\AppData\\Local\\App\\2\\thing.exe"),
            deleted(user_com(CLSID, "C:\\Users\\bob\\AppData\\Local\\App\\1\\thing.exe")),
        ];
        assert_eq!(relabel_superseded_com_registrations(&mut observations), 0);
    }

    #[test]
    fn a_deleted_machine_wide_registration_cannot_supersede_anything() {
        let mut observations = vec![
            deleted(machine_com(CLSID, "C:\\Program Files\\Vendor\\2\\thing.exe")),
            deleted(user_com(CLSID, "C:\\Users\\bob\\AppData\\Local\\Vendor\\1\\thing.exe")),
        ];
        assert_eq!(relabel_superseded_com_registrations(&mut observations), 0);
    }

    #[test]
    fn an_ordinary_com_registration_does_not_create_a_candidate() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll"),
            machine_com("{1}", "C:\\Program Files\\Vendor\\ext.dll"),
            machine_com("{2}", "C:\\ProgramData\\Vendor\\ext.dll"),
            machine_com("{3}", "ole32.dll"),
        ];
        let deferred = defer_ordinary_com_registrations(&mut observations);
        assert_eq!(deferred.len(), 4, "all four are ordinary places for a COM server");
        assert!(observations.is_empty(), "nothing should be left to seed a candidate");
        assert!(mm_score::graph::build(observations, 0.0).is_empty());
    }

    #[test]
    fn a_com_registration_outside_the_software_zones_creates_a_candidate() {
        for target in [
            "C:\\Users\\bob\\AppData\\Roaming\\evil\\hijack.dll",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\x.dll",
            "C:\\hijack.dll",
            "C:\\Windows\\Temp\\x.dll",
            "D:\\stage\\x.dll",
        ] {
            let mut observations = vec![machine_com(CLSID, target)];
            let deferred = defer_ordinary_com_registrations(&mut observations);
            assert!(deferred.is_empty(), "{target} should not be deferred");
            assert_eq!(
                mm_score::graph::build(observations, 0.0).len(),
                1,
                "{target} should still become a candidate on its own"
            );
        }
    }

    #[test]
    fn a_com_registration_recovered_from_a_deleted_cell_is_never_deferred() {
        let mut o = machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll");
        if let ObservationKind::Persistence { raw_value, .. } = &mut o.kind {
            *raw_value = format!("[deleted] {raw_value}");
        }
        let mut observations = vec![o];
        assert!(defer_ordinary_com_registrations(&mut observations).is_empty());
        assert_eq!(observations.len(), 1);
    }

    #[test]
    fn a_deferred_registration_rejoins_a_file_something_else_implicated() {
        let target = "C:\\Program Files\\Vendor\\ext.dll";
        let mut observations = vec![
            machine_com(CLSID, target),
            Observation::about_path(
                ArtifactSource::Amcache,
                path(target),
                ObservationKind::Executed { when: None, run_count: None },
            ),
            machine_com("{9}", "C:\\Windows\\System32\\nobody-else-mentions-this.dll"),
        ];
        let deferred = defer_ordinary_com_registrations(&mut observations);
        assert_eq!(deferred.len(), 2);
        reattach_deferred_com(&mut observations, deferred);

        let candidates = mm_score::graph::build(observations, 0.0);
        assert_eq!(candidates.len(), 1, "only the executed file should be a candidate");
        assert_eq!(
            candidates[0].observations.len(),
            2,
            "the registration should be back on it as evidence"
        );
    }

    #[test]
    fn a_per_user_registration_redirecting_a_machine_class_is_a_hijack() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll"),
            user_com(CLSID, "C:\\Users\\bob\\AppData\\Roaming\\evil\\hijack.dll"),
        ];
        assert_eq!(promote_com_hijacks(&mut observations), 1);
        assert_eq!(kind_of(&observations[0]), mm_core::PersistenceKind::ComServer);
        assert_eq!(kind_of(&observations[1]), mm_core::PersistenceKind::ComHijack);

        let deferred = defer_ordinary_com_registrations(&mut observations);
        assert_eq!(deferred.len(), 1, "only the machine-wide half is ordinary");
        let candidates = mm_score::graph::build(observations, 0.0);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].label().contains("hijack.dll"));
    }

    #[test]
    fn a_hijack_pointing_at_a_conventional_zone_is_still_not_deferred() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll"),
            user_com(CLSID, "C:\\Program Files\\Vendor\\shim.dll"),
        ];
        assert_eq!(promote_com_hijacks(&mut observations), 1);
        let deferred = defer_ordinary_com_registrations(&mut observations);
        assert_eq!(deferred.len(), 1);
        assert_eq!(observations.len(), 1);
        assert!(observations[0].path.as_ref().unwrap().key().contains("shim.dll"));
    }

    #[test]
    fn a_per_user_registration_naming_the_machine_target_is_not_a_hijack() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Program Files\\Vendor\\ext.dll"),
            user_com(CLSID, "%ProgramFiles%\\Vendor\\ext.dll"),
        ];
        assert_eq!(promote_com_hijacks(&mut observations), 0);
    }

    #[test]
    fn a_class_the_machine_never_registered_is_not_a_hijack() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Windows\\System32\\shell32.dll"),
            user_com(
                "{deadbeef-0000-0000-0000-000000000001}",
                "C:\\Users\\bob\\AppData\\Local\\PowerToys\\ext.dll",
            ),
        ];
        assert_eq!(promote_com_hijacks(&mut observations), 0);
        let deferred = defer_ordinary_com_registrations(&mut observations);
        assert_eq!(deferred.len(), 1);
        assert_eq!(observations.len(), 1);
    }

    #[test]
    fn the_thirty_two_bit_mirror_does_not_manufacture_a_hijack() {
        let mut observations = vec![
            machine_com(CLSID, "C:\\Windows\\System32\\ext.dll"),
            wow_com(CLSID, "C:\\Windows\\SysWOW64\\ext.dll"),
            user_com(CLSID, "C:\\Windows\\SysWOW64\\ext.dll"),
        ];
        assert_eq!(promote_com_hijacks(&mut observations), 0);
    }

    #[test]
    fn no_machine_hive_means_no_hijack_claim() {
        let mut observations =
            vec![user_com(CLSID, "C:\\Users\\bob\\AppData\\Roaming\\evil\\hijack.dll")];
        assert_eq!(promote_com_hijacks(&mut observations), 0);
        assert_eq!(kind_of(&observations[0]), mm_core::PersistenceKind::ComServer);
    }

    #[test]
    fn a_clsid_is_read_out_of_every_key_shape_the_hives_use() {
        assert_eq!(
            clsid_of("Classes\\CLSID\\{AB}\\InprocServer32\\(Default)").as_deref(),
            Some("{ab}")
        );
        assert_eq!(
            clsid_of("Classes\\Wow6432Node\\CLSID\\{AB}\\LocalServer32\\(Default)").as_deref(),
            Some("{ab}")
        );
        assert_eq!(clsid_of("CLSID\\{ab}\\InprocServer32\\(Default)").as_deref(), Some("{ab}"));
        assert_eq!(clsid_of("Microsoft\\Windows\\CurrentVersion\\Run"), None);
        assert_eq!(clsid_of(""), None);
        assert_eq!(clsid_of("{}"), None);
    }

    #[test]
    fn the_prior_tightens_as_candidates_multiply() {
        let few = prior_log_odds(10);
        let many = prior_log_odds(10_000);
        assert!(many < few, "more candidates must mean a stricter prior");
        assert!((few - (1.0f64 / 10.0).ln()).abs() < 1e-9);
        assert!(prior_log_odds(0).is_finite());
        assert!(prior_log_odds(1).is_finite());
    }

    #[test]
    fn a_realistic_prior_suppresses_weak_lone_evidence() {
        let mut c = Candidate::new(CandidateId(0), prior_log_odds(5_000));
        c.evidence.push(mm_core::Evidence::new("unsigned_in_user_zone", 1.1, "unsigned"));
        assert!(c.probability() < mm_report::DEFAULT_THRESHOLD);
    }

    #[test]
    fn scoring_assigns_the_same_prior_to_every_candidate() {
        let observations = vec![
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\a.exe"),
                ObservationKind::Executed { when: None, run_count: None },
            ),
            Observation::about_hash(
                ArtifactSource::DefenderLog { event_id: 1116 },
                FileHash::compute(b"x"),
                ObservationKind::HashRecovered,
            ),
        ];
        let candidates = build_and_score(
            observations,
            &Baseline::default(),
            &Weights::embedded(),
            &mm_core::Enumeration::complete(120_000),
        );
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].prior_log_odds, candidates[1].prior_log_odds);
        assert!(candidates[0].prior_log_odds < 0.0);
    }

    #[test]
    fn a_short_walk_does_not_sharpen_the_base_rate() {
        let observations = || {
            vec![
                Observation::about_path(
                    ArtifactSource::Amcache,
                    path("C:\\a.exe"),
                    ObservationKind::Executed { when: None, run_count: None },
                ),
                Observation::about_path(
                    ArtifactSource::Amcache,
                    path("C:\\b.exe"),
                    ObservationKind::Executed { when: None, run_count: None },
                ),
            ]
        };
        let weights = Weights::embedded();

        let whole = build_and_score(
            observations(),
            &Baseline::default(),
            &weights,
            &mm_core::Enumeration::complete(100_000),
        );
        let short = build_and_score(
            observations(),
            &Baseline::default(),
            &weights,
            &mm_core::Enumeration::partial(50_000, 50_000),
        );

        assert!(
            short[0].prior_log_odds < whole[0].prior_log_odds,
            "the short walk scored against {} where the complete one scored against {}",
            short[0].prior_log_odds,
            whole[0].prior_log_odds
        );
        let expected = mm_core::log_odds_of_one_in(short.len() as f64 + 50_000.0);
        assert!((short[0].prior_log_odds - expected).abs() < 1e-9, "{}", short[0].prior_log_odds);
    }

    #[test]
    fn a_walk_that_never_happened_falls_back_to_the_bare_count() {
        let observations = vec![Observation::about_path(
            ArtifactSource::Amcache,
            path("C:\\a.exe"),
            ObservationKind::Executed { when: None, run_count: None },
        )];
        let candidates = build_and_score(
            observations,
            &Baseline::default(),
            &Weights::embedded(),
            &mm_core::Enumeration::not_attempted(),
        );
        assert_eq!(candidates[0].prior_log_odds, prior_log_odds(candidates.len()));
    }

    fn scored(id: u32, p: &str, evidence_log_lr: f64) -> Candidate {
        let mut c = Candidate::new(CandidateId(id), prior_log_odds(20_000));
        c.path = Some(path(p));
        c.evidence.push(mm_core::Evidence::new("f", evidence_log_lr, "because"));
        c
    }

    #[test]
    fn only_candidates_a_signature_could_still_move_are_read() {
        let weights = Weights::embedded();
        let headroom = weights.max_log_lr_in_group(group::SIGNATURE);
        let prior = prior_log_odds(20_000);

        let reachable = scored(0, "C:\\Users\\bob\\near.exe", -prior - headroom + 0.1);
        let hopeless = scored(1, "C:\\Users\\bob\\far.exe", 0.5);
        let candidates = vec![reachable, hopeless];

        let band = verification_band(&candidates, &weights, 0);
        assert_eq!(band, vec![0], "the reachable candidate must be checked");

        assert_eq!(verification_band(&candidates, &weights, 2), vec![0, 1]);
    }

    #[test]
    fn nothing_outside_the_band_could_have_become_a_finding() {
        let weights = Weights::embedded();
        let headroom = weights.max_log_lr_in_group(group::SIGNATURE);
        let candidates: Vec<Candidate> = (0..50)
            .map(|i| scored(i, &format!("C:\\Users\\bob\\f{i}.exe"), i as f64 * 0.4))
            .collect();

        let band = verification_band(&candidates, &weights, 0);
        for (i, candidate) in candidates.iter().enumerate() {
            if !band.contains(&i) {
                assert!(
                    candidate.logit() + headroom < logit(mm_report::DEFAULT_THRESHOLD),
                    "candidate {i} was skipped but could have reached the threshold"
                );
            }
        }
        assert!(!band.is_empty(), "the band must not be vacuous");
    }

    #[test]
    fn only_locatable_executables_are_worth_reading() {
        assert!(is_verifiable_shape(&scored(0, "C:\\Windows\\System32\\svchost.exe", 0.0)));
        assert!(is_verifiable_shape(&scored(0, "C:\\Windows\\System32\\drivers\\x.sys", 0.0)));
        assert!(!is_verifiable_shape(&scored(0, "notepad.exe", 0.0)));
        assert!(!is_verifiable_shape(&scored(0, "C:\\Users\\bob\\notes.txt", 0.0)));
        assert!(!is_verifiable_shape(&Candidate::new(CandidateId(0), -9.2)));
    }

    #[test]
    fn the_threshold_in_log_odds_is_where_the_report_puts_it() {
        assert!(logit(mm_report::DEFAULT_THRESHOLD).abs() < 1e-12);
        assert!(logit(0.9) > 0.0 && logit(0.1) < 0.0);
    }

    #[test]
    fn the_verification_headroom_tracks_the_weight_table() {
        let weights = Weights::embedded();
        assert_eq!(
            weights.max_log_lr_in_group(group::SIGNATURE),
            weights.get(mm_score::weights::feature::SIGNATURE_INVALID).unwrap().log_lr
        );
    }

    fn created(
        id: u32,
        p: &str,
        evidence_log_lr: f64,
        when: chrono::DateTime<chrono::Utc>,
    ) -> Candidate {
        let mut c = scored(id, p, evidence_log_lr);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(p),
            ObservationKind::FileExists {
                size: 4096,
                created: Some(when),
                modified: None,
                mft_modified: None,
                record: None,
            },
        ));
        c
    }

    fn at(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_800_000_000 + seconds, 0).expect("valid")
    }

    fn window_case() -> Vec<Candidate> {
        let prior = prior_log_odds(3);
        let dropper = "C:\\Users\\bob\\dropper.exe";
        let mut seed = Candidate::new(CandidateId(0), prior);
        seed.observe(Observation::about_path(
            ArtifactSource::DefenderQuarantine,
            path(dropper),
            ObservationKind::Quarantined {
                product: "Windows Defender".into(),
                threat: Some("Trojan:Win32/Wacatac".into()),
                when: None,
                severity: None,
            },
        ));
        seed.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(dropper),
            ObservationKind::Executed { when: Some(at(0)), run_count: Some(1) },
        ));
        seed.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(dropper),
            ObservationKind::FileExists {
                size: 1024,
                created: Some(at(0)),
                modified: None,
                mft_modified: None,
                record: None,
            },
        ));
        let mut candidates = vec![
            seed,
            created(1, "C:\\Users\\bob\\beside.exe", 0.0, at(30)),
            created(2, "C:\\Users\\bob\\elsewhere.exe", 0.0, at(90_000)),
        ];
        for c in &mut candidates {
            c.prior_log_odds = prior;
            c.evidence = mm_score::extract(c, &Baseline::default(), &Weights::embedded());
        }
        candidates
    }

    #[test]
    fn the_journal_checks_the_window_and_moves_no_score() {
        let (mut with, mut without) = (window_case(), window_case());
        let keys: Vec<String> =
            with.iter().map(|c| c.path.as_ref().expect("a path").key().to_string()).collect();
        let clock = mm_harvest::usn_journal::Clock::new(
            vec![(keys[0].clone(), at(0)), (keys[1].clone(), at(30))],
            Some(at(-10_000)),
        );

        let mut a = Coverage::default();
        apply_incident_window(
            &mut without,
            &Baseline::default(),
            &Weights::embedded(),
            &mm_harvest::usn_journal::Clock::default(),
            &mut a,
            Style::Silent,
        );
        let mut b = Coverage::default();
        apply_incident_window(
            &mut with,
            &Baseline::default(),
            &Weights::embedded(),
            &clock,
            &mut b,
            Style::Silent,
        );

        let scores_without: Vec<f64> = without.iter().map(|c| c.logit()).collect();
        let scores_with: Vec<f64> = with.iter().map(|c| c.logit()).collect();
        assert_eq!(scores_without, scores_with, "the change journal must not move a score");

        assert!(
            !a.artifacts.iter().any(|l| l.artifact.contains("checked against the change journal")),
            "{:#?}",
            a.artifacts
        );
        let line = b
            .artifacts
            .iter()
            .find(|l| l.artifact.contains("checked against the change journal"))
            .expect("the corroboration line");
        assert!(line.artifact.contains("2 of the 2"), "{}", line.artifact);
        assert!(line.artifact.contains("Nothing here is scored"), "{}", line.artifact);
    }

    #[test]
    fn a_journal_that_disagrees_says_so_and_names_the_file() {
        let mut candidates = window_case();
        let beside = candidates[1].path.as_ref().expect("a path").key().to_string();
        let seed = candidates[0].path.as_ref().expect("a path").key().to_string();
        let clock = mm_harvest::usn_journal::Clock::new(
            vec![(seed, at(0)), (beside, at(30 + 172_800))],
            Some(at(-10_000)),
        );
        let mut control = window_case();
        let mut ignored = Coverage::default();
        apply_incident_window(
            &mut control,
            &Baseline::default(),
            &Weights::embedded(),
            &mm_harvest::usn_journal::Clock::default(),
            &mut ignored,
            Style::Silent,
        );
        let mut coverage = Coverage::default();
        apply_incident_window(
            &mut candidates,
            &Baseline::default(),
            &Weights::embedded(),
            &clock,
            &mut coverage,
            Style::Silent,
        );
        let control_scores: Vec<f64> = control.iter().map(|c| c.logit()).collect();
        let after: Vec<f64> = candidates.iter().map(|c| c.logit()).collect();
        assert_eq!(control_scores, after, "a contradicted timestamp must not move a score either");
        let line = coverage
            .artifacts
            .iter()
            .find(|l| l.artifact.contains("checked against the change journal"))
            .expect("the corroboration line");
        assert!(line.artifact.contains("1 DISAGREE"), "{}", line.artifact);
        assert!(line.artifact.contains("beside.exe"), "{}", line.artifact);
    }

    #[test]
    fn a_file_older_than_the_journal_is_unknown_rather_than_unconfirmed() {
        let mut candidates = window_case();
        let clock = mm_harvest::usn_journal::Clock::new(Vec::new(), Some(at(10_000)));
        let mut coverage = Coverage::default();
        apply_incident_window(
            &mut candidates,
            &Baseline::default(),
            &Weights::embedded(),
            &clock,
            &mut coverage,
            Style::Silent,
        );
        let line = coverage
            .artifacts
            .iter()
            .find(|l| l.artifact.contains("checked against the change journal"))
            .expect("the corroboration line");
        assert!(line.artifact.contains("predate the journal"), "{}", line.artifact);
        assert!(line.artifact.contains("UNKNOWN"), "{}", line.artifact);
    }

    #[test]
    fn a_machine_with_no_finding_gets_no_incident_window() {
        let mut candidates: Vec<Candidate> = (0..2_000)
            .map(|i| created(i, &format!("C:\\Users\\bob\\f{i}.exe"), 1.0, at(i as i64 % 60)))
            .collect();
        let before: Vec<f64> = candidates.iter().map(|c| c.logit()).collect();

        let mut coverage = Coverage::default();
        apply_incident_window(
            &mut candidates,
            &Baseline::default(),
            &Weights::embedded(),
            &mm_harvest::usn_journal::Clock::default(),
            &mut coverage,
            Style::Silent,
        );

        let after: Vec<f64> = candidates.iter().map(|c| c.logit()).collect();
        assert_eq!(before, after, "no score may move when there is no finding to cluster around");
        let line = coverage.artifacts.last().expect("the window must record coverage either way");
        assert_eq!(line.artifact, "incident window");
        assert!(
            matches!(&line.status, CoverageStatus::NotAvailableHere { reason } if reason.contains("no candidate")),
            "{:?}",
            line.status
        );
    }

    #[test]
    fn a_finding_pulls_in_what_was_created_beside_it() {
        let prior = prior_log_odds(3);
        let dropper = "C:\\Users\\bob\\dropper.exe";
        let mut seed = Candidate::new(CandidateId(0), prior);
        seed.observe(Observation::about_path(
            ArtifactSource::DefenderQuarantine,
            path(dropper),
            ObservationKind::Quarantined {
                product: "Windows Defender".into(),
                threat: Some("Trojan:Win32/Wacatac".into()),
                when: None,
                severity: None,
            },
        ));
        seed.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(dropper),
            ObservationKind::Executed { when: Some(at(0)), run_count: Some(1) },
        ));

        let mut candidates = vec![
            seed,
            created(1, "C:\\Users\\bob\\beside.exe", 0.0, at(30)),
            created(2, "C:\\Users\\bob\\elsewhere.exe", 0.0, at(90_000)),
        ];
        for c in &mut candidates {
            c.prior_log_odds = prior;
            c.evidence = mm_score::extract(c, &Baseline::default(), &Weights::embedded());
        }
        assert!(
            candidates[0].probability() >= mm_report::DEFAULT_THRESHOLD,
            "the seed must be a finding"
        );
        let seed_before = candidates[0].logit();

        let mut coverage = Coverage::default();
        apply_incident_window(
            &mut candidates,
            &Baseline::default(),
            &Weights::embedded(),
            &mm_harvest::usn_journal::Clock::default(),
            &mut coverage,
            Style::Silent,
        );

        assert!(
            (candidates[0].logit() - seed_before).abs() < 1e-9,
            "the seed must not corroborate itself"
        );
        assert!(
            candidates[1].evidence.iter().any(|e| e.feature == "created_in_incident_window"),
            "{:#?}",
            candidates[1].evidence
        );
        assert!(
            !candidates[2].evidence.iter().any(|e| e.feature == "created_in_incident_window"),
            "a file created a day later is not in the burst: {:#?}",
            candidates[2].evidence
        );

        let line = coverage.artifacts.last().unwrap();
        assert!(line.artifact.starts_with("incident window ("), "{}", line.artifact);
        assert!(matches!(line.status, CoverageStatus::Read { observations: 1 }));
    }

    fn av_observation(raw: &str, event_id: u32) -> Observation {
        Observation::about_path(
            ArtifactSource::DefenderLog { event_id },
            path(raw),
            ObservationKind::AvDetected {
                product: "Windows Defender".into(),
                threat: Some("Trojan:Win32/Egairtigado!rfn".into()),
                when: None,
                severity: None,
            },
        )
    }

    #[test]
    fn a_detection_naming_a_file_this_volume_does_not_have_scores_nothing() {
        let mut observations = vec![av_observation(
            "W:\\$RECYCLE.BIN\\S-1-5-21-1\\$RKNXU3F\\\
             c3693a465b935ce368769f456942fba955512cf77a421db5bda2a5f4edbd117e.exe",
            1116,
        )];

        let deferred = defer_defender_log(&mut observations);
        assert_eq!(deferred.len(), 1);
        assert!(observations.is_empty(), "the verdict must not stand on its own");

        let mut coverage = Coverage::default();
        reattach_defender_log(&mut observations, deferred, &mut coverage);
        assert!(observations.is_empty());

        let matched = coverage
            .artifacts
            .iter()
            .find(|a| a.artifact.starts_with("Defender detections matched"))
            .expect("coverage must say what happened to the detections");
        assert!(matches!(matched.status, CoverageStatus::Absent));
        assert!(
            coverage.warnings.iter().any(|w| w.contains("this volume does not have")),
            "the analyst has to be told the detection existed: {:?}",
            coverage.warnings
        );
    }

    #[test]
    fn a_detection_naming_a_file_that_is_here_rejoins_it() {
        let here = "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe";
        let mut observations = vec![
            av_observation(here, 1118),
            Observation::about_path(
                ArtifactSource::Mft,
                path(here),
                ObservationKind::FileExists {
                    size: 4096,
                    created: None,
                    modified: None,
                    mft_modified: None,
                    record: None,
                },
            ),
        ];

        let deferred = defer_defender_log(&mut observations);
        assert_eq!(deferred.len(), 1);
        assert_eq!(observations.len(), 1, "only the $MFT fact is left holding the path");

        let mut coverage = Coverage::default();
        reattach_defender_log(&mut observations, deferred, &mut coverage);
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().any(is_defender_log));

        let matched = coverage
            .artifacts
            .iter()
            .find(|a| a.artifact.starts_with("Defender detections matched"))
            .unwrap();
        assert!(matches!(matched.status, CoverageStatus::Read { observations: 1 }));
        assert!(coverage.warnings.is_empty());
    }

    #[test]
    fn deferral_covers_the_log_and_spares_the_quarantine_store() {
        let quarantined = ObservationKind::Quarantined {
            product: "Windows Defender".into(),
            threat: Some("Virus:DOS/EICAR_Test_File".into()),
            when: None,
            severity: None,
        };
        let mut observations = vec![
            av_observation("C:\\a.exe", 1116),
            Observation::about_path(
                ArtifactSource::DefenderLog { event_id: 1117 },
                path("C:\\b.exe"),
                quarantined.clone(),
            ),
            Observation::about_path(
                ArtifactSource::DefenderQuarantine,
                path("C:\\c.exe"),
                quarantined,
            ),
        ];

        let deferred = defer_defender_log(&mut observations);
        assert_eq!(deferred.len(), 2, "both log observations are held back");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].source, ArtifactSource::DefenderQuarantine);
    }

    #[test]
    fn a_panicking_parser_costs_its_own_coverage_line_and_nothing_else() {
        let caught = guarded(|| -> usize { panic!("a damaged cell") });
        assert!(caught.is_err());
        let reason = caught.unwrap_err();
        assert!(reason.contains("parser failure"), "{reason}");
        assert!(reason.contains("a damaged cell"), "the reason must reach the report: {reason}");
        assert_eq!(guarded(|| 7usize).ok(), Some(7));
    }

    #[test]
    fn the_release_profile_still_unwinds() {
        let manifest = include_str!("../../../Cargo.toml");
        let profile = manifest
            .split_once("[profile.release]")
            .expect("the release profile must still exist")
            .1;
        assert!(
            !profile.contains("panic"),
            "the release profile sets a panic strategy; `guarded` only contains a panic \
             in an unwinding build:\n{profile}"
        );
    }

    #[test]
    fn only_the_defender_channel_is_deferred() {
        let other = Observation::about_path(
            ArtifactSource::EventLog { channel: "Security".into(), event_id: 4688 },
            path("C:\\x.exe"),
            ObservationKind::Executed { when: None, run_count: None },
        );
        assert!(!is_defender_log(&other));
        assert!(is_defender_log(&av_observation("C:\\x.exe", 1116)));
    }

    #[test]
    fn non_profile_directories_are_excluded_from_user_enumeration() {
        for name in ["Public", "Default", "All Users", "desktop.ini"] {
            assert!(
                NON_PROFILE_DIRECTORIES.contains(&name.to_ascii_lowercase().as_str()),
                "{name} should not be treated as a profile"
            );
        }
    }
}

#[cfg(test)]
mod other_volume_tests {
    use super::*;
    use mm_core::{ArtifactSource, CandidateId, ObservationKind};

    fn observation(source: ArtifactSource, kind: ObservationKind, raw: &str) -> Observation {
        Observation { source, kind, path: NormalizedPath::parse(raw), hash: Default::default() }
    }

    fn identity() -> VolumeIdentity {
        VolumeIdentity::new(1)
            .with_system_root("C:\\Windows")
            .with_mounted_devices([('W', "MBR disk signature 0x1a2b3c4d at offset 1048576".into())])
    }

    #[test]
    fn every_artifact_that_records_a_path_is_covered() {
        let sources = [
            ArtifactSource::Amcache,
            ArtifactSource::ShimCache,
            ArtifactSource::Prefetch,
            ArtifactSource::DefenderQuarantine,
            ArtifactSource::DefenderLog { event_id: 1116 },
            ArtifactSource::ScheduledTask { file: "\\Windows\\System32\\Tasks\\T".into() },
            ArtifactSource::Registry { hive: "SYSTEM".into(), key: "Services\\x".into() },
        ];
        let mut observations: Vec<Observation> = sources
            .iter()
            .map(|s| {
                observation(
                    s.clone(),
                    ObservationKind::Executed { when: None, run_count: None },
                    "W:\\tools\\x.exe",
                )
            })
            .collect();
        observations.extend(sources.iter().map(|s| {
            observation(
                s.clone(),
                ObservationKind::Executed { when: None, run_count: None },
                "C:\\Windows\\System32\\x.exe",
            )
        }));

        let mut coverage = Coverage::default();
        withhold_other_volumes(&mut observations, &identity(), &mut coverage);

        assert_eq!(observations.len(), sources.len(), "the C: half is untouched");
        assert!(observations
            .iter()
            .all(|o| o.path.as_ref().is_some_and(|p| p.key() == "\\windows\\system32\\x.exe")));
        assert_eq!(coverage.other_volumes.len(), 1);
        assert_eq!(coverage.other_volumes[0].observations, sources.len());
    }

    #[test]
    fn a_hash_only_observation_survives() {
        let mut observations = vec![Observation {
            source: ArtifactSource::DefenderQuarantine,
            kind: ObservationKind::HashRecovered,
            path: None,
            hash: Default::default(),
        }];
        let mut coverage = Coverage::default();
        withhold_other_volumes(&mut observations, &identity(), &mut coverage);
        assert_eq!(observations.len(), 1);
        assert!(coverage.other_volumes.is_empty());
    }

    #[test]
    fn a_quarantine_entry_for_another_volume_says_where_the_bytes_are() {
        let mut observations = vec![observation(
            ArtifactSource::DefenderQuarantine,
            ObservationKind::Quarantined {
                product: "Microsoft Defender".into(),
                threat: Some("Trojan:Win32/Wacatac".into()),
                when: None,
                severity: None,
            },
            "W:\\$RECYCLE.BIN\\S-1-5-21-1\\aXbYcZ.exe",
        )];
        let mut coverage = Coverage::default();
        withhold_other_volumes(&mut observations, &identity(), &mut coverage);

        assert!(observations.is_empty(), "still not a candidate on this volume");
        let warning = coverage
            .warnings
            .iter()
            .find(|w| w.contains("quarantine"))
            .expect("the run must say the payload is here");
        assert!(warning.contains("ON THIS VOLUME"), "{warning}");
        assert!(warning.contains("aXbYcZ.exe"), "{warning}");
    }

    #[test]
    fn the_other_volume_carries_what_mounted_devices_said() {
        let mut observations = vec![observation(
            ArtifactSource::ShimCache,
            ObservationKind::Executed { when: None, run_count: None },
            "W:\\tools\\x.exe",
        )];
        let mut coverage = Coverage::default();
        withhold_other_volumes(&mut observations, &identity(), &mut coverage);
        assert_eq!(
            coverage.other_volumes[0].identified_as.as_deref(),
            Some("MBR disk signature 0x1a2b3c4d at offset 1048576")
        );
    }

    #[test]
    fn a_letter_with_no_mount_record_is_still_a_lead() {
        let mut observations = vec![observation(
            ArtifactSource::UserAssist,
            ObservationKind::Executed { when: None, run_count: None },
            "E:\\setup.exe",
        )];
        let mut coverage = Coverage::default();
        withhold_other_volumes(&mut observations, &identity(), &mut coverage);
        assert_eq!(coverage.other_volumes[0].volume, "E:");
        assert_eq!(coverage.other_volumes[0].identified_as, None);
    }

    #[test]
    fn a_hostile_artifact_set_cannot_grow_the_report_without_bound() {
        let mut observations: Vec<Observation> = (0..5_000)
            .map(|i| {
                observation(
                    ArtifactSource::ShimCache,
                    ObservationKind::Executed { when: None, run_count: None },
                    &format!("W:\\dir{i}\\x.exe"),
                )
            })
            .collect();
        let mut coverage = Coverage::default();
        withhold_other_volumes(&mut observations, &identity(), &mut coverage);

        assert!(observations.is_empty());
        let volume = &coverage.other_volumes[0];
        assert_eq!(volume.observations, 5_000, "the count is exact");
        assert_eq!(volume.paths.len(), 64, "the listing is not");
    }

    #[test]
    fn a_defender_detection_this_volume_cannot_account_for_is_named() {
        let mut observations = vec![observation(
            ArtifactSource::Mft,
            ObservationKind::FileExists {
                size: 1,
                created: None,
                modified: None,
                mft_modified: None,
                record: Some(9),
            },
            "C:\\Users\\bob\\Downloads\\known.exe",
        )];
        let deferred = vec![
            observation(
                ArtifactSource::DefenderLog { event_id: 1116 },
                ObservationKind::AvDetected {
                    product: "Windows Defender".into(),
                    threat: Some("Backdoor:MSIL/Bladabindi!atmn".into()),
                    when: None,
                    severity: None,
                },
                "C:\\Users\\bob\\Downloads\\known.exe",
            ),
            observation(
                ArtifactSource::DefenderLog { event_id: 1116 },
                ObservationKind::AvDetected {
                    product: "Windows Defender".into(),
                    threat: Some("Backdoor:MSIL/Bladabindi!atmn".into()),
                    when: None,
                    severity: None,
                },
                "C:\\Windows\\Temp\\server.exe",
            ),
        ];

        let mut coverage = Coverage::default();
        reattach_defender_log(&mut observations, deferred, &mut coverage);

        let warning = coverage
            .warnings
            .iter()
            .find(|w| w.contains("Defender detection"))
            .expect("the unmatched half is warned about");
        assert!(warning.contains("1 Defender detection"), "{warning}");
        assert!(
            warning.contains("server.exe"),
            "the analyst has to be able to see WHICH path: {warning}"
        );
        assert!(
            !warning.contains("known.exe"),
            "a detection that matched must not be listed as unmatched: {warning}"
        );
        assert_eq!(observations.len(), 2, "the matched detection rejoined");
    }

    #[test]
    fn the_named_detections_are_capped_and_the_count_is_not() {
        let mut observations: Vec<Observation> = Vec::new();
        let deferred: Vec<Observation> = (0..200)
            .map(|i| {
                observation(
                    ArtifactSource::DefenderLog { event_id: 1116 },
                    ObservationKind::AvDetected {
                        product: "Windows Defender".into(),
                        threat: None,
                        when: None,
                        severity: None,
                    },
                    &format!("C:\\gone\\p{i}.exe"),
                )
            })
            .collect();

        let mut coverage = Coverage::default();
        reattach_defender_log(&mut observations, deferred, &mut coverage);
        let warning =
            coverage.warnings.iter().find(|w| w.contains("Defender detection")).expect("warned");
        assert!(warning.contains("200 Defender detection"), "the count is exact: {warning}");
        assert!(
            warning.contains("...and 192 more"),
            "the listing is bounded and says by how much: {warning}"
        );
    }

    fn shaped(path_str: &str, kinds: Vec<ObservationKind>) -> Candidate {
        let mut c = Candidate::new(CandidateId(1), -7.8);
        c.path = NormalizedPath::parse(path_str);
        for kind in kinds {
            c.observe(Observation::about_path(
                ArtifactSource::ShimCache,
                NormalizedPath::parse(path_str).unwrap(),
                kind,
            ));
        }
        c
    }

    fn executed() -> ObservationKind {
        ObservationKind::Executed { when: None, run_count: None }
    }

    fn deleted_with_record() -> ObservationKind {
        ObservationKind::FileDeleted { when: None, record: Some(4242), sequence: None }
    }

    fn exists() -> ObservationKind {
        ObservationKind::FileExists {
            size: 1,
            created: None,
            modified: None,
            mft_modified: None,
            record: Some(7),
        }
    }

    fn unranked(candidate: &Candidate) -> bool {
        matches_an_unranked_rule(candidate, &crate::index_slack::RecoveredNames::default())
    }

    #[test]
    fn a_deleted_executable_with_a_record_is_acquired_whatever_it_scored() {
        assert!(unranked(&shaped(
            "C:\\Program Files\\Vendor\\old.exe",
            vec![deleted_with_record()]
        )));
        assert!(!unranked(&shaped(
            "C:\\Program Files\\Vendor\\install.log",
            vec![deleted_with_record()]
        )));
        assert!(!unranked(&shaped(
            "C:\\Program Files\\Vendor\\old.exe",
            vec![ObservationKind::FileDeleted { when: None, record: None, sequence: None }]
        )));
    }

    #[test]
    fn an_executed_executable_absent_from_a_scratch_root_is_acquired() {
        assert!(unranked(&shaped("C:\\Windows\\Temp\\server.exe", vec![executed()])));
        assert!(unranked(&shaped("C:\\setup.exe", vec![executed()])));

        assert!(!unranked(&shaped(
            "C:\\Windows\\Temp\\{54106D84}\\.be\\VC_redist.x64.exe",
            vec![executed()]
        )));
        assert!(!unranked(&shaped("C:\\Program Files\\Vendor\\update.exe", vec![executed()])));
        assert!(!unranked(&shaped("C:\\Windows\\Temp\\server.exe", vec![executed(), exists()])));
        assert!(!unranked(&shaped("C:\\Windows\\Temp\\server.exe", vec![])));
        let mut bare = Candidate::new(CandidateId(1), -7.8);
        bare.path = NormalizedPath::parse("explorer.exe");
        bare.observe(Observation::about_path(
            ArtifactSource::ShimCache,
            NormalizedPath::parse("explorer.exe").unwrap(),
            executed(),
        ));
        assert!(!bare.path.as_ref().unwrap().is_located());
        assert!(!unranked(&bare));
    }
}
