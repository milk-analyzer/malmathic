use chrono::{DateTime, Duration, Utc};
use mm_core::{
    ArtifactSource, Candidate, Evidence, NormalizedPath, ObservationKind, OutOfBandArrival,
    PersistenceKind, SignatureStatus, UrlZone,
};

use crate::baseline::Baseline;
use crate::weights::{feature, EvidenceSet, Weights};
use crate::window::IncidentWindow;
use crate::zone::{classify, is_immediately_in_a_scratch_root, Zone};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SystemBinaryHome {
    SystemDirectories,
    SystemDirectoriesOrWindowsRoot,
}

impl SystemBinaryHome {
    fn accepts(self, path: &NormalizedPath, zone: Zone) -> bool {
        if matches!(zone, Zone::SystemDir | Zone::WinSxs) {
            return true;
        }
        self == SystemBinaryHome::SystemDirectoriesOrWindowsRoot
            && path.parent() == Some(WINDOWS_DIRECTORY)
    }
}

const WINDOWS_DIRECTORY: &str = "\\windows";

const SYSTEM_BINARIES: &[(&str, SystemBinaryHome)] = &[
    ("svchost.exe", SystemBinaryHome::SystemDirectories),
    ("lsass.exe", SystemBinaryHome::SystemDirectories),
    ("services.exe", SystemBinaryHome::SystemDirectories),
    ("csrss.exe", SystemBinaryHome::SystemDirectories),
    ("winlogon.exe", SystemBinaryHome::SystemDirectories),
    ("smss.exe", SystemBinaryHome::SystemDirectories),
    ("explorer.exe", SystemBinaryHome::SystemDirectoriesOrWindowsRoot),
    ("spoolsv.exe", SystemBinaryHome::SystemDirectories),
    ("taskhost.exe", SystemBinaryHome::SystemDirectories),
    ("taskhostw.exe", SystemBinaryHome::SystemDirectories),
    ("dwm.exe", SystemBinaryHome::SystemDirectories),
    ("conhost.exe", SystemBinaryHome::SystemDirectories),
    ("rundll32.exe", SystemBinaryHome::SystemDirectories),
    ("regsvr32.exe", SystemBinaryHome::SystemDirectories),
    ("wininit.exe", SystemBinaryHome::SystemDirectories),
    ("userinit.exe", SystemBinaryHome::SystemDirectories),
    ("ctfmon.exe", SystemBinaryHome::SystemDirectories),
    ("dllhost.exe", SystemBinaryHome::SystemDirectories),
    ("sihost.exe", SystemBinaryHome::SystemDirectories),
    ("runtimebroker.exe", SystemBinaryHome::SystemDirectories),
];

fn system_binary_home(file_name: &str) -> Option<SystemBinaryHome> {
    SYSTEM_BINARIES.iter().find(|(name, _)| *name == file_name).map(|(_, home)| *home)
}

const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp4",
    "zip", "rar",
];

const SELF_DELETE_WINDOW: Duration = Duration::minutes(10);

const TIMESTOMP_TECHNIQUE: &str = "T1070.006";

const PACKING_TECHNIQUE: &str = "T1027.002";

const RARE_ZONE_THRESHOLD: u64 = 5;

const LONE_EXECUTABLE_MIN_SIBLINGS: u32 = 10;

const COMPACT_OS_RARE_MAX: u64 = 5;

const COMPACT_OS_NORMAL_SHARE: f64 = 0.01;

const COMPACT_OS_FAILURE_MARKER: &str = "Compact-OS";

#[must_use]
pub fn compact_os_failure_is_recognised(reason: &str) -> bool {
    reason.contains(COMPACT_OS_FAILURE_MARKER)
}

pub fn extract(candidate: &Candidate, baseline: &Baseline, weights: &Weights) -> Vec<Evidence> {
    extract_with_window(candidate, baseline, weights, None)
}

pub fn extract_with_window(
    candidate: &Candidate,
    baseline: &Baseline,
    weights: &Weights,
    window: Option<&IncidentWindow>,
) -> Vec<Evidence> {
    let mut set = EvidenceSet::new();

    from_observations(candidate, weights, &mut set);
    if let Some(path) = &candidate.path {
        from_path(path, weights, &mut set);
        if baseline.is_usable() {
            let counted_in_census = candidate.observations.iter().any(|o| {
                matches!(o.source, ArtifactSource::Mft)
                    && matches!(
                        o.kind,
                        ObservationKind::FileExists { .. } | ObservationKind::FileDeleted { .. }
                    )
            });
            from_baseline(path, counted_in_census, baseline, weights, &mut set);
            from_compact_os(candidate, path, baseline, weights, &mut set);
        }
    }
    from_lifecycle(candidate, weights, baseline.volume_enumerated(), &mut set);
    if let Some(window) = window {
        from_incident_window(candidate, window, weights, &mut set);
    }

    set.into_evidence()
}

fn at(when: &Option<chrono::DateTime<chrono::Utc>>) -> String {
    match when {
        Some(t) => format!(" on {}", mm_core::filetime::format(*t)),
        None => String::new(),
    }
}

fn rated(severity: &Option<u32>) -> String {
    match severity {
        Some(1) => " (Defender severity: low)".to_string(),
        Some(2) => " (Defender severity: moderate)".to_string(),
        Some(4) => " (Defender severity: high)".to_string(),
        Some(5) => " (Defender severity: severe)".to_string(),
        Some(other) => format!(" (Defender severity id {other}, which this build does not name)"),
        None => String::new(),
    }
}

fn is_managed_assembly(candidate: &Candidate) -> bool {
    candidate.observations.iter().any(|o| matches!(o.kind, ObservationKind::ManagedAssembly))
}

fn is_autostart_target(candidate: &Candidate) -> bool {
    candidate.observations.iter().any(|o| {
        matches!(
            o.kind,
            ObservationKind::Persistence { kind, .. } if kind != PersistenceKind::ComServer
        )
    })
}

fn version_resource_is_expected_of_an_autostart_target(zone: Option<Zone>) -> bool {
    matches!(
        zone,
        Some(
            Zone::WindowsOther
                | Zone::WindowsTemp
                | Zone::ProgramFiles
                | Zone::ProgramData
                | Zone::UserTemp
                | Zone::UserAppData
                | Zone::UserDownloads
                | Zone::UserProfile
                | Zone::VolumeRoot
        )
    )
}

fn offer_no_trusted_signature(
    set: &mut EvidenceSet,
    weights: &Weights,
    candidate: &Candidate,
    managed: bool,
    source: Vec<ArtifactSource>,
    untrusted_signer: Option<&str>,
) {
    let zone = candidate.path.as_ref().map(classify);
    let conventional = zone.is_some_and(|z| z.is_conventional_for_executables());
    let native_row = if zone == Some(Zone::ProgramFiles) {
        feature::UNSIGNED_IN_PROGRAM_FILES
    } else {
        feature::UNSIGNED_IN_SYSTEM_ZONE
    };
    let unrecognised_ca = "the signature verifies, but its chain ends at a certificate authority \
                           this build does not carry — THIS BUILD DOES NOT HAVE THAT ROOT, which \
                           is not itself a finding about the file";
    let (row, detail) = if managed && conventional {
        (
            feature::UNSIGNED_MANAGED_ASSEMBLY,
            match untrusted_signer {
                None => "unsigned — but a managed .NET assembly, which is normally strong-named \
                         rather than Authenticode-signed"
                    .to_string(),
                Some(signer) => format!(
                    "no trusted signature: {signer} signed it and {unrecognised_ca}; and this is \
                     a managed .NET assembly, which is normally strong-named rather than \
                     Authenticode-signed"
                ),
            },
        )
    } else if conventional {
        let here = if native_row == feature::UNSIGNED_IN_PROGRAM_FILES {
            "a directory where most software is signed"
        } else {
            "a directory where essentially everything is signed"
        };
        (
            native_row,
            match untrusted_signer {
                None => format!("unsigned, in {here}"),
                Some(signer) => format!(
                    "no trusted signature, in {here}: {signer} signed it and {unrecognised_ca}"
                ),
            },
        )
    } else {
        (
            feature::UNSIGNED_IN_USER_ZONE,
            match untrusted_signer {
                None => "unsigned".to_string(),
                Some(signer) => {
                    format!("no trusted signature: {signer} signed it and {unrecognised_ca}")
                }
            },
        )
    };
    set.offer(weights, row, detail, source);
}

fn from_observations(candidate: &Candidate, weights: &Weights, set: &mut EvidenceSet) {
    let managed = is_managed_assembly(candidate);
    for observation in &candidate.observations {
        let source = vec![observation.source.clone()];
        match &observation.kind {
            ObservationKind::Quarantined { product, threat, when, severity } => {
                let named = threat.as_deref().unwrap_or("an unnamed threat");
                set.offer(
                    weights,
                    feature::QUARANTINED_BY_AV,
                    format!(
                        "{product} quarantined this file as {named}{}{}",
                        at(when),
                        rated(severity)
                    ),
                    source,
                );
            }

            ObservationKind::AvDetected { product, threat, when, severity } => {
                let named = threat.as_deref().unwrap_or("an unnamed threat");
                set.offer(
                    weights,
                    feature::AV_DETECTION_LOGGED,
                    format!(
                        "{product} logged a detection of {named}{}{} against this file \
                         and is not recorded as having removed it",
                        at(when),
                        rated(severity)
                    ),
                    source,
                );
            }

            ObservationKind::Signature(status) => match status {
                SignatureStatus::CatalogValid { signer, catalog, root_is_microsoft } => {
                    if *root_is_microsoft {
                        set.offer(
                            weights,
                            feature::SIGNED_MICROSOFT_CATALOG,
                            format!("catalog-signed by {signer} ({catalog}), chaining to a Microsoft root"),
                            source,
                        )
                    } else {
                        set.offer(
                            weights,
                            feature::SIGNED_TRUSTED_PUBLISHER,
                            format!(
                                "catalog-signed by {signer} ({catalog}) — a third-party catalog, \
                                 not one of Microsoft's"
                            ),
                            source,
                        )
                    }
                }
                SignatureStatus::EmbeddedValid { signer } => set.offer(
                    weights,
                    feature::SIGNED_TRUSTED_PUBLISHER,
                    format!("validly signed by {signer}"),
                    source,
                ),
                SignatureStatus::Invalid { reason } => set.offer(
                    weights,
                    feature::SIGNATURE_INVALID,
                    format!("signature present but does not verify: {reason}"),
                    source,
                ),
                SignatureStatus::Untrusted { signer, self_signed_leaf } => {
                    if *self_signed_leaf {
                        set.offer(
                            weights,
                            feature::SIGNATURE_SELF_SIGNED,
                            format!(
                                "self-signed: {signer} issued its own signing certificate, so                                  nothing outside the file vouches for it — this is a finding                                  about the file, not about our trust store"
                            ),
                            source.clone(),
                        );
                    }
                    offer_no_trusted_signature(
                        set,
                        weights,
                        candidate,
                        managed,
                        source,
                        Some(signer.as_str()),
                    );
                }
                SignatureStatus::Expired { signer } => set.offer(
                    weights,
                    feature::SIGNATURE_EXPIRED,
                    format!(
                        "signed by {signer}, but nothing establishes the certificate was valid \
                         when it signed — no trusted countersignature"
                    ),
                    source,
                ),
                SignatureStatus::Unknown { reason } => set.offer(
                    weights,
                    feature::SIGNATURE_UNVERIFIABLE,
                    format!("signature could not be checked: {reason}"),
                    source,
                ),
                SignatureStatus::Unsigned => {
                    offer_no_trusted_signature(set, weights, candidate, managed, source, None)
                }
            },

            ObservationKind::Persistence { kind, raw_value } => {
                let deleted = raw_value.starts_with("[deleted]");
                if deleted {
                    set.offer(
                        weights,
                        feature::PERSISTENCE_DELETED_ENTRY,
                        format!(
                            "a {} entry for this file was recovered from deleted registry cells ({})",
                            kind.label(),
                            kind.attack_id()
                        ),
                        source.clone(),
                    );
                }
                let (name, described) = persistence_feature(*kind);
                set.offer(
                    weights,
                    name,
                    format!("{described} ({}): {}", kind.attack_id(), truncate(raw_value, 120)),
                    source.clone(),
                );

                if let Some(target) = &observation.path {
                    let target_zone = classify(target);
                    if let Some((name, described)) = persistence_target_feature(*kind, target_zone)
                    {
                        set.offer(
                            weights,
                            name,
                            format!(
                                "the {} that starts this file points into the {} — {described}",
                                kind.label(),
                                target_zone.label()
                            ),
                            source,
                        );
                    }
                }
            }

            ObservationKind::YaraMatch { rule, namespace } => set.offer(
                weights,
                feature::YARA_MATCH,
                format!("matched YARA rule {namespace}:{rule}"),
                source,
            ),

            ObservationKind::RichHeaderChecksumInvalid { entries, decoded } => set.offer(
                weights,
                feature::RICH_HEADER_CHECKSUM_INVALID,
                if *decoded {
                    format!(
                        "the Rich header's key does not match the checksum of the bytes above \
                         it — the linker computes one from the other, so the two disagree only \
                         if the header was copied here from another binary or the stub was \
                         edited under it ({entries} toolchain entries) (T1036)"
                    )
                } else {
                    "a Rich marker sits above the PE header but the block before it does not \
                     decode under the key stored beside it — no linker writes that; the key \
                     was overwritten or the block was planted (T1036)"
                        .to_string()
                },
                source,
            ),

            ObservationKind::PeAnomaly { detail } => {
                if detail.contains(TIMESTOMP_TECHNIQUE) {
                    set.offer(weights, feature::TIMESTOMPED, detail.clone(), source);
                } else if detail.contains(PACKING_TECHNIQUE) {
                    set.offer(weights, feature::HIGH_ENTROPY_CODE_SECTION, detail.clone(), source);
                } else {
                    set.offer(
                        weights,
                        feature::PE_STRUCTURAL_ANOMALY,
                        format!("malformed PE: {detail}"),
                        source,
                    );
                }
            }

            ObservationKind::DownloadedFrom { zone, host_url, referrer_url } => {
                let origin = describe_origin(host_url.as_deref(), referrer_url.as_deref());
                let (name, claim) = match zone {
                    UrlZone::Untrusted => (
                        feature::DOWNLOADED_FROM_RESTRICTED_ZONE,
                        "marked as downloaded from the restricted-sites zone".to_string(),
                    ),
                    UrlZone::Internet => (
                        feature::DOWNLOADED_FROM_INTERNET_ZONE,
                        "marked as downloaded from the internet".to_string(),
                    ),
                    other => (
                        feature::DOWNLOAD_ORIGIN_RECORDED,
                        format!("carries a Mark of the Web claiming the {} zone", other.label()),
                    ),
                };
                set.offer(weights, name, format!("{claim}{origin}"), source);
            }

            ObservationKind::UnbackedExecutableMemory { pid, size } => set.offer(
                weights,
                feature::UNBACKED_EXECUTABLE_MEMORY,
                format!(
                    "process {pid} holds {size} bytes of executable memory with no file behind it"
                ),
                source,
            ),

            ObservationKind::ProcessRunning { pid, .. } => {
                let in_user_zone = candidate
                    .path
                    .as_ref()
                    .map(|p| !classify(p).is_conventional_for_executables())
                    .unwrap_or(false);
                if in_user_zone {
                    set.offer(
                        weights,
                        feature::RUNNING_FROM_USER_DIRECTORY,
                        format!("running right now as process {pid}"),
                        source,
                    );
                }
            }

            ObservationKind::FileExists { .. } => {}
            ObservationKind::DeletedRegistryValue { .. } => {}

            ObservationKind::CompactOsCompressed { .. } => {}

            ObservationKind::ArrivedOutOfBand(arrival) => match arrival {
                OutOfBandArrival::NotAComponentStoreLink { hard_links } => set.offer(
                    weights,
                    feature::INSTALLED_OUTSIDE_COMPONENT_STORE,
                    format!(
                        "sits in the system directory but has {hard_links} hard link — it is \
                         not a projection of a component-store file, so Windows servicing \
                         did not put it there"
                    ),
                    source,
                ),
                OutOfBandArrival::AfterItsDirectory { days_later } => set.offer(
                    weights,
                    feature::ARRIVED_AFTER_ITS_DIRECTORY,
                    format!(
                        "created {days_later} days after the directory holding it — it did \
                         not arrive with the application around it"
                    ),
                    source,
                ),
            },

            ObservationKind::NoVersionResource => {
                let zone = candidate.path.as_ref().map(classify);
                if matches!(zone, Some(Zone::SystemDir) | Some(Zone::WinSxs)) {
                    set.offer(
                        weights,
                        feature::NO_VERSION_RESOURCE,
                        "carries no version resource — no company, no product, no version — \
                         which is unusual for a binary in a directory Windows services"
                            .to_string(),
                        source,
                    );
                } else if version_resource_is_expected_of_an_autostart_target(zone)
                    && is_autostart_target(candidate)
                {
                    set.offer(
                        weights,
                        feature::AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE,
                        "the machine is wired to start this file by itself, and the file \
                         carries no version resource — no company, no product, no version"
                            .to_string(),
                        source,
                    );
                }
            }

            ObservationKind::SharedDigestElsewhere { path, algorithm, copies } => {
                let Some(mine) = candidate.path.as_ref() else { continue };
                let renamed = match (mine.file_name(), path.file_name()) {
                    (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b),
                    _ => false,
                };
                if renamed && classify(mine) != classify(path) && path.is_located() {
                    let also = if *copies > 1 {
                        format!(" (and {} other path(s) on this volume)", copies - 1)
                    } else {
                        String::new()
                    };
                    set.offer(
                        weights,
                        feature::SHARED_DIGEST_RENAMED_COPY,
                        format!(
                            "identical {algorithm}: these exact bytes are also on this volume \
                             at {}, under a different name and in a different part of the \
                             filesystem{also} — one file, written twice",
                            path.raw()
                        ),
                        source,
                    );
                }
            }

            ObservationKind::Executed { .. }
            | ObservationKind::FileDeleted { .. }
            | ObservationKind::ManagedAssembly
            | ObservationKind::HashRecovered => {}
        }
    }
}

fn persistence_feature(kind: PersistenceKind) -> (&'static str, &'static str) {
    match kind {
        PersistenceKind::ImageFileExecutionOptions => {
            (feature::PERSISTENCE_IFEO, "registered as an IFEO debugger")
        }
        PersistenceKind::ComServer => {
            (feature::PERSISTENCE_COM_SERVER, "registered as a COM server")
        }
        PersistenceKind::ComHijack => (
            feature::PERSISTENCE_COM_HIJACK,
            "redirects an existing COM class away from its machine-wide server",
        ),
        PersistenceKind::WinlogonShell | PersistenceKind::WinlogonUserinit => {
            (feature::PERSISTENCE_WINLOGON, "wired into Winlogon startup")
        }
        PersistenceKind::ScheduledTask => {
            (feature::PERSISTENCE_SCHEDULED_TASK, "launched by a scheduled task")
        }
        PersistenceKind::Service => (feature::PERSISTENCE_SERVICE, "installed as a service"),
        PersistenceKind::StartupFolder => {
            (feature::PERSISTENCE_RUN_KEY, "started at logon from a Startup folder")
        }
        _ => (feature::PERSISTENCE_RUN_KEY, "set to start automatically"),
    }
}

fn persistence_target_feature(
    kind: PersistenceKind,
    zone: Zone,
) -> Option<(&'static str, &'static str)> {
    if matches!(kind, PersistenceKind::ComServer | PersistenceKind::ComHijack) {
        return None;
    }
    match zone {
        Zone::UserAppData | Zone::UserDownloads | Zone::UserProfile => Some((
            feature::PERSISTENCE_TARGETS_USER_PROFILE,
            "a directory the user can write to without being an administrator",
        )),
        Zone::UserTemp | Zone::WindowsTemp | Zone::VolumeRoot | Zone::RecycleBin => Some((
            feature::PERSISTENCE_TARGETS_SCRATCH_SPACE,
            "scratch space, where nothing is installed and nothing is meant to persist",
        )),
        Zone::SystemDir
        | Zone::WindowsOther
        | Zone::WinSxs
        | Zone::ProgramFiles
        | Zone::ProgramData
        | Zone::Other
        | Zone::Unlocated => None,
    }
}

fn from_path(path: &NormalizedPath, weights: &Weights, set: &mut EvidenceSet) {
    let zone = classify(path);

    if path.is_executable_extension() {
        let location = match zone {
            Zone::UserTemp => Some((
                feature::EXECUTABLE_IN_USER_TEMP,
                "an executable in the user's temp directory",
            )),
            Zone::VolumeRoot => {
                Some((feature::EXECUTABLE_AT_VOLUME_ROOT, "an executable at the volume root"))
            }
            Zone::RecycleBin => {
                Some((feature::EXECUTABLE_IN_RECYCLE_BIN, "an executable inside the recycle bin"))
            }
            Zone::WindowsTemp => Some((
                feature::EXECUTABLE_IN_WINDOWS_TEMP,
                "an executable in the Windows temp directory",
            )),
            Zone::UserAppData => Some((
                feature::EXECUTABLE_IN_USER_APPDATA,
                "an executable under the user's AppData",
            )),
            Zone::UserDownloads => Some((
                feature::EXECUTABLE_IN_USER_DOWNLOADS,
                "an executable in the user's Downloads",
            )),
            Zone::ProgramData => {
                Some((feature::EXECUTABLE_IN_PROGRAMDATA, "an executable under ProgramData"))
            }
            Zone::UserProfile => {
                Some((feature::EXECUTABLE_IN_USER_PROFILE, "an executable in the user's profile"))
            }
            Zone::WindowsOther => Some((
                feature::EXECUTABLE_IN_WINDOWS_DIRECTORY,
                "an executable under \\Windows outside the system directories",
            )),
            Zone::Other => Some((
                feature::EXECUTABLE_OUTSIDE_STANDARD_ZONES,
                "an executable outside every standard Windows location",
            )),
            Zone::SystemDir | Zone::WinSxs | Zone::ProgramFiles | Zone::Unlocated => None,
        };
        if let Some((name, described)) = location {
            set.offer(weights, name, format!("{described} ({})", zone.label()), vec![]);
        }
    }

    let Some(file_name) = path.file_name() else { return };

    if let Some(home) = system_binary_home(file_name) {
        if path.is_located() && !home.accepts(path, zone) {
            set.offer(
                weights,
                feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR,
                format!(
                    "named `{file_name}` — a Windows system binary — but located in the {}, \
                     not where Windows keeps it",
                    zone.label()
                ),
                vec![],
            );
        }
    }

    if let Some(decoy) = double_extension(file_name) {
        set.offer(
            weights,
            feature::DOUBLE_EXTENSION,
            format!("`{file_name}` is built to read as a .{decoy} file"),
            vec![],
        );
    }

    if looks_machine_generated(file_name) {
        set.offer(
            weights,
            feature::RANDOM_LOOKING_NAME,
            format!("`{file_name}` looks machine-generated rather than chosen"),
            vec![],
        );
    }
}

fn from_baseline(
    path: &NormalizedPath,
    counted_in_census: bool,
    baseline: &Baseline,
    weights: &Weights,
    set: &mut EvidenceSet,
) {
    let zone = classify(path);

    if baseline.is_lone_executable(path, LONE_EXECUTABLE_MIN_SIBLINGS) {
        if let Some(parent) = path.parent() {
            let stats = baseline.directory(parent).unwrap_or_default();
            set.offer(
                weights,
                feature::LONE_EXECUTABLE_AMONG_DOCUMENTS,
                format!("the only executable among {} files in {parent}", stats.files),
                vec![],
            );
        }
    }

    if path.is_executable_extension() {
        let count = baseline.zone_rarity(zone);
        if zone != Zone::Unlocated
            && count > 0
            && count <= RARE_ZONE_THRESHOLD
            && !zone.is_conventional_for_executables()
        {
            set.offer(
                weights,
                feature::EXECUTABLE_RARE_FOR_ZONE,
                format!(
                    "one of only {count} executable(s) anywhere in the {} on this machine",
                    zone.label()
                ),
                vec![],
            );
        }
    }

    if let Some(name) = path.file_name() {
        let impersonating_a_system_binary = system_binary_home(name)
            .is_some_and(|home| path.is_located() && !home.accepts(path, zone));

        let occurrences = baseline.name_occurrences(name);
        let others = occurrences.saturating_sub(u32::from(counted_in_census));
        match occurrences {
            0 | 1 if others == 0 => set.offer(
                weights,
                feature::NAME_UNIQUE_ON_MACHINE,
                format!("no other file on this machine is named `{name}`"),
                vec![],
            ),
            n if n >= 3 => {
                let own = u32::from(zone.is_conventional_for_executables());
                let vouching = baseline.name_occurrences_in_conventional_zones(name);
                if impersonating_a_system_binary {
                    let elsewhere = vouching.saturating_sub(own);
                    if elsewhere > 0 {
                        set.offer(
                            weights,
                            feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR,
                            format!(
                                "of the {n} files named `{name}` on this machine, {elsewhere} sit \
                                 where Windows ships executables — the genuine binary and its \
                                 component-store copies, and this file is not one of them"
                            ),
                            vec![],
                        );
                    }
                } else if vouching > own {
                    set.offer(
                        weights,
                        feature::NAME_RECURS_ON_MACHINE,
                        format!(
                            "`{name}` appears {n} times on this machine, {vouching} of them \
                             where Windows and installers ship executables — the \
                             pattern of a real system file"
                        ),
                        vec![],
                    );
                }
            }
            _ => {}
        }
    }
}

fn from_compact_os(
    candidate: &Candidate,
    path: &NormalizedPath,
    baseline: &Baseline,
    weights: &Weights,
    set: &mut EvidenceSet,
) {
    if !path.is_executable_extension() {
        return;
    }
    let Some((algorithm, readable)) = candidate.observations.iter().find_map(|o| match &o.kind {
        ObservationKind::CompactOsCompressed { algorithm, readable } => {
            Some((algorithm.as_str(), *readable))
        }
        _ => None,
    }) else {
        return;
    };

    let compact_os_blocked_the_check = !readable
        || candidate.observations.iter().any(|o| match &o.kind {
            ObservationKind::Signature(SignatureStatus::Unknown { reason }) => {
                compact_os_failure_is_recognised(reason)
            }
            _ => false,
        });
    if !compact_os_blocked_the_check {
        return;
    }

    let compressed = baseline.compact_os_executables();
    let share = baseline.compact_os_share_of_executables().unwrap_or(0.0);
    if compressed == 0 || compressed > COMPACT_OS_RARE_MAX || share > COMPACT_OS_NORMAL_SHARE {
        return;
    }

    if baseline.is_lone_compact_os_file(path) != Some(true) {
        return;
    }

    let of_which = if compressed == 1 {
        "the only Compact-OS-compressed executable on this volume".to_string()
    } else {
        format!("one of only {compressed} Compact-OS-compressed executables on this volume")
    };
    let consequence = if readable {
        String::new()
    } else {
        " — its bytes cannot be produced by this build, so nothing \
         downstream could check what it is"
            .to_string()
    };
    set.offer(
        weights,
        feature::COMPACT_OS_COMPRESSED_EXECUTABLE,
        format!("stored Compact-OS ({algorithm}) compressed, {of_which}{consequence}"),
        vec![],
    );
}

fn from_lifecycle(
    candidate: &Candidate,
    weights: &Weights,
    volume_was_walked: bool,
    set: &mut EvidenceSet,
) {
    let mut observed_execution: Option<DateTime<Utc>> = None;
    let mut inferred_execution: Option<DateTime<Utc>> = None;
    let mut first_deletion: Option<DateTime<Utc>> = None;
    let mut executed = false;
    let mut exists = false;

    for observation in &candidate.observations {
        match &observation.kind {
            ObservationKind::Executed { when, .. } => {
                executed = true;
                let Some(t) = when else { continue };
                let slot = if observation.source == ArtifactSource::ShimCache {
                    &mut inferred_execution
                } else {
                    &mut observed_execution
                };
                *slot = Some(slot.map_or(*t, |e: DateTime<Utc>| e.max(*t)));
            }
            ObservationKind::FileDeleted { when: Some(t), .. } => {
                if observation.source != ArtifactSource::RecycleBin {
                    first_deletion = Some(first_deletion.map_or(*t, |e: DateTime<Utc>| e.min(*t)));
                }
            }
            ObservationKind::FileExists { .. } => exists = true,
            _ => {}
        }
    }

    let last_execution = observed_execution.or(inferred_execution);

    if let (Some(ran), Some(deleted)) = (last_execution, first_deletion) {
        let gap = deleted - ran;
        if gap >= Duration::zero() && gap <= SELF_DELETE_WINDOW {
            set.offer(
                weights,
                feature::DELETED_SOON_AFTER_EXECUTION,
                format!(
                    "ran at {} and was deleted {} seconds later — the signature of a self-deleting dropper",
                    mm_core::filetime::format(ran),
                    gap.num_seconds()
                ),
                vec![],
            );
            return;
        }
    }

    let located = candidate.path.as_ref().is_some_and(|p| p.is_located());
    if executed && !exists && located && volume_was_walked {
        let scratch = candidate.path.as_ref().is_some_and(|p| {
            matches!(classify(p), Zone::WindowsTemp) && !is_immediately_in_a_scratch_root(p)
        });
        if scratch {
            set.offer(
                weights,
                feature::ABSENT_FROM_SCRATCH_SPACE,
                "execution artifacts record this file running, but it is no longer on disk — \
                 in a scratch SUBDIRECTORY, where an installer unpacking and then deleting \
                 its own working directory is ordinary",
                vec![],
            );
        } else {
            set.offer(
                weights,
                feature::EXECUTED_BUT_NOW_ABSENT,
                "execution artifacts record this file running, but it is no longer on disk",
                vec![],
            );
        }
    }
}

fn from_incident_window(
    candidate: &Candidate,
    window: &IncidentWindow,
    weights: &Weights,
    set: &mut EvidenceSet,
) {
    let Some(created) = window.membership(candidate) else { return };
    set.offer(
        weights,
        feature::CREATED_IN_INCIDENT_WINDOW,
        format!(
            "created at {}, inside the burst of activity the strongest evidence on this \
             machine sits in — {} — and one of {} candidate{} created in it",
            mm_core::filetime::format(created),
            window.summarise(),
            window.members(),
            if window.members() == 1 { "" } else { "s" },
        ),
        vec![],
    );
}

const URL_IN_EXPLANATION: usize = 60;

fn describe_origin(host: Option<&str>, referrer: Option<&str>) -> String {
    let short = |u: &str| truncate(u, URL_IN_EXPLANATION);
    match (host, referrer) {
        (Some(h), Some(r)) if r != h => {
            format!(": {} (linked from {})", short(h), short(r))
        }
        (Some(h), _) => format!(": {}", short(h)),
        (None, Some(r)) => format!(", linked from {}", short(r)),
        (None, None) => String::new(),
    }
}

fn double_extension(file_name: &str) -> Option<&str> {
    let parts: Vec<&str> = file_name.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let real = parts.last()?;
    let decoy = parts.get(parts.len() - 2)?;
    let is_executable =
        matches!(*real, "exe" | "scr" | "com" | "pif" | "bat" | "cmd" | "js" | "vbs" | "hta");
    if is_executable && DECOY_EXTENSIONS.contains(decoy) {
        Some(decoy)
    } else {
        None
    }
}

fn looks_machine_generated(file_name: &str) -> bool {
    let stem = file_name.split('.').next().unwrap_or(file_name);
    if stem.len() < 10 {
        return false;
    }
    if stem.contains(['-', '_', ' ']) {
        return false;
    }
    let letters: Vec<char> = stem.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if letters.len() < 6 {
        return stem.len() >= 10;
    }

    let vowels = letters.iter().filter(|c| "aeiou".contains(**c)).count();
    let vowel_ratio = vowels as f64 / letters.len() as f64;

    vowel_ratio < 0.16 || all_hex(stem)
}

fn all_hex(s: &str) -> bool {
    s.len() >= 8 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mm_core::{ArtifactSource, Candidate, CandidateId, FileHash, Observation};

    use crate::baseline::BaselineBuilder;
    use crate::machine;

    const PRIOR: f64 = -9.2;

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).unwrap()
    }

    fn candidate_at(p: &str) -> Candidate {
        let mut c = Candidate::new(CandidateId(0), PRIOR);
        c.path = Some(path(p));
        c
    }

    fn documents_baseline() -> Baseline {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
        }
        for i in 0..40 {
            b.observe(&path(&format!("C:\\Users\\bob\\Documents\\report{i}.docx")));
        }
        b.observe(&path("C:\\Users\\bob\\Documents\\invoice.exe"));
        b.build()
    }

    fn score(c: &Candidate, b: &Baseline) -> Vec<Evidence> {
        extract(c, b, &Weights::embedded())
    }

    fn group_total(e: &[Evidence], group: &str) -> f64 {
        let w = Weights::embedded();
        e.iter()
            .filter(|x| w.get(&x.feature).map(|g| g.group.as_str()) == Some(group))
            .map(|x| x.log_lr)
            .sum()
    }

    fn fired(evidence: &[Evidence], name: &str) -> bool {
        evidence.iter().any(|e| e.feature == name)
    }

    fn walked_volume() -> Baseline {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
        }
        b.build()
    }

    fn vanished_from(p: &str) -> Candidate {
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(p),
            ObservationKind::Executed { when: None, run_count: Some(1) },
        ));
        c
    }

    fn ran_and_vanished(p: &str) -> Vec<Evidence> {
        score(&vanished_from(p), &walked_volume())
    }

    #[test]
    fn absence_is_unknown_when_the_volume_was_never_walked() {
        for p in [
            "C:\\Program Files\\Vendor\\app.exe",
            "C:\\Windows\\Temp\\setup.exe",
            "C:\\Users\\bob\\AppData\\Roaming\\svcupdate.exe",
        ] {
            let unwalked = score(&vanished_from(p), &Baseline::default());
            assert!(!fired(&unwalked, feature::EXECUTED_BUT_NOW_ABSENT), "{p}");
            assert!(!fired(&unwalked, feature::ABSENT_FROM_SCRATCH_SPACE), "{p}");

            let walked = score(&vanished_from(p), &walked_volume());
            assert!(
                fired(&walked, feature::EXECUTED_BUT_NOW_ABSENT)
                    || fired(&walked, feature::ABSENT_FROM_SCRATCH_SPACE),
                "{p} lost its absence row entirely"
            );
        }
    }

    #[test]
    fn absence_in_a_scratch_directory_is_priced_below_absence_anywhere_else() {
        for scratch in [
            "C:\\Windows\\Temp\\{54106D84}\\.be\\VC_redist.x64.exe",
            "C:\\Windows\\SystemTemp\\unpack\\installer.exe",
        ] {
            let e = ran_and_vanished(scratch);
            assert!(fired(&e, feature::ABSENT_FROM_SCRATCH_SPACE), "{scratch}");
            assert!(!fired(&e, feature::EXECUTED_BUT_NOW_ABSENT), "{scratch} took both rows");
        }

        for elsewhere in [
            "C:\\Program Files\\Vendor\\app.exe",
            "C:\\Users\\bob\\AppData\\Roaming\\svcupdate.exe",
            "C:\\ProgramData\\Vendor\\app.exe",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\setup.exe",
            "C:\\Windows\\Temp\\server.exe",
            "C:\\Windows\\SystemTemp\\server.exe",
        ] {
            let e = ran_and_vanished(elsewhere);
            assert!(fired(&e, feature::EXECUTED_BUT_NOW_ABSENT), "{elsewhere}");
            assert!(!fired(&e, feature::ABSENT_FROM_SCRATCH_SPACE), "{elsewhere} took both rows");
        }

        let w = Weights::embedded();
        let scratch = w.get(feature::ABSENT_FROM_SCRATCH_SPACE).unwrap();
        let general = w.get(feature::EXECUTED_BUT_NOW_ABSENT).unwrap();
        assert!(scratch.log_lr > 0.0 && scratch.log_lr < general.log_lr);
        assert_eq!(scratch.group, general.group, "the two must never be able to stack");
    }

    #[test]
    fn a_system_binary_name_outside_system32_fires() {
        let c = candidate_at("C:\\Users\\bob\\AppData\\Roaming\\svchost.exe");
        let e = score(&c, &Baseline::default());
        assert!(fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR));
    }

    #[test]
    fn the_real_system_binary_does_not_fire() {
        let c = candidate_at("C:\\Windows\\System32\\svchost.exe");
        let e = score(&c, &Baseline::default());
        assert!(!fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR));

        let c = candidate_at("C:\\Windows\\WinSxS\\amd64_x\\svchost.exe");
        assert!(!fired(
            &score(&c, &Baseline::default()),
            feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR
        ));
    }

    #[test]
    fn only_explorer_has_a_home_outside_the_system_directories() {
        let extra: Vec<&str> = SYSTEM_BINARIES
            .iter()
            .filter(|(_, home)| *home == SystemBinaryHome::SystemDirectoriesOrWindowsRoot)
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(extra, vec!["explorer.exe"], "the home table gained an entry unmeasured");

        assert!(system_binary_home("notepad.exe").is_none());
        assert!(system_binary_home("svchost.exe").is_some());
    }

    #[test]
    fn stock_explorer_in_the_windows_directory_does_not_fire() {
        for p in [
            "C:\\Windows\\explorer.exe",
            "%SystemRoot%\\explorer.exe",
            "%windir%\\explorer.exe",
            "C:\\WINDOWS\\EXPLORER.EXE",
            "C:\\Windows\\SysWOW64\\explorer.exe",
        ] {
            let e = score(&candidate_at(p), &Baseline::default());
            assert!(
                !fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR),
                "{p} was accused of impersonating itself"
            );
        }
    }

    #[test]
    fn the_windows_root_home_does_not_widen_to_the_whole_windows_directory() {
        for p in [
            "C:\\Windows\\Tasks\\explorer.exe",
            "C:\\Windows\\SystemTemp\\explorer.exe",
            "C:\\Windows\\assembly\\explorer.exe",
            "C:\\Windows\\svchost.exe",
            "C:\\Windows\\lsass.exe",
            "C:\\Windows\\userinit.exe",
        ] {
            let e = score(&candidate_at(p), &Baseline::default());
            assert!(
                fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR),
                "the masquerade row went quiet on {p}"
            );
        }
    }

    #[test]
    fn double_extensions_are_detected_without_catching_versioned_names() {
        assert_eq!(double_extension("invoice.pdf.exe"), Some("pdf"));
        assert_eq!(double_extension("photo.jpg.scr"), Some("jpg"));
        assert_eq!(double_extension("report.docx.js"), Some("docx"));

        assert_eq!(double_extension("archive.tar.gz"), None);
        assert_eq!(double_extension("lib.1.dll"), None);
        assert_eq!(double_extension("setup.exe"), None);
        assert_eq!(double_extension("a.b.c.txt"), None);
    }

    #[test]
    fn machine_generated_names_are_recognized_conservatively() {
        assert!(looks_machine_generated("a3f8b2c1d9.exe"));
        assert!(looks_machine_generated("xkcdrqzptv.exe"));

        for name in [
            "notepad.exe",
            "chrome.exe",
            "WindowsUpdate.exe",
            "setup.exe",
            "vcredist_x64.exe",
            "Adobe Reader.exe",
            "python3.11.exe",
        ] {
            assert!(!looks_machine_generated(name), "{name} should not look generated");
        }
    }

    #[test]
    fn location_features_fire_per_zone() {
        assert!(fired(
            &score(
                &candidate_at("C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe"),
                &Baseline::default()
            ),
            feature::EXECUTABLE_IN_USER_TEMP
        ));
        assert!(fired(
            &score(&candidate_at("C:\\payload.exe"), &Baseline::default()),
            feature::EXECUTABLE_AT_VOLUME_ROOT
        ));
        assert!(!fired(
            &score(&candidate_at("C:\\Program Files\\App\\a.exe"), &Baseline::default()),
            feature::EXECUTABLE_IN_USER_TEMP
        ));
    }

    #[test]
    fn the_lone_executable_among_documents_is_noticed() {
        let e =
            score(&candidate_at("C:\\Users\\bob\\Documents\\invoice.exe"), &documents_baseline());
        assert!(fired(&e, feature::LONE_EXECUTABLE_AMONG_DOCUMENTS));
        let detail = &e
            .iter()
            .find(|x| x.feature == feature::LONE_EXECUTABLE_AMONG_DOCUMENTS)
            .unwrap()
            .detail;
        assert!(detail.contains("41"), "detail should say how many files: {detail}");
    }

    #[test]
    fn baseline_features_stay_silent_when_the_baseline_is_thin() {
        let mut b = BaselineBuilder::new();
        b.observe(&path("C:\\Users\\bob\\Documents\\invoice.exe"));
        let thin = b.build();
        assert!(!thin.is_usable());

        let e = score(&candidate_at("C:\\Users\\bob\\Documents\\invoice.exe"), &thin);
        assert!(!fired(&e, feature::LONE_EXECUTABLE_AMONG_DOCUMENTS));
        assert!(!fired(&e, feature::NAME_UNIQUE_ON_MACHINE));
        assert!(!fired(&e, feature::EXECUTABLE_RARE_FOR_ZONE));
    }

    fn machine_plus(extra: &[&str]) -> Baseline {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
        }
        for p in extra {
            b.observe(&path(p));
        }
        b.build()
    }

    #[test]
    fn decoy_copies_in_user_directories_do_not_exonerate() {
        let baseline = machine_plus(&[
            "C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svcupdate.exe",
            "C:\\Users\\bob\\AppData\\Local\\Decoy0\\svcupdate.exe",
            "C:\\Users\\bob\\AppData\\Local\\Decoy1\\svcupdate.exe",
        ]);
        assert_eq!(baseline.name_occurrences("svcupdate.exe"), 3);

        let e = score(
            &candidate_at("C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svcupdate.exe"),
            &baseline,
        );
        assert!(!fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");
        assert!(!fired(&e, feature::NAME_UNIQUE_ON_MACHINE), "{e:#?}");
    }

    #[test]
    fn a_component_store_original_still_exonerates() {
        let baseline = machine_plus(&[
            "C:\\Windows\\System32\\common.dll",
            "C:\\Windows\\WinSxS\\amd64_a\\common.dll",
            "C:\\Windows\\WinSxS\\amd64_b\\common.dll",
        ]);
        let e = score(&candidate_at("C:\\Windows\\System32\\common.dll"), &baseline);
        assert!(fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");
        let detail =
            &e.iter().find(|x| x.feature == feature::NAME_RECURS_ON_MACHINE).unwrap().detail;
        assert!(detail.contains("3 of them"), "the sentence must say how many vouch: {detail}");
    }

    #[test]
    fn a_shipped_runtime_exonerates_a_copy_sitting_in_a_user_directory() {
        let baseline = machine_plus(&[
            "C:\\Users\\bob\\AppData\\Local\\App\\vcruntime140.dll",
            "C:\\Program Files\\A\\vcruntime140.dll",
            "C:\\Program Files\\B\\vcruntime140.dll",
        ]);
        let e = score(
            &candidate_at("C:\\Users\\bob\\AppData\\Local\\App\\vcruntime140.dll"),
            &baseline,
        );
        assert!(fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");
    }

    #[test]
    fn a_file_does_not_vouch_for_itself() {
        let baseline = machine_plus(&[
            "C:\\Program Files\\Vendor\\svcupdate.exe",
            "C:\\Users\\bob\\AppData\\Local\\Decoy0\\svcupdate.exe",
            "C:\\Users\\bob\\AppData\\Local\\Decoy1\\svcupdate.exe",
        ]);
        assert_eq!(baseline.name_occurrences_in_conventional_zones("svcupdate.exe"), 1);

        let e = score(&candidate_at("C:\\Program Files\\Vendor\\svcupdate.exe"), &baseline);
        assert!(!fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");

        let baseline = machine_plus(&[
            "C:\\Program Files\\Vendor\\svcupdate.exe",
            "C:\\Program Files\\Other\\svcupdate.exe",
            "C:\\Users\\bob\\AppData\\Local\\Decoy0\\svcupdate.exe",
        ]);
        let e = score(&candidate_at("C:\\Program Files\\Vendor\\svcupdate.exe"), &baseline);
        assert!(fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");
    }

    #[test]
    fn the_genuine_binary_does_not_exonerate_the_file_impersonating_it() {
        let mut extra: Vec<String> = vec![
            "C:\\Windows\\System32\\svchost.exe".to_string(),
            "C:\\Windows\\SysWOW64\\svchost.exe".to_string(),
        ];
        for i in 0..6 {
            extra.push(format!("C:\\Windows\\WinSxS\\amd64_{i}\\svchost.exe"));
        }
        extra.push("C:\\Users\\Alice\\AppData\\Roaming\\svchost.exe".to_string());
        let refs: Vec<&str> = extra.iter().map(String::as_str).collect();
        let baseline = machine_plus(&refs);

        assert_eq!(baseline.name_occurrences("svchost.exe"), 9);
        assert_eq!(baseline.name_occurrences_in_conventional_zones("svchost.exe"), 8);

        let e = score(&candidate_at("C:\\Users\\Alice\\AppData\\Roaming\\svchost.exe"), &baseline);
        assert!(fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR), "{e:#?}");
        assert!(!fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");

        let masq: Vec<&Evidence> = e
            .iter()
            .filter(|x| x.feature == feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR)
            .collect();
        assert_eq!(masq.len(), 1, "the masquerade row must score exactly once: {e:#?}");
        assert_eq!(masq[0].log_lr, 6.0);
        assert!(masq[0].detail.contains("9 files named"), "{}", masq[0].detail);
        assert!(masq[0].detail.contains("8 sit"), "{}", masq[0].detail);
        assert!(
            masq[0].detail.contains("not one of them"),
            "the sentence must say the file is not among them: {}",
            masq[0].detail
        );

        let real = score(&candidate_at("C:\\Windows\\System32\\svchost.exe"), &baseline);
        assert!(fired(&real, feature::NAME_RECURS_ON_MACHINE), "{real:#?}");
        assert!(!fired(&real, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR), "{real:#?}");
    }

    #[test]
    fn a_masquerade_sitting_in_a_conventional_zone_is_not_counted_among_the_genuine_copies() {
        let baseline = machine_plus(&[
            "C:\\Windows\\System32\\regsvr32.exe",
            "C:\\Windows\\SysWOW64\\regsvr32.exe",
            "C:\\Windows\\WinSxS\\amd64_a\\regsvr32.exe",
            "C:\\Program Files (x86)\\Bignox\\BigNoxVM\\RT\\regsvr32.exe",
        ]);
        assert_eq!(baseline.name_occurrences("regsvr32.exe"), 4);
        assert_eq!(baseline.name_occurrences_in_conventional_zones("regsvr32.exe"), 4);

        let e = score(
            &candidate_at("C:\\Program Files (x86)\\Bignox\\BigNoxVM\\RT\\regsvr32.exe"),
            &baseline,
        );
        assert!(fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR), "{e:#?}");
        assert!(!fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");

        let detail = &e
            .iter()
            .find(|x| x.feature == feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR)
            .unwrap()
            .detail;
        assert!(detail.contains("4 files named"), "{detail}");
        assert!(detail.contains("3 sit"), "the file must not be counted among them: {detail}");
    }

    #[test]
    fn no_file_can_take_the_masquerade_row_and_the_recurrence_row_at_once() {
        let dirs = [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\Windows\\WinSxS\\amd64_a",
            "C:\\Windows\\WinSxS\\amd64_b",
            "C:\\Windows",
            "C:\\Windows\\Tasks",
            "C:\\Program Files\\Vendor",
            "C:\\Program Files (x86)\\Vendor",
            "C:\\Users\\bob\\AppData\\Roaming",
            "C:\\Users\\bob\\AppData\\Local\\Temp",
            "C:\\ProgramData\\Vendor",
            "C:\\\\",
        ];
        for (name, _) in SYSTEM_BINARIES {
            let all: Vec<String> = dirs.iter().map(|d| format!("{d}\\{name}")).collect();
            let refs: Vec<&str> = all.iter().map(String::as_str).collect();
            let baseline = machine_plus(&refs);

            for dir in dirs {
                let p = format!("{dir}\\{name}");
                let e = score(&candidate_at(&p), &baseline);
                assert!(
                    !(fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR)
                        && fired(&e, feature::NAME_RECURS_ON_MACHINE)),
                    "{p} was accused of impersonating a system binary and excused for \
                     sharing its name in the same breath"
                );
            }
        }
    }

    #[test]
    fn a_name_that_is_not_a_system_binarys_still_recurs_normally() {
        let baseline = machine_plus(&[
            "C:\\Users\\bob\\AppData\\Local\\App\\vcruntime140.dll",
            "C:\\Program Files\\A\\vcruntime140.dll",
            "C:\\Program Files\\B\\vcruntime140.dll",
        ]);
        let e = score(
            &candidate_at("C:\\Users\\bob\\AppData\\Local\\App\\vcruntime140.dll"),
            &baseline,
        );
        assert!(fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");
        assert!(!fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR), "{e:#?}");
    }

    #[test]
    fn an_unlocated_system_binary_name_keeps_the_recurrence_row() {
        let baseline = machine_plus(&[
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\WinSxS\\amd64_a\\svchost.exe",
            "C:\\Windows\\WinSxS\\amd64_b\\svchost.exe",
        ]);
        let e = score(&candidate_at("svchost.exe"), &baseline);
        assert!(!fired(&e, feature::SYSTEM_BINARY_NAME_OUTSIDE_SYSTEM_DIR), "{e:#?}");
        assert!(fired(&e, feature::NAME_RECURS_ON_MACHINE), "{e:#?}");
    }

    fn walked(p: &str) -> Candidate {
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(p),
            ObservationKind::FileExists {
                size: 2048,
                created: None,
                modified: None,
                mft_modified: None,
                record: None,
            },
        ));
        c
    }

    #[test]
    fn a_recurring_name_exonerates_and_a_unique_one_does_not() {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
        }
        for dir in ["System32", "WinSxS\\a", "WinSxS\\b"] {
            b.observe(&path(&format!("C:\\Windows\\{dir}\\common.dll")));
        }
        b.observe(&path("C:\\Users\\bob\\once.exe"));
        let baseline = b.build();

        let c = walked("C:\\Windows\\System32\\common.dll");
        assert!(fired(&score(&c, &baseline), feature::NAME_RECURS_ON_MACHINE));

        assert!(fired(
            &score(&walked("C:\\Users\\bob\\once.exe"), &baseline),
            feature::NAME_UNIQUE_ON_MACHINE
        ));
    }

    #[test]
    fn a_name_the_machine_still_carries_is_not_unique_for_a_file_that_is_gone() {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
        }
        let live = "C:\\Program Files (x86)\\Microsoft OneDrive\\23.038.0219.0001\\FileCoAuth.exe";
        b.observe(&path(live));
        let baseline = b.build();

        let gone = candidate_at(
            "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\21.220.1024.0005\\FileCoAuth.exe",
        );
        assert!(
            !fired(&score(&gone, &baseline), feature::NAME_UNIQUE_ON_MACHINE),
            "the machine holds a FileCoAuth.exe, so nothing here is unique"
        );

        assert!(fired(&score(&walked(live), &baseline), feature::NAME_UNIQUE_ON_MACHINE));

        let unheard_of = candidate_at("C:\\Users\\bob\\AppData\\Roaming\\dropper-9f2c.exe");
        assert!(fired(&score(&unheard_of, &baseline), feature::NAME_UNIQUE_ON_MACHINE));
    }

    fn baseline_with(rare: &[&str]) -> Baseline {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
        }
        for p in rare {
            b.observe(&path(p));
        }
        b.build()
    }

    #[test]
    fn zone_rarity_still_fires_after_the_unlocated_change() {
        let baseline = baseline_with(&["C:\\Users\\bob\\Downloads\\tool.exe"]);
        let e = score(&candidate_at("C:\\Users\\bob\\Downloads\\tool.exe"), &baseline);
        assert!(fired(&e, feature::EXECUTABLE_RARE_FOR_ZONE), "{e:#?}");
        let rare = e.iter().find(|x| x.feature == feature::EXECUTABLE_RARE_FOR_ZONE).unwrap();
        assert!(rare.detail.contains("only 1"), "{}", rare.detail);
    }

    #[test]
    fn an_unlocated_name_is_never_rare_for_its_zone() {
        let mut c = Candidate::new(CandidateId(0), PRIOR);
        c.path = NormalizedPath::unlocated("steam.exe");
        assert!(!fired(&score(&c, &baseline_with(&[])), feature::EXECUTABLE_RARE_FOR_ZONE));
    }

    #[test]
    fn rarity_does_not_charge_twice_for_the_volume_root() {
        let baseline = baseline_with(&["C:\\payload.exe", "C:\\appverifUI.dll"]);
        let e = score(&candidate_at("C:\\payload.exe"), &baseline);

        assert!(fired(&e, feature::EXECUTABLE_AT_VOLUME_ROOT), "the location weight still applies");
        assert!(!fired(&e, feature::EXECUTABLE_RARE_FOR_ZONE), "and it must not be paid for twice");

        let location = e.iter().find(|x| x.feature == feature::EXECUTABLE_AT_VOLUME_ROOT).unwrap();
        assert!(location.detail.contains("only 2 executable"), "{}", location.detail);
    }

    #[test]
    fn rarity_still_wins_where_the_fixed_row_is_weaker() {
        for p in [
            "C:\\Users\\bob\\AppData\\Roaming\\vendor\\svc.exe",
            "C:\\Users\\bob\\Desktop\\svc.exe",
            "D:\\vendor\\svc.exe",
        ] {
            let baseline = baseline_with(&[p]);
            let e = score(&candidate_at(p), &baseline);
            let rare =
                e.iter().find(|x| x.feature == feature::EXECUTABLE_RARE_FOR_ZONE).unwrap_or_else(
                    || panic!("the measured claim lost to a weaker fixed row at {p}: {e:#?}"),
                );
            assert!(rare.log_lr > 0.0);
        }
    }

    #[test]
    fn programdata_outranks_the_measured_claim_and_keeps_its_sentence() {
        let baseline = baseline_with(&["C:\\ProgramData\\vendor\\svc.exe"]);
        let e = score(&candidate_at("C:\\ProgramData\\vendor\\svc.exe"), &baseline);
        let location = e
            .iter()
            .find(|x| x.feature == feature::EXECUTABLE_IN_PROGRAMDATA)
            .expect("ProgramData must carry a location weight");
        assert_eq!(location.log_lr, 2.6);
        assert!(
            location.detail.contains("only 1 executable"),
            "the rarity sentence was dropped instead of folded in: {}",
            location.detail
        );
    }

    #[test]
    fn a_zone_this_machine_actually_uses_is_not_rare() {
        let mut paths: Vec<String> =
            (0..40).map(|i| format!("C:\\Users\\bob\\Downloads\\tool{i}.exe")).collect();
        paths.push("C:\\Users\\bob\\Downloads\\payload.exe".into());
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();

        let e =
            score(&candidate_at("C:\\Users\\bob\\Downloads\\payload.exe"), &baseline_with(&refs));
        assert!(!fired(&e, feature::EXECUTABLE_RARE_FOR_ZONE));
    }

    fn compact_os_baseline(compressed: usize) -> Baseline {
        compact_os_baseline_in(compressed, 1)
    }

    fn compact_os_baseline_in(compressed: usize, per_directory: usize) -> Baseline {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe_file(&path(&format!(r"C:\Windows\System32\f{i}.dll")), false);
        }
        for i in 0..compressed {
            let dir = i / per_directory.max(1);
            b.observe_file(&path(&format!(r"C:\ProgramData\vendor{dir}\c{i}.exe")), true);
        }
        b.observe_file(&path(r"C:\ProgramData\vendor\svc.exe"), compressed > 0);
        b.build()
    }

    fn compressed_candidate(p: &str, algorithm: &str, readable: bool) -> Candidate {
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(p),
            ObservationKind::CompactOsCompressed { algorithm: algorithm.into(), readable },
        ));
        c
    }

    #[test]
    fn compressing_a_payload_is_no_longer_free() {
        let p = r"C:\ProgramData\vendor\svc.exe";
        let mut c = compressed_candidate(p, "LZX", false);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::Signature(SignatureStatus::Unknown {
                reason: "the file is Compact-OS compressed with LZX, which this build does not \
                         decode"
                    .into(),
            }),
        ));
        let e = score(&c, &compact_os_baseline(1));
        let signature = e
            .iter()
            .find(|x| x.feature == feature::COMPACT_OS_COMPRESSED_EXECUTABLE)
            .expect("the compression must be scored, not the unverifiable zero");
        let unverifiable = Weights::embedded().get(feature::SIGNATURE_UNVERIFIABLE).unwrap().log_lr;
        assert!(
            signature.log_lr > unverifiable,
            "the compression must be worth more than the zero it replaces, got {}",
            signature.log_lr
        );
        assert!(
            signature.detail.contains("LZX"),
            "the algorithm has to be named: {}",
            signature.detail
        );
        assert!(
            signature.detail.contains("could not be checked")
                || signature.detail.contains("cannot be produced"),
            "the analyst must still see why nothing was verified: {}",
            signature.detail
        );
    }

    #[test]
    fn a_machine_that_compresses_everything_is_silent() {
        let c = compressed_candidate(r"C:\ProgramData\vendor\svc.exe", "LZX", false);
        for compressed in [6usize, 500, 11_000] {
            let e = score(&c, &compact_os_baseline(compressed));
            assert!(
                !fired(&e, feature::COMPACT_OS_COMPRESSED_EXECUTABLE),
                "fired on a machine holding {compressed} compressed executables: {e:#?}"
            );
        }
    }

    #[test]
    fn a_compressed_resource_file_is_not_accused() {
        let c = compressed_candidate(r"C:\Program Files\Chrome\Locales\en-GB.pak", "LZX", false);
        assert!(!fired(
            &score(&c, &compact_os_baseline(1)),
            feature::COMPACT_OS_COMPRESSED_EXECUTABLE
        ));
    }

    #[test]
    fn a_real_signature_verdict_outranks_the_compression() {
        let p = r"C:\ProgramData\Microsoft\Windows Defender\platform\x\MpSvc.exe";
        let mut c = compressed_candidate(p, "XPRESS4K", true);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::Signature(SignatureStatus::CatalogValid {
                signer: "Microsoft Windows".into(),
                catalog: "x.cat".into(),
                root_is_microsoft: true,
            }),
        ));
        let e = score(&c, &compact_os_baseline(2));
        let signature = e
            .iter()
            .find(|x| x.detail.contains("Microsoft"))
            .expect("the catalog verdict must survive");
        assert!(signature.log_lr < 0.0, "a signed binary must not be accused: {signature:#?}");
        assert!(
            !fired(&e, feature::COMPACT_OS_COMPRESSED_EXECUTABLE),
            "there is no UNKNOWN here to price — the file was read and verified: {e:#?}"
        );
    }

    #[test]
    fn compression_is_not_added_to_an_unsigned_verdict() {
        let p = r"C:\ProgramData\vendor\svc.exe";
        let mut c = compressed_candidate(p, "LZX", false);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::Signature(SignatureStatus::Unsigned),
        ));
        let e = score(&c, &compact_os_baseline(1));
        let weights = Weights::embedded();
        let unsigned = weights.get(feature::UNSIGNED_IN_USER_ZONE).unwrap().log_lr;
        let compression = weights.get(feature::COMPACT_OS_COMPRESSED_EXECUTABLE).unwrap().log_lr;
        let group: f64 = e
            .iter()
            .filter(|x| {
                x.feature == feature::UNSIGNED_IN_USER_ZONE
                    || x.feature == feature::COMPACT_OS_COMPRESSED_EXECUTABLE
            })
            .map(|x| x.log_lr)
            .sum();
        assert_eq!(group, unsigned.max(compression), "the two claims were summed: {e:#?}");
        let surviving = e
            .iter()
            .find(|x| x.log_lr == group && x.feature != feature::EXECUTABLE_IN_PROGRAMDATA)
            .expect("one of them must survive");
        assert!(
            surviving.detail.contains("unsigned") && surviving.detail.contains("Compact-OS"),
            "the superseded claim was dropped instead of folded in: {}",
            surviving.detail
        );
    }

    #[test]
    fn it_holds_when_the_bytes_cannot_be_read() {
        for (algorithm, readable) in
            [("LZX", false), ("WIM-backed", false), ("unknown WOF algorithm", false)]
        {
            let c = compressed_candidate(r"C:\ProgramData\vendor\svc.exe", algorithm, readable);
            let e = score(&c, &compact_os_baseline(1));
            let hit = e
                .iter()
                .find(|x| x.feature == feature::COMPACT_OS_COMPRESSED_EXECUTABLE)
                .unwrap_or_else(|| panic!("silent for {algorithm}: {e:#?}"));
            assert!(hit.detail.contains(algorithm), "{}", hit.detail);
        }
    }

    #[test]
    fn a_directory_that_was_compressed_wholesale_is_not_evidence() {
        let baseline = compact_os_baseline_in(4, 4);
        let c = compressed_candidate(r"C:\ProgramData\vendor0\c0.exe", "LZX", false);
        assert!(
            !fired(&score(&c, &baseline), feature::COMPACT_OS_COMPRESSED_EXECUTABLE),
            "a file compressed along with its directory was accused of being singled out"
        );
    }

    #[test]
    fn a_file_singled_out_on_that_same_machine_still_fires() {
        let baseline = compact_os_baseline_in(4, 4);
        let c = compressed_candidate(r"C:\ProgramData\vendor\svc.exe", "LZX", false);
        assert!(fired(&score(&c, &baseline), feature::COMPACT_OS_COMPRESSED_EXECUTABLE));
    }

    #[test]
    fn a_compact_os_unknown_cannot_report_the_defender_binaries_on_a_clean_vm() {
        let weights = Weights::embedded();
        let row = weights.get(feature::COMPACT_OS_COMPRESSED_EXECUTABLE).unwrap().log_lr;

        let stack: f64 = [
            feature::PERSISTENCE_SERVICE,
            feature::EXECUTABLE_IN_PROGRAMDATA,
            feature::NAME_UNIQUE_ON_MACHINE,
        ]
        .iter()
        .map(|f| weights.get(f).unwrap().log_lr)
        .sum();

        for (path, m) in machine::MEASURED_MACHINES {
            let reached = m.prior() + stack + row;
            assert!(
                reached < 0.0,
                "on {path} ({}, {} candidates, prior {:.4}, counted {}) a Compact-OS UNKNOWN on \
                 Defender's own service binary reaches {reached:+.4} log-odds, over the even-odds \
                 threshold: the tool would name Windows Defender as its top finding on a clean \
                 machine. The stack is {stack}, so this row may not exceed {:.4} there",
                m.what,
                m.candidates,
                m.prior(),
                m.measured,
                m.ln_population() - stack,
            );
        }
    }

    #[test]
    fn the_defender_service_stack_convicts_on_its_own_below_1096_candidates() {
        let weights = Weights::embedded();
        let stack: f64 = [
            feature::PERSISTENCE_SERVICE,
            feature::EXECUTABLE_IN_PROGRAMDATA,
            feature::NAME_UNIQUE_ON_MACHINE,
        ]
        .iter()
        .map(|f| weights.get(f).unwrap().log_lr)
        .sum();

        let break_even = stack.exp();
        assert!(
            (break_even - 1096.0).abs() < 5.0,
            "the population at which Defender's own service binary becomes a finding on a clean \
             machine has moved to {break_even:.0} (stack {stack:+}). That number is quoted in \
             `mm_score::machine` and in this test's documentation; if it moved deliberately, \
             update both. It is above `SMALLEST_MACHINE` ({}), which is why the guard above \
             cannot be written against the floor.",
            machine::SMALLEST_MACHINE.candidates,
        );

        assert!(
            (machine::SMALLEST_MACHINE.candidates as f64) < break_even,
            "the floor has risen above {break_even:.0}, so this hole is closed and this test \
             should be replaced by the guard it stands in for"
        );
    }

    #[test]
    fn compressing_a_file_never_scores_more_than_reading_it_unsigned() {
        let weights = Weights::embedded();
        let row = weights.get(feature::COMPACT_OS_COMPRESSED_EXECUTABLE).unwrap().log_lr;
        let weakest_unsigned = [
            feature::UNSIGNED_IN_SYSTEM_ZONE,
            feature::UNSIGNED_IN_PROGRAM_FILES,
            feature::UNSIGNED_IN_USER_ZONE,
            feature::UNSIGNED_MANAGED_ASSEMBLY,
        ]
        .iter()
        .map(|f| weights.get(f).unwrap().log_lr)
        .fold(f64::INFINITY, f64::min);

        assert!(
            row < weakest_unsigned,
            "an executable whose signature could not be checked scores {row}, more than \
             the {weakest_unsigned} the same file would score if it had been read and \
             found unsigned — compressing a payload would buy the attacker more than \
             being caught unsigned costs him"
        );
        assert!(row > 0.0, "it is still evidence: the bypass must not be free");
    }

    #[test]
    fn a_census_that_counted_nothing_makes_no_claim() {
        let c = compressed_candidate(r"C:\ProgramData\vendor\svc.exe", "LZX", false);
        assert!(!fired(
            &score(&c, &compact_os_baseline(0)),
            feature::COMPACT_OS_COMPRESSED_EXECUTABLE
        ));
    }

    fn with_pe_anomaly(detail: &str) -> Vec<Evidence> {
        let p = "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe";
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::PeAnomaly { detail: detail.into() },
        ));
        score(&c, &Baseline::default())
    }

    fn with_rich(entries: usize, decoded: bool) -> Vec<Evidence> {
        let p = r"C:\Users\bob\AppData\Local\Temp\x.exe";
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::RichHeaderChecksumInvalid { entries, decoded },
        ));
        score(&c, &Baseline::default())
    }

    #[test]
    fn a_forged_rich_header_scores_its_own_row_and_a_technique_id_in_prose_does_not() {
        let forged = with_rich(9, true);
        assert!(fired(&forged, feature::RICH_HEADER_CHECKSUM_INVALID));
        assert!(!fired(&forged, feature::PE_STRUCTURAL_ANOMALY));
        let row =
            forged.iter().find(|x| x.feature == feature::RICH_HEADER_CHECKSUM_INVALID).unwrap();
        assert!(row.detail.contains("9 toolchain entries"), "{}", row.detail);

        let planted = with_rich(0, false);
        assert!(fired(&planted, feature::RICH_HEADER_CHECKSUM_INVALID));
        let row =
            planted.iter().find(|x| x.feature == feature::RICH_HEADER_CHECKSUM_INVALID).unwrap();
        assert!(row.detail.contains("does not decode"), "{}", row.detail);

        let prose = with_pe_anomaly("a version resource claiming Microsoft (T1036.005)");
        assert!(!fired(&prose, feature::RICH_HEADER_CHECKSUM_INVALID));
        assert!(fired(&prose, feature::PE_STRUCTURAL_ANOMALY));
    }

    #[test]
    fn a_forged_rich_header_adds_to_a_suspicious_name_instead_of_being_silenced_by_it() {
        let p = r"C:\Users\bob\AppData\Local\Temp\invoice.pdf.exe";
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::RichHeaderChecksumInvalid { entries: 3, decoded: true },
        ));
        let e = score(&c, &Baseline::default());
        assert!(fired(&e, feature::DOUBLE_EXTENSION), "{e:#?}");
        assert!(fired(&e, feature::RICH_HEADER_CHECKSUM_INVALID), "{e:#?}");
    }

    #[test]
    fn the_three_pe_anomaly_findings_are_kept_apart() {
        let packed = with_pe_anomaly(
            "the `UPX1` section holds 6832 KB at 7.93 bits/byte of entropy — near-random, \
             which is what packing or encryption looks like (T1027.002)",
        );
        assert!(fired(&packed, feature::HIGH_ENTROPY_CODE_SECTION));
        assert!(!fired(&packed, feature::PE_STRUCTURAL_ANOMALY));
        assert!(!fired(&packed, feature::TIMESTOMPED));

        let stomped = with_pe_anomaly("timestamps were overwritten (T1070.006)");
        assert!(fired(&stomped, feature::TIMESTOMPED));
        assert!(!fired(&stomped, feature::HIGH_ENTROPY_CODE_SECTION));

        let malformed = with_pe_anomaly("the entry point lies outside every section");
        assert!(fired(&malformed, feature::PE_STRUCTURAL_ANOMALY));
        assert!(!fired(&malformed, feature::HIGH_ENTROPY_CODE_SECTION));
        assert!(!fired(&malformed, feature::TIMESTOMPED));
    }

    #[test]
    fn the_packing_explanation_reaches_the_report_intact() {
        let e =
            with_pe_anomaly("the `.themida` section holds 900 KB at 7.99 bits/byte (T1027.002)");
        let packed = e.iter().find(|x| x.feature == feature::HIGH_ENTROPY_CODE_SECTION).unwrap();
        assert!(packed.detail.contains(".themida"));
        assert!(packed.detail.contains("7.99"));
        assert!(!packed.detail.contains("malformed"));
    }

    #[test]
    fn packing_and_structural_damage_score_once_between_them() {
        let p = "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe";
        let mut c = candidate_at(p);
        for detail in ["packed at 7.9 bits/byte (T1027.002)", "overlapping sections"] {
            c.observe(Observation::about_path(
                ArtifactSource::FileContent,
                path(p),
                ObservationKind::PeAnomaly { detail: detail.into() },
            ));
        }
        let e = score(&c, &Baseline::default());
        let content: Vec<&Evidence> = e
            .iter()
            .filter(|x| {
                x.feature == feature::HIGH_ENTROPY_CODE_SECTION
                    || x.feature == feature::PE_STRUCTURAL_ANOMALY
            })
            .collect();
        assert_eq!(content.len(), 1, "one per group: {e:#?}");
        assert_eq!(content[0].feature, feature::PE_STRUCTURAL_ANOMALY);
        assert!(content[0].detail.contains("7.9 bits/byte"));
    }

    #[test]
    fn quarantine_is_the_strongest_single_observation() {
        let mut c = candidate_at("C:\\Users\\bob\\x.exe");
        c.observe(Observation::about_path(
            ArtifactSource::DefenderQuarantine,
            path("C:\\Users\\bob\\x.exe"),
            ObservationKind::Quarantined {
                product: "Windows Defender".into(),
                threat: Some("Trojan:Win32/Wacatac".into()),
                when: chrono::DateTime::from_timestamp(1_785_272_874, 0),
                severity: None,
            },
        ));
        let e = score(&c, &Baseline::default());
        let q = e.iter().find(|x| x.feature == feature::QUARANTINED_BY_AV).unwrap();
        assert!(q.detail.contains("Wacatac"));

        let weights = Weights::embedded();
        assert!(q.log_lr > 0.0, "a quarantine is still evidence");
        assert_eq!(
            q.log_lr,
            weights.max_log_lr_in_group("antivirus"),
            "a quarantine must be the strongest claim the antivirus group can make"
        );
    }

    fn av_detected(product: &str, threat: Option<&str>) -> Vec<Evidence> {
        let p = "C:\\Users\\bob\\x.exe";
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::DefenderLog { event_id: 1118 },
            path(p),
            ObservationKind::AvDetected {
                product: product.into(),
                threat: threat.map(Into::into),
                when: None,
                severity: None,
            },
        ));
        score(&c, &Baseline::default())
    }

    #[test]
    fn a_detection_without_a_remediation_is_a_different_claim_from_a_quarantine() {
        let e = av_detected("Windows Defender", Some("Trojan:Win32/Egairtigado!rfn"));
        let d = e.iter().find(|x| x.feature == feature::AV_DETECTION_LOGGED).unwrap();
        assert!(d.detail.contains("Egairtigado"));
        assert!(!d.detail.contains("quarantin"), "it was not quarantined: {}", d.detail);
        assert!(d.detail.contains("not recorded as having removed it"));
        assert!(!fired(&e, feature::QUARANTINED_BY_AV));
    }

    #[test]
    fn a_detection_and_a_quarantine_of_one_file_are_counted_once() {
        let p = "C:\\Users\\bob\\x.exe";
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::DefenderLog { event_id: 1116 },
            path(p),
            ObservationKind::AvDetected {
                product: "Windows Defender".into(),
                threat: Some("Trojan:Win32/Suschil!rfn".into()),
                when: None,
                severity: None,
            },
        ));
        c.observe(Observation::about_path(
            ArtifactSource::DefenderLog { event_id: 1117 },
            path(p),
            ObservationKind::Quarantined {
                product: "Windows Defender".into(),
                threat: Some("Trojan:Win32/Suschil!rfn".into()),
                when: None,
                severity: None,
            },
        ));

        let e = score(&c, &Baseline::default());
        let scoring: Vec<&Evidence> = e
            .iter()
            .filter(|x| {
                x.log_lr != 0.0
                    && (x.feature == feature::QUARANTINED_BY_AV
                        || x.feature == feature::AV_DETECTION_LOGGED)
            })
            .collect();
        assert_eq!(scoring.len(), 1, "one AV claim survives the group: {scoring:#?}");
        assert_eq!(scoring[0].feature, feature::QUARANTINED_BY_AV);
    }

    #[test]
    fn no_single_av_verdict_can_convict_on_its_own() {
        let weights = Weights::embedded();
        let most = weights.max_log_lr_in_group("antivirus");

        let floor = machine::SMALLEST_MACHINE;
        let ceiling = floor.single_feature_ceiling();
        assert!(
            most <= ceiling,
            "the strongest antivirus row is {most:+}, above the {ceiling:.4} a single row may \
             carry on the smallest machine this tool will report on ({} candidates, ln = {:.4}, \
             measured {}). At {most:+} an AV verdict plus one +{:.1} row that fires on a third \
             of the volume reaches p = {:.4} there with no other evidence at all — a resolved \
             past detection becomes a present accusation.",
            floor.candidates,
            floor.ln_population(),
            floor.measured,
            machine::CHEAPEST_UBIQUITOUS_ROW,
            1.0 / (1.0 + (-(floor.prior() + most + machine::CHEAPEST_UBIQUITOUS_ROW)).exp()),
        );

        for (path, m) in machine::MEASURED_MACHINES {
            let reached = m.prior() + most + machine::CHEAPEST_UBIQUITOUS_ROW;
            assert!(
                reached < 0.0,
                "on {path} ({}, {} candidates, prior {:.4}) an AV verdict plus one +{:.1} row \
                 reaches {reached:+.4} log-odds — over the even-odds threshold",
                m.what,
                m.candidates,
                m.prior(),
                machine::CHEAPEST_UBIQUITOUS_ROW,
            );
        }

        let detection = weights.get(feature::AV_DETECTION_LOGGED).unwrap().log_lr;
        let quarantine = weights.get(feature::QUARANTINED_BY_AV).unwrap().log_lr;
        assert!(
            detection < quarantine,
            "an AV that only logged a detection is weaker evidence than one that acted"
        );
        assert!(detection > 0.0, "it is still evidence");
    }

    #[test]
    fn a_microsoft_catalog_signature_exonerates() {
        let mut c = candidate_at("C:\\Windows\\System32\\svchost.exe");
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path("C:\\Windows\\System32\\svchost.exe"),
            ObservationKind::Signature(SignatureStatus::CatalogValid {
                signer: "Microsoft Windows".into(),
                catalog: "Package_1.cat".into(),
                root_is_microsoft: true,
            }),
        ));
        c.evidence = score(&c, &Baseline::default());
        assert!(c.evidence.iter().any(|e| e.log_lr < -5.0));
        assert!(c.probability() < 0.001);
    }

    #[test]
    fn a_third_party_catalog_does_not_collect_the_microsoft_weight() {
        let make = |root_is_microsoft: bool| {
            let mut c = candidate_at("C:\\Windows\\System32\\drivers\\tap0901.sys");
            c.observe(Observation::about_path(
                ArtifactSource::FileContent,
                path("C:\\Windows\\System32\\drivers\\tap0901.sys"),
                ObservationKind::Signature(SignatureStatus::CatalogValid {
                    signer: "OpenVPN Technologies, Inc.".into(),
                    catalog: "oem40.cat".into(),
                    root_is_microsoft,
                }),
            ));
            score(&c, &Baseline::default())
        };

        let oem = make(false);
        assert!(fired(&oem, feature::SIGNED_TRUSTED_PUBLISHER));
        assert!(!fired(&oem, feature::SIGNED_MICROSOFT_CATALOG));
        let detail =
            &oem.iter().find(|e| e.feature == feature::SIGNED_TRUSTED_PUBLISHER).unwrap().detail;
        assert!(detail.contains("oem40.cat"), "the analyst must be told which catalog: {detail}");
        assert!(detail.contains("third-party"));

        assert!(fired(&make(true), feature::SIGNED_MICROSOFT_CATALOG));

        let oem_total: f64 = oem.iter().map(|e| e.log_lr).sum();
        let ms_total: f64 = make(true).iter().map(|e| e.log_lr).sum();
        assert!(
            ms_total < oem_total,
            "Microsoft {ms_total} should exonerate harder than OEM {oem_total}"
        );
    }

    #[test]
    fn an_expired_signature_is_not_reported_as_an_invalid_one() {
        let mut c = candidate_at("C:\\Program Files\\Qt\\Qt5Positioning.dll");
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path("C:\\Program Files\\Qt\\Qt5Positioning.dll"),
            ObservationKind::Signature(SignatureStatus::Expired {
                signer: "The Qt Company Oy".into(),
            }),
        ));
        let e = score(&c, &Baseline::default());
        assert!(fired(&e, feature::SIGNATURE_EXPIRED));
        assert!(!fired(&e, feature::SIGNATURE_INVALID), "expiry is not tampering");

        let expired = e.iter().find(|x| x.feature == feature::SIGNATURE_EXPIRED).unwrap();
        assert!(expired.log_lr < 2.0, "an old certificate is not an accusation");
        assert!(expired.detail.contains("The Qt Company Oy"));
    }

    fn unsigned_at(p: &str, managed: bool) -> Vec<Evidence> {
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::Signature(SignatureStatus::Unsigned),
        ));
        if managed {
            c.observe(Observation::about_path(
                ArtifactSource::FileContent,
                path(p),
                ObservationKind::ManagedAssembly,
            ));
        }
        score(&c, &Baseline::default())
    }

    #[test]
    fn an_unsigned_managed_assembly_takes_the_smaller_signature_weight() {
        let gac = "C:\\Windows\\assembly\\GAC_MSIL\\System.Data\\v4.0__b77a\\System.Data.dll";
        let managed = unsigned_at(gac, true);
        let native = unsigned_at(gac, false);

        assert!(fired(&managed, feature::UNSIGNED_MANAGED_ASSEMBLY));
        assert!(!fired(&managed, feature::UNSIGNED_IN_SYSTEM_ZONE));
        assert!(fired(&native, feature::UNSIGNED_IN_SYSTEM_ZONE));
        assert!(!fired(&native, feature::UNSIGNED_MANAGED_ASSEMBLY));

        assert_eq!(group_total(&managed, "signature").min(0.0), 0.0);
        assert!(
            group_total(&managed, "signature") < group_total(&native, "signature"),
            "managed {:.2} did not come in under native {:.2}",
            group_total(&managed, "signature"),
            group_total(&native, "signature")
        );

        assert!(group_total(&managed, "signature") > 1.0);
    }

    #[test]
    fn the_managed_discount_applies_across_the_conventional_zones() {
        for p in [
            "C:\\Windows\\assembly\\GAC_64\\a\\a.dll",
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\WPF\\a.dll",
            "C:\\Windows\\System32\\a.dll",
            "C:\\Windows\\WinSxS\\amd64_x\\a.dll",
            "C:\\Program Files\\WindowsPowerShell\\Modules\\Pester\\bin\\Pester.dll",
            "C:\\Program Files (x86)\\Steam\\bin\\cef\\managed\\SteamUI.dll",
        ] {
            assert!(fired(&unsigned_at(p, true), feature::UNSIGNED_MANAGED_ASSEMBLY), "{p}");
            let native_row = if p.starts_with("C:\\Program Files") {
                feature::UNSIGNED_IN_PROGRAM_FILES
            } else {
                feature::UNSIGNED_IN_SYSTEM_ZONE
            };
            assert!(fired(&unsigned_at(p, false), native_row), "{p}");
        }
    }

    #[test]
    fn the_two_conventional_zones_take_different_unsigned_weights() {
        let system = unsigned_at("C:\\Windows\\System32\\odd.dll", false);
        let program = unsigned_at("C:\\Program Files\\Vendor\\odd.dll", false);

        assert!(fired(&system, feature::UNSIGNED_IN_SYSTEM_ZONE));
        assert!(!fired(&system, feature::UNSIGNED_IN_PROGRAM_FILES));
        assert!(fired(&program, feature::UNSIGNED_IN_PROGRAM_FILES));
        assert!(!fired(&program, feature::UNSIGNED_IN_SYSTEM_ZONE));

        let sys_lr = group_total(&system, "signature");
        let pf_lr = group_total(&program, "signature");
        assert!(
            sys_lr > pf_lr + 2.0,
            "the system zone must price this far above Program Files: {sys_lr:.2} vs {pf_lr:.2}"
        );
        assert!(sys_lr < 7.5, "system zone {sys_lr:.2} exceeds ln(1/0.00053)");
        assert!(pf_lr < 1.66, "Program Files {pf_lr:.2} exceeds ln(1/0.191)");
    }

    #[test]
    fn the_managed_discount_does_not_reach_the_user_zones() {
        for p in [
            "C:\\Users\\bob\\AppData\\Local\\Temp\\stage.dll",
            "C:\\Users\\bob\\Downloads\\stage.exe",
            "C:\\ProgramData\\stage.exe",
            "C:\\stage.exe",
        ] {
            let managed = unsigned_at(p, true);
            assert!(fired(&managed, feature::UNSIGNED_IN_USER_ZONE), "{p}");
            assert!(!fired(&managed, feature::UNSIGNED_MANAGED_ASSEMBLY), "{p}");
            assert_eq!(
                group_total(&managed, "signature"),
                group_total(&unsigned_at(p, false), "signature"),
                "{p}: being managed moved the score in a user zone"
            );
        }
    }

    #[test]
    fn being_a_managed_assembly_is_never_itself_evidence() {
        let p = "C:\\Program Files\\Vendor\\a.dll";
        for status in [
            None,
            Some(SignatureStatus::CatalogValid {
                signer: "Vendor".into(),
                catalog: "v.cat".into(),
                root_is_microsoft: true,
            }),
            Some(SignatureStatus::Unknown { reason: "CatRoot could not be read".into() }),
        ] {
            let mut plain = candidate_at(p);
            let mut managed = candidate_at(p);
            if let Some(status) = status {
                for c in [&mut plain, &mut managed] {
                    c.observe(Observation::about_path(
                        ArtifactSource::FileContent,
                        path(p),
                        ObservationKind::Signature(status.clone()),
                    ));
                }
            }
            managed.observe(Observation::about_path(
                ArtifactSource::FileContent,
                path(p),
                ObservationKind::ManagedAssembly,
            ));
            assert_eq!(
                score(&managed, &Baseline::default()).len(),
                score(&plain, &Baseline::default()).len(),
                "being managed added evidence of its own"
            );
        }
    }

    #[test]
    fn an_unrecognised_certificate_authority_is_not_a_tampering_claim() {
        let mut c = candidate_at("C:\\Users\\bob\\tool.exe");
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path("C:\\Users\\bob\\tool.exe"),
            ObservationKind::Signature(SignatureStatus::Untrusted {
                signer: "Contoso Internal Code Signing".into(),
                self_signed_leaf: false,
            }),
        ));
        let e = score(&c, &Baseline::default());
        assert!(
            !e.iter().any(|x| x.feature == feature::SIGNATURE_INVALID),
            "an unrecognised CA is not tampering: {e:?}"
        );
        assert!(
            !e.iter().any(|x| x.feature == feature::SIGNATURE_SELF_SIGNED),
            "a chain to a CA above the leaf is not self-signing: {e:?}"
        );
        let f = e.iter().find(|x| x.feature == feature::UNSIGNED_IN_USER_ZONE).unwrap();
        assert!(f.detail.contains("THIS BUILD DOES NOT HAVE THAT ROOT"), "{}", f.detail);
        assert!(f.detail.contains("Contoso Internal Code Signing"), "{}", f.detail);
        assert!(!f.detail.contains("tamper"), "{}", f.detail);
    }

    #[test]
    fn a_self_signed_leaf_is_a_finding_about_the_file() {
        let mut c = candidate_at("C:\\Users\\bob\\tool.exe");
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path("C:\\Users\\bob\\tool.exe"),
            ObservationKind::Signature(SignatureStatus::Untrusted {
                signer: "ACME Ltd".into(),
                self_signed_leaf: true,
            }),
        ));
        let e = score(&c, &Baseline::default());
        let f = e.iter().find(|x| x.feature == feature::SIGNATURE_SELF_SIGNED).unwrap();
        assert!(f.detail.contains("issued its own signing certificate"), "{}", f.detail);
        let invalid = Weights::embedded().get(feature::SIGNATURE_INVALID).unwrap().log_lr;
        assert!(f.log_lr < invalid, "{} should be below the tampering row {invalid}", f.log_lr);
        let mut plain = candidate_at("C:\\Users\\bob\\tool.exe");
        plain.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path("C:\\Users\\bob\\tool.exe"),
            ObservationKind::Signature(SignatureStatus::Unsigned),
        ));
        let unsigned: f64 = score(&plain, &Baseline::default()).iter().map(|x| x.log_lr).sum();
        let signed: f64 = e.iter().map(|x| x.log_lr).sum();
        assert!(signed > unsigned, "self-signed {signed} must beat unsigned {unsigned}");
    }

    #[test]
    fn stapling_on_your_own_certificate_never_lowers_the_score() {
        for status in [
            SignatureStatus::Untrusted { signer: "ACME".into(), self_signed_leaf: true },
            SignatureStatus::Untrusted { signer: "ACME".into(), self_signed_leaf: false },
        ] {
            for p in [
                "C:\\Windows\\System32\\evil.dll",
                "C:\\Program Files\\Thing\\evil.dll",
                "C:\\Users\\bob\\evil.exe",
            ] {
                let mut signed = candidate_at(p);
                signed.observe(Observation::about_path(
                    ArtifactSource::FileContent,
                    path(p),
                    ObservationKind::Signature(status.clone()),
                ));
                let mut plain = candidate_at(p);
                plain.observe(Observation::about_path(
                    ArtifactSource::FileContent,
                    path(p),
                    ObservationKind::Signature(SignatureStatus::Unsigned),
                ));
                let a: f64 = score(&signed, &Baseline::default()).iter().map(|x| x.log_lr).sum();
                let b: f64 = score(&plain, &Baseline::default()).iter().map(|x| x.log_lr).sum();
                assert!(a >= b, "{p} with {status:?} scored {a}, below unsigned's {b}");
            }
        }
    }

    #[test]
    fn tampering_is_never_out_scored_by_an_unrecognised_authority() {
        for p in [
            "C:\\Windows\\System32\\evil.dll",
            "C:\\Program Files\\Thing\\evil.dll",
            "C:\\Users\\bob\\evil.exe",
        ] {
            let mut tampered = candidate_at(p);
            tampered.observe(Observation::about_path(
                ArtifactSource::FileContent,
                path(p),
                ObservationKind::Signature(SignatureStatus::Invalid {
                    reason: "the file's SHA-256 Authenticode hash does not match".into(),
                }),
            ));
            let mut unknown_ca = candidate_at(p);
            unknown_ca.observe(Observation::about_path(
                ArtifactSource::FileContent,
                path(p),
                ObservationKind::Signature(SignatureStatus::Untrusted {
                    signer: "Contoso Internal".into(),
                    self_signed_leaf: false,
                }),
            ));
            let a: f64 = score(&tampered, &Baseline::default()).iter().map(|x| x.log_lr).sum();
            let b: f64 = score(&unknown_ca, &Baseline::default()).iter().map(|x| x.log_lr).sum();
            assert!(a >= b, "{p}: tampering {a} scored below an unrecognised CA {b}");
            if !p.starts_with("C:\\Windows") {
                assert!(a > b, "{p}: tampering {a} must beat an unrecognised CA {b}");
            }
        }
    }

    #[test]
    fn a_signature_we_could_not_check_scores_exactly_nothing() {
        let p = "C:\\Windows\\System32\\svchost.exe";
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::Signature(SignatureStatus::Unknown {
                reason: "CatRoot could not be read".into(),
            }),
        ));
        let e = score(&c, &Baseline::default());

        assert!(!fired(&e, feature::UNSIGNED_IN_SYSTEM_ZONE));
        assert!(!fired(&e, feature::SIGNATURE_INVALID));
        let total: f64 = e.iter().map(|x| x.log_lr).sum();
        assert_eq!(total, 0.0, "an unfinished check must be worth exactly zero: {e:#?}");

        let u = e.iter().find(|x| x.feature == feature::SIGNATURE_UNVERIFIABLE).unwrap();
        assert!(u.detail.contains("CatRoot could not be read"));
    }

    #[test]
    fn unsigned_is_weighted_by_where_the_file_lives() {
        let make = |p: &str| {
            let mut c = candidate_at(p);
            c.observe(Observation::about_path(
                ArtifactSource::FileContent,
                path(p),
                ObservationKind::Signature(SignatureStatus::Unsigned),
            ));
            score(&c, &Baseline::default())
        };
        assert!(fired(&make("C:\\Windows\\System32\\odd.exe"), feature::UNSIGNED_IN_SYSTEM_ZONE));
        assert!(fired(&make("C:\\Users\\bob\\odd.exe"), feature::UNSIGNED_IN_USER_ZONE));
    }

    #[test]
    fn persistence_maps_to_its_mechanism_and_carries_the_attack_id() {
        let mut c = candidate_at("C:\\Users\\bob\\x.exe");
        c.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "IFEO".into() },
            path("C:\\Users\\bob\\x.exe"),
            ObservationKind::Persistence {
                kind: PersistenceKind::ImageFileExecutionOptions,
                raw_value: "C:\\Users\\bob\\x.exe".into(),
            },
        ));
        let e = score(&c, &Baseline::default());
        let p = e.iter().find(|x| x.feature == feature::PERSISTENCE_IFEO).unwrap();
        assert!(p.detail.contains("T1546.012"));
    }

    #[test]
    fn a_com_redirection_outscores_an_ordinary_com_registration() {
        let scored = |kind| {
            let mut c = candidate_at("C:\\Users\\bob\\x.dll");
            c.observe(Observation::about_path(
                ArtifactSource::Registry {
                    hive: "UsrClass.dat (bob)".into(),
                    key: "CLSID\\{ab}\\InprocServer32\\(Default)".into(),
                },
                path("C:\\Users\\bob\\x.dll"),
                ObservationKind::Persistence { kind, raw_value: "C:\\Users\\bob\\x.dll".into() },
            ));
            score(&c, &Baseline::default())
        };

        let ordinary = scored(PersistenceKind::ComServer);
        let hijack = scored(PersistenceKind::ComHijack);
        assert!(fired(&ordinary, feature::PERSISTENCE_COM_SERVER));
        assert!(fired(&hijack, feature::PERSISTENCE_COM_HIJACK));
        assert!(!fired(&ordinary, feature::PERSISTENCE_COM_HIJACK));
        assert!(!fired(&hijack, feature::PERSISTENCE_COM_SERVER));

        let weight = |e: &[mm_core::Evidence], name: &str| {
            e.iter().find(|x| x.feature == name).unwrap().log_lr
        };
        let plain = weight(&ordinary, feature::PERSISTENCE_COM_SERVER);
        let redirect = weight(&hijack, feature::PERSISTENCE_COM_HIJACK);
        assert!(
            redirect >= plain + 3.0,
            "a redirection ({redirect}) must be worth materially more than a registration \
             ({plain}); collapsing them is what made 44% of a clean machine's candidates"
        );
        for (e, name) in [
            (&ordinary, feature::PERSISTENCE_COM_SERVER),
            (&hijack, feature::PERSISTENCE_COM_HIJACK),
        ] {
            assert!(e.iter().find(|x| x.feature == name).unwrap().detail.contains("T1546.015"));
        }
    }

    #[test]
    fn a_deleted_persistence_entry_scores_separately() {
        let mut c = candidate_at("C:\\Users\\bob\\x.exe");
        c.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "NTUSER.DAT".into(), key: "Run".into() },
            path("C:\\Users\\bob\\x.exe"),
            ObservationKind::Persistence {
                kind: PersistenceKind::RunKey,
                raw_value: "[deleted] C:\\Users\\bob\\x.exe".into(),
            },
        ));
        let e = score(&c, &Baseline::default());
        assert!(fired(&e, feature::PERSISTENCE_DELETED_ENTRY));
        assert!(fired(&e, feature::PERSISTENCE_RUN_KEY), "different groups, both should score");
    }

    fn downloaded(p: &str, zone: UrlZone, host: Option<&str>, referrer: Option<&str>) -> Candidate {
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::ZoneIdentifier,
            path(p),
            ObservationKind::DownloadedFrom {
                zone,
                host_url: host.map(str::to_string),
                referrer_url: referrer.map(str::to_string),
            },
        ));
        c
    }

    #[test]
    fn the_host_the_file_came_from_reaches_the_explanation() {
        let c = downloaded(
            "C:\\Users\\bob\\Downloads\\setup.exe",
            UrlZone::Internet,
            Some("https://cdn.evil.invalid/p/setup.exe"),
            Some("https://forum.invalid/thread"),
        );
        let e = score(&c, &Baseline::default());
        let d =
            &e.iter().find(|x| x.feature == feature::DOWNLOADED_FROM_INTERNET_ZONE).unwrap().detail;
        assert!(d.contains("cdn.evil.invalid"), "{d}");
        assert!(d.contains("forum.invalid"), "the referrer is a second pivot: {d}");
    }

    #[test]
    fn merely_having_been_downloaded_cannot_carry_a_candidate() {
        let mut c = downloaded(
            "C:\\Users\\bob\\Downloads\\setup.exe",
            UrlZone::Internet,
            Some("https://example.invalid/setup.exe"),
            None,
        );
        c.evidence = score(&c, &Baseline::default());
        assert!(
            c.probability() < 0.05,
            "a downloaded installer scored {:.3}: {:#?}",
            c.probability(),
            c.evidence
        );
    }

    #[test]
    fn the_restricted_zone_outweighs_the_internet_zone_without_accusing() {
        let internet = score(
            &downloaded("C:\\Users\\bob\\a.exe", UrlZone::Internet, None, None),
            &Baseline::default(),
        );
        let restricted = score(
            &downloaded("C:\\Users\\bob\\a.exe", UrlZone::Untrusted, None, None),
            &Baseline::default(),
        );

        let lr = |e: &[Evidence]| group_total(e, "provenance");
        assert!(lr(&restricted) > lr(&internet));
        assert!(lr(&restricted) < 3.0, "restricted-sites is not an accusation");
    }

    #[test]
    fn a_local_or_unstated_zone_scores_exactly_nothing() {
        for zone in [
            UrlZone::LocalMachine,
            UrlZone::LocalIntranet,
            UrlZone::Trusted,
            UrlZone::Other(9),
            UrlZone::Unstated,
        ] {
            let c = downloaded("C:\\Users\\bob\\a.exe", zone, Some("https://a.invalid/x"), None);
            let e = score(&c, &Baseline::default());
            let total = group_total(&e, "provenance");
            assert_eq!(total, 0.0, "{zone:?} moved the score: {e:#?}");

            let d =
                &e.iter().find(|x| x.feature == feature::DOWNLOAD_ORIGIN_RECORDED).unwrap().detail;
            assert!(d.contains("a.invalid"), "{d}");
        }
    }

    #[test]
    fn provenance_scores_alongside_location_and_signature() {
        let p = "C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe";
        let mut c = downloaded(p, UrlZone::Internet, Some("https://a.invalid/x.exe"), None);
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::Signature(SignatureStatus::Unsigned),
        ));
        let e = score(&c, &Baseline::default());
        assert!(fired(&e, feature::DOWNLOADED_FROM_INTERNET_ZONE));
        assert!(fired(&e, feature::EXECUTABLE_IN_USER_TEMP));
        assert!(fired(&e, feature::UNSIGNED_IN_USER_ZONE));
    }

    #[test]
    fn a_very_long_url_is_cut_before_it_reaches_a_report_line() {
        let url = format!("https://a.invalid/{}", "x".repeat(300));
        let c = downloaded("C:\\Users\\bob\\a.exe", UrlZone::Internet, Some(&url), None);
        let e = score(&c, &Baseline::default());
        let d =
            &e.iter().find(|x| x.feature == feature::DOWNLOADED_FROM_INTERNET_ZONE).unwrap().detail;
        assert!(d.chars().count() < 140, "{} chars: {d}", d.chars().count());
    }

    #[test]
    fn a_referrer_that_repeats_the_host_is_not_printed_twice() {
        let url = "https://a.invalid/x.exe";
        assert_eq!(describe_origin(Some(url), Some(url)), format!(": {url}"));
        assert_eq!(describe_origin(None, Some(url)), format!(", linked from {url}"));
        assert_eq!(describe_origin(None, None), "");
    }

    #[test]
    fn running_then_vanishing_within_minutes_is_self_deletion() {
        let ran = DateTime::from_timestamp(1_704_067_200, 0).unwrap();
        let mut c = candidate_at("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe");
        c.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"),
            ObservationKind::Executed { when: Some(ran), run_count: Some(1) },
        ));
        c.observe(Observation::about_path(
            ArtifactSource::UsnJournal,
            path("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"),
            ObservationKind::FileDeleted {
                when: Some(ran + Duration::seconds(40)),
                record: None,
                sequence: None,
            },
        ));
        let e = score(&c, &Baseline::default());
        let f = e.iter().find(|x| x.feature == feature::DELETED_SOON_AFTER_EXECUTION).unwrap();
        assert!(f.detail.contains("40 seconds"));
    }

    fn machine_with_an_incident() -> (Vec<Candidate>, DateTime<Utc>) {
        let ran = DateTime::from_timestamp(1_704_067_200, 0).unwrap();
        let p = "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe";

        let mut seed = candidate_at(p);
        seed.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(p),
            ObservationKind::Executed { when: Some(ran), run_count: Some(1) },
        ));
        seed.observe(Observation::about_path(
            ArtifactSource::UsnJournal,
            path(p),
            ObservationKind::FileDeleted {
                when: Some(ran + Duration::seconds(30)),
                record: None,
                sequence: None,
            },
        ));
        seed.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "NTUSER.DAT".into(), key: "Run".into() },
            path(p),
            ObservationKind::Persistence {
                kind: PersistenceKind::RunKey,
                raw_value: "[deleted] C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe".into(),
            },
        ));
        seed.id = mm_core::CandidateId(0);
        seed.prior_log_odds = -5.0;
        seed.evidence = extract(&seed, &Baseline::default(), &Weights::embedded());

        (vec![seed], ran)
    }

    fn created_at(id: u32, p: &str, when: DateTime<Utc>) -> Candidate {
        let mut c = candidate_at(p);
        c.id = mm_core::CandidateId(id);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(p),
            ObservationKind::FileExists {
                size: 2048,
                created: Some(when),
                modified: None,
                mft_modified: None,
                record: None,
            },
        ));
        c
    }

    fn window_for(candidates: &[Candidate]) -> IncidentWindow {
        match crate::window::IncidentWindow::detect(candidates, 0.5) {
            crate::window::Detection::Found(w) => w,
            other => panic!("expected a window: {other:?}"),
        }
    }

    #[test]
    fn a_file_created_in_the_burst_collects_the_window_weight() {
        let (mut candidates, ran) = machine_with_an_incident();
        candidates.push(created_at(
            1,
            "C:\\Users\\bob\\AppData\\Local\\Temp\\payload2.tmp",
            ran + Duration::seconds(12),
        ));

        let window = window_for(&candidates);
        let e = extract_with_window(
            &candidates[1],
            &Baseline::default(),
            &Weights::embedded(),
            Some(&window),
        );
        let hit = e
            .iter()
            .find(|x| x.feature == feature::CREATED_IN_INCIDENT_WINDOW)
            .expect("the neighbour should have collected it");
        assert!((hit.log_lr - 1.8).abs() < 1e-9);
        assert!(hit.detail.contains("2024-01-01"), "{}", hit.detail);
    }

    #[test]
    fn the_window_cannot_stack_with_the_lifecycle_evidence_that_produced_it() {
        let (mut candidates, ran) = machine_with_an_incident();

        let p = "C:\\Users\\bob\\AppData\\Local\\Temp\\stage2.exe";
        let mut neighbour = created_at(1, p, ran + Duration::seconds(5));
        neighbour.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(p),
            ObservationKind::Executed {
                when: Some(ran + Duration::seconds(6)),
                run_count: Some(1),
            },
        ));
        neighbour.observe(Observation::about_path(
            ArtifactSource::UsnJournal,
            path(p),
            ObservationKind::FileDeleted {
                when: Some(ran + Duration::seconds(20)),
                record: None,
                sequence: None,
            },
        ));
        candidates.push(neighbour);

        let window = window_for(&candidates);
        let weights = Weights::embedded();
        let e = extract_with_window(&candidates[1], &Baseline::default(), &weights, Some(&window));

        let lifecycle_group = &weights.get(feature::CREATED_IN_INCIDENT_WINDOW).unwrap().group;
        let in_group: Vec<&Evidence> = e
            .iter()
            .filter(|x| weights.get(&x.feature).map(|w| &w.group) == Some(lifecycle_group))
            .collect();
        assert_eq!(in_group.len(), 1, "one weight per group: {e:#?}");
        assert!(
            (in_group[0].log_lr - 5.3).abs() < 1e-9,
            "the stronger lifecycle weight must survive, got {:#?}",
            in_group[0]
        );
        assert!(in_group[0].detail.contains("burst of activity"), "{}", in_group[0].detail);
    }

    #[test]
    fn a_candidate_never_collects_the_window_its_own_timestamps_defined() {
        let (candidates, _) = machine_with_an_incident();
        let window = window_for(&candidates);
        let e = extract_with_window(
            &candidates[0],
            &Baseline::default(),
            &Weights::embedded(),
            Some(&window),
        );
        assert!(!fired(&e, feature::CREATED_IN_INCIDENT_WINDOW));
    }

    #[test]
    fn scoring_without_a_window_is_identical_to_the_first_pass() {
        let (mut candidates, ran) = machine_with_an_incident();
        candidates.push(created_at(1, "C:\\Users\\bob\\x.exe", ran));
        let plain = extract(&candidates[1], &Baseline::default(), &Weights::embedded());
        let none =
            extract_with_window(&candidates[1], &Baseline::default(), &Weights::embedded(), None);
        assert_eq!(plain.len(), none.len());
        assert!(!fired(&none, feature::CREATED_IN_INCIDENT_WINDOW));
    }

    #[test]
    fn re_scoring_with_the_window_is_idempotent() {
        let (mut candidates, ran) = machine_with_an_incident();
        candidates.push(created_at(1, "C:\\Users\\bob\\near.exe", ran + Duration::seconds(3)));
        let window = window_for(&candidates);

        let once = extract_with_window(
            &candidates[1],
            &Baseline::default(),
            &Weights::embedded(),
            Some(&window),
        );
        candidates[1].evidence = once.clone();
        let twice = extract_with_window(
            &candidates[1],
            &Baseline::default(),
            &Weights::embedded(),
            Some(&window),
        );

        let sum = |e: &[Evidence]| e.iter().map(|x| x.log_lr).sum::<f64>();
        assert_eq!(once.len(), twice.len());
        assert!((sum(&once) - sum(&twice)).abs() < 1e-12);
    }

    #[test]
    fn an_ordinary_signed_system_file_scores_near_zero() {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
        }
        for dir in ["System32", "WinSxS\\a", "WinSxS\\b"] {
            b.observe(&path(&format!("C:\\Windows\\{dir}\\svchost.exe")));
        }
        let baseline = b.build();

        let mut c = candidate_at("C:\\Windows\\System32\\svchost.exe");
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path("C:\\Windows\\System32\\svchost.exe"),
            ObservationKind::Signature(SignatureStatus::CatalogValid {
                signer: "Microsoft Windows".into(),
                catalog: "Package.cat".into(),
                root_is_microsoft: true,
            }),
        ));
        c.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path("C:\\Windows\\System32\\svchost.exe"),
            ObservationKind::Executed { when: None, run_count: Some(900) },
        ));
        c.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "SYSTEM".into(), key: "Services".into() },
            path("C:\\Windows\\System32\\svchost.exe"),
            ObservationKind::Persistence {
                kind: PersistenceKind::Service,
                raw_value: "C:\\Windows\\System32\\svchost.exe -k netsvcs".into(),
            },
        ));
        c.evidence = extract(&c, &baseline, &Weights::embedded());

        assert!(
            c.probability() < 0.05,
            "a signed service binary scored {:.3}: {:#?}",
            c.probability(),
            c.evidence
        );
    }

    #[test]
    fn a_realistic_dropper_scores_high() {
        let baseline = documents_baseline();
        let ran = DateTime::from_timestamp(1_704_067_200, 0).unwrap();
        let p = "C:\\Users\\bob\\Documents\\invoice.exe";

        let mut c = candidate_at(p);
        c.hash = FileHash::compute(b"payload");
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::Signature(SignatureStatus::Unsigned),
        ));
        c.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "NTUSER.DAT".into(), key: "Run".into() },
            path(p),
            ObservationKind::Persistence {
                kind: PersistenceKind::RunKey,
                raw_value: "[deleted] C:\\Users\\bob\\Documents\\invoice.exe".into(),
            },
        ));
        c.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(p),
            ObservationKind::Executed { when: Some(ran), run_count: Some(1) },
        ));
        c.observe(Observation::about_path(
            ArtifactSource::UsnJournal,
            path(p),
            ObservationKind::FileDeleted {
                when: Some(ran + Duration::seconds(30)),
                record: None,
                sequence: None,
            },
        ));
        c.evidence = extract(&c, &baseline, &Weights::embedded());

        assert!(
            c.probability() > 0.85,
            "the dropper only scored {:.3}: {:#?}",
            c.probability(),
            c.evidence
        );
        assert!(c.corroboration() >= 3);
    }

    fn arrived(p: &str, kind: mm_core::OutOfBandArrival) -> Candidate {
        let mut c = candidate_at(p);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(p),
            ObservationKind::ArrivedOutOfBand(kind),
        ));
        c
    }

    fn unsigned(c: &mut Candidate) {
        let p = c.path.clone().unwrap();
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            p,
            ObservationKind::Signature(mm_core::SignatureStatus::Unsigned),
        ));
    }

    #[test]
    fn a_system_directory_arrival_does_not_stack_with_being_unsigned() {
        let mut c = arrived(
            "C:\\Windows\\System32\\evil.dll",
            mm_core::OutOfBandArrival::NotAComponentStoreLink { hard_links: 1 },
        );
        unsigned(&mut c);

        let weights = Weights::embedded();
        let e = extract(&c, &Baseline::default(), &weights);
        let group = &weights.get(feature::INSTALLED_OUTSIDE_COMPONENT_STORE).unwrap().group;
        assert_eq!(group, "signature", "the measurement puts this row in the signature group");

        let surviving: Vec<&Evidence> =
            e.iter().filter(|x| weights.get(&x.feature).map(|w| &w.group) == Some(group)).collect();
        assert_eq!(surviving.len(), 1, "one weight per group: {e:#?}");
        assert!(
            (surviving[0].log_lr - 4.2).abs() < 1e-9,
            "the stronger signature claim must survive, got {:#?}",
            surviving[0]
        );
        assert!(
            surviving[0].detail.contains("component-store"),
            "the arrival must still be explained: {}",
            surviving[0].detail
        );
    }

    #[test]
    fn a_program_files_arrival_does_stack_with_being_unsigned() {
        let mut c = arrived(
            "C:\\Program Files\\Vendor\\uxtheme.dll",
            mm_core::OutOfBandArrival::AfterItsDirectory { days_later: 180 },
        );
        unsigned(&mut c);

        let weights = Weights::embedded();
        let e = extract(&c, &Baseline::default(), &weights);
        let arrival = e
            .iter()
            .find(|x| x.feature == feature::ARRIVED_AFTER_ITS_DIRECTORY)
            .expect("the arrival must be scored");
        let signature = e
            .iter()
            .find(|x| x.feature == feature::UNSIGNED_IN_PROGRAM_FILES)
            .expect("being unsigned must still be scored");
        assert_ne!(
            weights.get(&arrival.feature).unwrap().group,
            weights.get(&signature.feature).unwrap().group,
            "these two make different claims and must not share a group"
        );
        assert!((arrival.log_lr - 1.8).abs() < 1e-9, "{arrival:#?}");
        assert!(arrival.detail.contains("180"), "{}", arrival.detail);
    }

    #[test]
    fn a_microsoft_signed_file_that_arrived_out_of_band_keeps_its_exoneration() {
        let p = "C:\\Windows\\System32\\MpSigStub.exe";
        let mut c = arrived(p, mm_core::OutOfBandArrival::NotAComponentStoreLink { hard_links: 1 });
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(p),
            ObservationKind::Signature(mm_core::SignatureStatus::CatalogValid {
                signer: "Microsoft Windows".into(),
                catalog: "Package_1.cat".into(),
                root_is_microsoft: true,
            }),
        ));

        let weights = Weights::embedded();
        let e = extract(&c, &Baseline::default(), &weights);
        let signature = e
            .iter()
            .find(|x| weights.get(&x.feature).map(|w| w.group.as_str()) == Some("signature"))
            .expect("a signature verdict must be scored");
        assert_eq!(signature.feature, feature::SIGNED_MICROSOFT_CATALOG, "{e:#?}");
        assert!((signature.log_lr + 6.7).abs() < 1e-9, "{signature:#?}");
    }

    #[test]
    fn the_arrival_row_does_not_widen_the_signature_band() {
        let weights = Weights::embedded();
        assert!(
            (weights.max_log_lr_in_group(crate::weights::group::SIGNATURE) - 4.2).abs() < 1e-9,
            "the band must still be set by signature_invalid, not by the arrival row"
        );
        assert!(
            weights.get(feature::INSTALLED_OUTSIDE_COMPONENT_STORE).unwrap().log_lr < 4.2,
            "an arrival must never be the strongest thing the signature group can pay"
        );
    }

    #[test]
    fn an_arrival_alone_is_worth_less_than_being_unsigned() {
        let weights = Weights::embedded();
        let arrival = weights.get(feature::ARRIVED_AFTER_ITS_DIRECTORY).unwrap().log_lr;
        let unsigned = weights.get(feature::UNSIGNED_IN_PROGRAM_FILES).unwrap().log_lr;
        assert!(arrival > 0.0, "an arrival must still say something: {arrival}");
        assert!(
            arrival < 3.0,
            "an arrival alone must stay a lead: arrival {arrival}, unsigned {unsigned}"
        );

        let c = arrived(
            "C:\\Program Files\\Vendor\\uxtheme.dll",
            mm_core::OutOfBandArrival::AfterItsDirectory { days_later: 180 },
        );
        let mut scored = c.clone();
        scored.evidence = extract(&c, &Baseline::default(), &weights);
        assert!(
            scored.probability() < 0.5,
            "an arrival with nothing else must not be reportable: {:?}",
            scored.probability()
        );
    }
}
