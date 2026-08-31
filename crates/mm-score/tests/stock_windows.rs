use mm_core::{
    ArtifactSource, Candidate, CandidateId, NormalizedPath, Observation, ObservationKind,
    PersistenceKind,
};
use mm_score::baseline::BaselineBuilder;
use mm_score::machine::{self, Machine};
use mm_score::zone::{classify, Zone};
use mm_score::{Baseline, Weights};

fn vm_machines() -> Vec<&'static Machine> {
    machine::MEASURED_MACHINES
        .iter()
        .filter(|(path, _)| path.starts_with("VM_TESTS"))
        .map(|(_, m)| m)
        .collect()
}

fn hardest_vm_prior() -> f64 {
    vm_machines().iter().map(|m| m.prior()).fold(f64::INFINITY, f64::min)
}

fn tightest_vm_prior() -> f64 {
    vm_machines().iter().map(|m| m.prior()).fold(f64::NEG_INFINITY, f64::max)
}

fn laptop_prior() -> f64 {
    machine::MEASURED_MACHINES
        .iter()
        .find(|(path, _)| path.starts_with("malmathic-case"))
        .map(|(_, m)| m.prior())
        .expect("the laptop dataset is in the table")
}

const REALISTIC_PRIOR: f64 = -8.5;

fn path(p: &str) -> NormalizedPath {
    NormalizedPath::parse(p).unwrap()
}

fn baseline() -> Baseline {
    let mut b = BaselineBuilder::new();
    for i in 0..12_000 {
        b.observe(&path(&format!(r"C:\Windows\System32\f{i}.dll")));
    }
    for dir in [r"C:\Windows", r"C:\Windows\WinSxS\a", r"C:\Windows\WinSxS\b"] {
        b.observe(&path(&format!(r"{dir}\explorer.exe")));
    }
    b.build()
}

fn score_persistence(raw_value: &str, kind: PersistenceKind) -> Option<f64> {
    let path = NormalizedPath::from_command_line(raw_value)?;
    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "Winlogon".into() },
        path,
        ObservationKind::Persistence { kind, raw_value: raw_value.to_string() },
    ));
    candidate.evidence = mm_score::extract(&candidate, &baseline(), &Weights::embedded());
    Some(candidate.probability())
}

#[test]
fn the_stock_winlogon_shell_value_is_not_a_finding() {
    let p = score_persistence("explorer.exe", PersistenceKind::WinlogonShell).unwrap();
    assert!(p < 0.5, "stock Winlogon Shell scored {p:.4}");
}

#[test]
fn the_stock_userinit_value_is_not_a_finding() {
    let p =
        score_persistence(r"C:\Windows\system32\userinit.exe,", PersistenceKind::WinlogonUserinit)
            .unwrap();
    assert!(p < 0.5, "stock Userinit scored {p:.4}");
}

#[test]
fn stock_lsa_packages_are_not_findings() {
    for name in ["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u"] {
        let p = score_persistence(name, PersistenceKind::LsaProvider).unwrap();
        assert!(p < 0.5, "LSA package `{name}` scored {p:.4}");
    }
}

#[test]
fn a_genuine_winlogon_hijack_is_still_reported() {
    let p = score_persistence(
        r"C:\Users\bob\AppData\Roaming\explorer.exe",
        PersistenceKind::WinlogonShell,
    )
    .unwrap();
    assert!(p > 0.8, "a real Winlogon hijack only scored {p:.4}");

    let stock = score_persistence("explorer.exe", PersistenceKind::WinlogonShell).unwrap();
    assert!(p > stock * 10.0, "hijack {p:.4} vs stock {stock:.4} — not separated enough");
}

#[test]
fn a_real_volume_root_executable_is_still_recognized() {
    assert_eq!(classify(&path(r"C:\payload.exe")), Zone::VolumeRoot);
    assert_eq!(
        classify(&NormalizedPath::from_command_line("payload.exe").unwrap()),
        Zone::Unlocated
    );
}

#[test]
fn unlocated_paths_produce_no_location_evidence() {
    let p = NormalizedPath::from_command_line("explorer.exe").unwrap();
    assert!(!p.is_located());

    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "Winlogon".into() },
        p,
        ObservationKind::Persistence {
            kind: PersistenceKind::WinlogonShell,
            raw_value: "explorer.exe".into(),
        },
    ));
    let evidence = mm_score::extract(&candidate, &baseline(), &Weights::embedded());

    for name in [
        "executable_at_volume_root",
        "system_binary_name_outside_system_dir",
        "executable_in_user_temp",
        "executable_in_windows_temp",
    ] {
        assert!(
            !evidence.iter().any(|e| e.feature == name),
            "`{name}` fired on a value that recorded no location"
        );
    }
}

#[test]
fn non_ascii_profile_names_fold_to_one_key() {
    let lower = path(r"C:\Users\Администратор\AppData\Roaming\x.exe");
    let upper = path(r"C:\USERS\АДМИНИСТРАТОР\APPDATA\ROAMING\X.EXE");
    assert_eq!(lower.key(), upper.key(), "Cyrillic profile names did not fold");

    assert_eq!(classify(&lower), Zone::UserAppData);
    assert_eq!(classify(&upper), Zone::UserAppData);
}

#[test]
fn other_cased_scripts_fold_too() {
    for (a, b) in [
        (r"C:\Users\Ελληνικά\x.exe", r"C:\Users\ΕΛΛΗΝΙΚΆ\x.exe"),
        (r"C:\Users\Müller\x.exe", r"C:\Users\MÜLLER\x.exe"),
    ] {
        assert_eq!(path(a).key(), path(b).key(), "{a} vs {b}");
    }
}

#[test]
fn a_name_only_prefetch_entry_is_not_a_finding() {
    for name in ["STEAM.EXE", "RUSTUP.EXE", "CARGO-CLIPPY.EXE"] {
        let path = NormalizedPath::unlocated(name).unwrap();
        assert!(!path.is_located(), "{name}");
        assert_eq!(classify(&path), Zone::Unlocated, "{name}");

        let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
        candidate.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path,
            ObservationKind::Executed { when: None, run_count: Some(12) },
        ));
        candidate.evidence = mm_score::extract(&candidate, &baseline(), &Weights::embedded());

        let p = candidate.probability();
        assert!(p < 0.5, "{name} scored {p:.4}: {:#?}", candidate.evidence);

        for feature in [
            "executable_at_volume_root",
            "executed_but_now_absent",
            "executable_rare_for_zone_on_this_machine",
        ] {
            assert!(
                !candidate.evidence.iter().any(|e| e.feature == feature),
                "`{feature}` fired on {name}, which recorded no location"
            );
        }
    }
}

#[test]
fn a_real_volume_root_executable_still_scores() {
    let path = NormalizedPath::parse(r"C:\payload.exe").unwrap();
    assert!(path.is_located());
    assert_eq!(classify(&path), Zone::VolumeRoot);

    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.observe(Observation::about_path(
        ArtifactSource::Prefetch,
        path,
        ObservationKind::Executed { when: None, run_count: Some(1) },
    ));
    candidate.evidence = mm_score::extract(&candidate, &baseline(), &Weights::embedded());
    assert!(
        candidate.evidence.iter().any(|e| e.feature == "executable_at_volume_root"),
        "a real root executable stopped being noticed"
    );
}

const REAL_APPDATA_SOFTWARE: &[&str] = &[
    r"C:\Users\bob\AppData\Local\Discord\app-1.0.9250\Discord.exe",
    r"C:\Users\bob\AppData\Local\Discord\Update.exe",
    r"C:\Users\bob\AppData\Local\Microsoft\Teams\current\Teams.exe",
    r"C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe",
    r"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
    r"C:\Users\bob\AppData\Local\Programs\Python\Python311\Scripts\pip.exe",
    r"C:\Users\bob\AppData\Local\JetBrains\Installations\Rider261\lib\ReSharperHost\JetBrains.Platform.Installer.exe",
    r"C:\Users\bob\AppData\Roaming\Telegram Desktop\Telegram.exe",
    r"C:\Users\bob\AppData\Roaming\Spotify\Spotify.exe",
    r"C:\Users\bob\AppData\Roaming\npm\node_modules\npm\bin\npm.cmd",
];

fn score_executed(raw: &str) -> Candidate {
    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.observe(Observation::about_path(
        ArtifactSource::Amcache,
        path(raw),
        ObservationKind::Executed { when: None, run_count: Some(9) },
    ));
    candidate.evidence = mm_score::extract(&candidate, &baseline(), &Weights::embedded());
    candidate
}

#[test]
fn ordinary_software_installed_in_appdata_is_not_a_finding() {
    for raw in REAL_APPDATA_SOFTWARE {
        let candidate = score_executed(raw);
        let p = candidate.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", candidate.evidence);
        assert!(p < 0.2, "{raw} scored {p:.4}, uncomfortably close to a finding");
    }
}

#[test]
fn an_appdata_app_mid_update_is_still_not_a_finding() {
    for raw in [
        r"C:\Users\bob\AppData\Local\Discord\app-1.0.9244\Discord.exe",
        r"C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\old_Code.exe",
        r"C:\Users\bob\AppData\Roaming\Telegram Desktop\tupdates\temp\Telegram.exe",
    ] {
        let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
        candidate.observe(Observation::about_path(
            ArtifactSource::Amcache,
            path(raw),
            ObservationKind::Executed { when: None, run_count: Some(3) },
        ));
        candidate.observe(Observation::about_path(
            ArtifactSource::FileContent,
            path(raw),
            ObservationKind::Signature(mm_core::SignatureStatus::Unsigned),
        ));
        candidate.evidence = mm_score::extract(&candidate, &baseline(), &Weights::embedded());
        let p = candidate.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", candidate.evidence);
    }
}

#[test]
fn installers_sitting_in_downloads_are_not_findings() {
    for raw in [
        r"C:\Users\bob\Downloads\ChromeSetup.exe",
        r"C:\Users\bob\Downloads\python-3.11.0-amd64.exe",
        r"C:\Users\bob\Downloads\Git-2.54.0-64-bit.exe",
        r"C:\Users\bob\Downloads\7z2601-x64.exe",
        r"C:\Users\bob\Downloads\windowsdesktop-runtime-10.0.8-win-x64.exe",
    ] {
        let candidate = score_executed(raw);
        let p = candidate.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", candidate.evidence);
        assert!(p < 0.2, "{raw} scored {p:.4}, uncomfortably close to a finding");
    }
}

#[test]
fn a_dropper_in_appdata_roaming_now_clears_the_threshold() {
    let vm_prior = hardest_vm_prior();

    let dropper = |raw: &str| {
        let mut candidate = Candidate::new(CandidateId(0), vm_prior);
        candidate.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "NTUSER.DAT".into(), key: "Run".into() },
            path(raw),
            ObservationKind::Persistence {
                kind: PersistenceKind::RunKey,
                raw_value: raw.to_string(),
            },
        ));
        candidate.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(raw),
            ObservationKind::Executed { when: None, run_count: Some(1) },
        ));
        candidate.evidence = mm_score::extract(&candidate, &baseline(), &Weights::embedded());
        candidate
    };

    let roaming = dropper(r"C:\Users\bob\AppData\Roaming\svcupdate.exe");
    let p = roaming.probability();
    assert!(p >= 0.5, "the AppData\\Roaming dropper still scores {p:.4}: {:#?}", roaming.evidence);
    assert!(
        roaming.evidence.iter().any(|e| {
            e.feature == "executable_in_user_appdata"
                || e.feature == "persistence_targets_user_profile"
        }),
        "it cleared the threshold without any location weight — the test is measuring \
         something else: {:#?}",
        roaming.evidence
    );

    let temp = dropper(r"C:\Users\bob\AppData\Local\Temp\svcupdate.exe");
    let location_claim = |c: &Candidate| {
        c.evidence
            .iter()
            .filter(|e| {
                matches!(
                    e.feature.as_str(),
                    "persistence_targets_scratch_space"
                        | "persistence_targets_user_profile"
                        | "executable_in_user_temp"
                        | "executable_in_user_appdata"
                )
            })
            .map(|e| e.log_lr)
            .fold(0.0f64, f64::max)
    };
    assert!(
        location_claim(&temp) > location_claim(&roaming),
        "Temp's location claim ({:.1}) should still outrank AppData's ({:.1})",
        location_claim(&temp),
        location_claim(&roaming)
    );
    assert!(
        temp.probability() >= 0.5,
        "the Temp dropper stopped clearing the threshold at {:.4}: {:#?}",
        temp.probability(),
        temp.evidence
    );
}

#[test]
fn the_new_location_weights_stay_the_smallest_in_the_group() {
    let w = Weights::embedded();
    let of = |name: &str| w.get(name).expect(name).log_lr;

    let appdata = of("executable_in_user_appdata");
    let downloads = of("executable_in_user_downloads");

    for stronger in [
        "executable_in_user_temp",
        "executable_in_windows_temp",
        "executable_at_volume_root",
        "executable_in_recycle_bin",
        "executable_rare_for_zone_on_this_machine",
    ] {
        assert!(
            appdata < of(stronger),
            "AppData ({appdata}) must stay below {stronger} ({})",
            of(stronger)
        );
        assert!(
            downloads < of(stronger),
            "Downloads ({downloads}) must stay below {stronger} ({})",
            of(stronger)
        );
    }

    for name in ["executable_in_user_appdata", "executable_in_user_downloads"] {
        assert_eq!(w.get(name).unwrap().group, "location", "`{name}` left the location group");
        assert!(of(name) > 0.0, "`{name}` must still say something");
    }
}

#[test]
fn a_forged_shimcache_time_cannot_erase_a_self_deletion() {
    use chrono::{DateTime, Duration};

    let ran = DateTime::from_timestamp(1_773_522_300, 2_500_000).unwrap();
    let p = path(r"C:\Users\bob\AppData\Roaming\Fenix\fenix-agent.exe");

    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.observe(Observation::about_path(
        ArtifactSource::Prefetch,
        p.clone(),
        ObservationKind::Executed { when: Some(ran), run_count: Some(1) },
    ));
    candidate.observe(Observation::about_path(
        ArtifactSource::ShimCache,
        p.clone(),
        ObservationKind::Executed { when: Some(ran + Duration::days(365)), run_count: None },
    ));
    candidate.observe(Observation::about_path(
        ArtifactSource::Mft,
        p,
        ObservationKind::FileDeleted {
            when: Some(ran + Duration::seconds(40)),
            record: None,
            sequence: None,
        },
    ));

    candidate.evidence = mm_score::extract(&candidate, &baseline(), &Weights::embedded());
    assert!(
        candidate.evidence.iter().any(|e| e.feature == "deleted_soon_after_execution"),
        "the forged ShimCache time suppressed the self-deletion: {:#?}",
        candidate.evidence
    );
}

fn busy_machine_baseline() -> Baseline {
    let mut b = BaselineBuilder::new();
    for i in 0..12_000 {
        b.observe(&path(&format!(r"C:\Windows\System32\f{i}.dll")));
    }
    for dir in [r"C:\Windows", r"C:\Windows\WinSxS\a", r"C:\Windows\WinSxS\b"] {
        b.observe(&path(&format!(r"{dir}\explorer.exe")));
    }
    for i in 0..170 {
        b.observe(&path(&format!(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\p{i}.dll"
        )));
    }
    for i in 0..4_510 {
        b.observe(&path(&format!(r"C:\Windows\assembly\GAC_MSIL\a{i}\a{i}.dll")));
    }
    for i in 0..811 {
        b.observe(&path(&format!(r"C:\dnspy\bin\d{i}.dll")));
    }
    for i in 0..43_857 {
        b.observe(&path(&format!(r"C:\Users\bob\.vscode\extensions\e{i}\e{i}.exe")));
    }
    b.build()
}

#[test]
fn the_newly_weighted_zones_are_past_the_rarity_threshold_on_a_real_machine() {
    let b = busy_machine_baseline();
    for zone in [Zone::ProgramData, Zone::UserProfile, Zone::WindowsOther, Zone::Other] {
        assert!(
            b.zone_rarity(zone) > 5,
            "{:?} holds only {} executables here, so this baseline is testing the rarity \
             branch and not the fixed row",
            zone,
            b.zone_rarity(zone)
        );
    }
}

fn score_executed_on(raw: &str, baseline: &Baseline) -> Candidate {
    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.observe(Observation::about_path(
        ArtifactSource::Amcache,
        path(raw),
        ObservationKind::Executed { when: None, run_count: Some(9) },
    ));
    candidate.evidence = mm_score::extract(&candidate, baseline, &Weights::embedded());
    candidate
}

#[test]
fn ordinary_software_in_programdata_is_not_a_finding() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\NisSrv.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MpCmdRun.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MPUXAGENT.DLL",
        r"C:\ProgramData\Package Cache\{77169412-f642-45e7-b533-0c6f48de12f9}\vc_redist.x64.exe",
        r"C:\ProgramData\Vendor VPN\cache\vendor-update\vendor-2026.4-beta1.exe",
        r"C:\ProgramData\Microsoft\VisualStudio\Packages\vs_setup_bootstrapper.exe",
    ] {
        let candidate = score_executed_on(raw, &b);
        let p = candidate.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", candidate.evidence);
        assert!(p < 0.2, "{raw} scored {p:.4}, uncomfortably close to a finding");
    }
}

#[test]
fn ordinary_software_in_the_user_profile_is_not_a_finding() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\Users\bob\.vscode\extensions\vendor.editor-tools-1.4.0-win32-x64\resources\tool.exe",
        r"C:\Users\bob\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\cargo.exe",
        r"C:\Users\bob\.cache\runtimes\node.exe",
        r"C:\Users\bob\Documents\analyzer\analyzer.exe",
        r"C:\Users\bob\Desktop\setup.exe",
        r"C:\Users\bob\.local\bin\tool.exe",
        r"C:\Users\bob\scoop\apps\ripgrep\current\rg.exe",
    ] {
        let candidate = score_executed_on(raw, &b);
        let p = candidate.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", candidate.evidence);
        assert!(p < 0.2, "{raw} scored {p:.4}, uncomfortably close to a finding");
    }
}

#[test]
fn windows_update_and_updater_scratch_are_not_findings() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\Windows\SystemTemp\GoogleUpdater_chrome_Unpacker_BeginUnzipping4392\updater.exe",
        r"C:\Windows\SoftwareDistribution\Download\Install\AM_Delta_Patch_1.457.201.0.exe",
        r"C:\Windows\SoftwareDistribution\Download\Install\Windows-KB890830-x64-V5.144.exe",
        r"C:\Windows\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll",
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        r"C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe",
        r"C:\Windows\HelpPane.exe",
    ] {
        let candidate = score_executed_on(raw, &b);
        let p = candidate.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", candidate.evidence);
        assert!(p < 0.2, "{raw} scored {p:.4}, uncomfortably close to a finding");
    }
}

#[test]
fn stock_explorer_in_the_windows_directory_is_not_a_finding() {
    let vm_prior = tightest_vm_prior();
    let raw = r"%SystemRoot%\explorer.exe";

    let mut candidate = Candidate::new(CandidateId(0), vm_prior);
    candidate.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "CLSID".into() },
        path(raw),
        ObservationKind::Persistence {
            kind: PersistenceKind::ComServer,
            raw_value: raw.to_string(),
        },
    ));
    candidate.observe(Observation::about_path(
        ArtifactSource::FileContent,
        path(raw),
        ObservationKind::Signature(mm_core::SignatureStatus::CatalogValid {
            signer: "Microsoft Windows".into(),
            catalog: "Package.cat".into(),
            root_is_microsoft: false,
        }),
    ));
    candidate.evidence =
        mm_score::extract(&candidate, &busy_machine_baseline(), &Weights::embedded());
    let p = candidate.probability();
    assert!(p < 0.5, "stock explorer.exe scored {p:.4}: {:#?}", candidate.evidence);
    assert!(
        p < 0.05,
        "stock explorer.exe scored {p:.4}, far above what both clean machines showed"
    );
    assert!(
        !candidate.evidence.iter().any(|e| e.feature == "system_binary_name_outside_system_dir"),
        "the masquerade row fired on Explorer in Explorer's own directory: {:#?}",
        candidate.evidence
    );

    let mut blind = Candidate::new(CandidateId(0), vm_prior);
    blind.observe(Observation::about_path(
        ArtifactSource::FileContent,
        path(raw),
        ObservationKind::Signature(mm_core::SignatureStatus::Unknown {
            reason: "CatRoot could not be read".into(),
        }),
    ));
    blind.evidence = mm_score::extract(&blind, &busy_machine_baseline(), &Weights::embedded());
    let p = blind.probability();
    assert!(
        !blind.evidence.iter().any(|e| e.feature == "system_binary_name_outside_system_dir"),
        "the masquerade row fired on unverifiable stock Explorer — the WinRE case, \
         which is the one that matters: {:#?}",
        blind.evidence
    );
    assert!(
        p < 0.01,
        "unverifiable stock explorer.exe scored {p:.4}; it reached 0.116 under the old rule \
         and nothing but the missing masquerade row should be keeping it down: {:#?}",
        blind.evidence
    );
}

#[test]
fn a_system_binary_name_away_from_its_home_still_fires() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\Windows\Tasks\explorer.exe",
        r"C:\Windows\Debug\WIA\explorer.exe",
        r"C:\Windows\SystemTemp\explorer.exe",
        r"C:\Users\bob\AppData\Local\Temp\explorer.exe",
        r"C:\ProgramData\explorer.exe",
        r"C:\explorer.exe",
        r"C:\Windows\svchost.exe",
        r"C:\Windows\lsass.exe",
        r"C:\Windows\services.exe",
        r"C:\Windows\csrss.exe",
        r"C:\Windows\winlogon.exe",
        r"C:\Windows\smss.exe",
        r"C:\Windows\spoolsv.exe",
        r"C:\Windows\taskhostw.exe",
        r"C:\Windows\dwm.exe",
        r"C:\Windows\conhost.exe",
        r"C:\Windows\rundll32.exe",
        r"C:\Windows\regsvr32.exe",
        r"C:\Windows\wininit.exe",
        r"C:\Windows\userinit.exe",
        r"C:\Windows\ctfmon.exe",
        r"C:\Windows\dllhost.exe",
        r"C:\Windows\sihost.exe",
        r"C:\Windows\runtimebroker.exe",
        r"C:\Windows\taskhost.exe",
    ] {
        let candidate = score_executed_on(raw, &b);
        assert!(
            candidate.evidence.iter().any(|e| e.feature == "system_binary_name_outside_system_dir"),
            "the masquerade row did not fire on {raw}: {:#?}",
            candidate.evidence
        );
    }
}

#[test]
fn a_system_binary_name_at_home_is_silent() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\System32\lsass.exe",
        r"C:\Windows\System32\userinit.exe",
        r"C:\Windows\SysWOW64\explorer.exe",
        r"C:\Windows\SysWOW64\rundll32.exe",
        r"C:\Windows\SysWOW64\dllhost.exe",
        r"C:\Windows\WinSxS\amd64_microsoft-windows-winlogon_31bf3856ad364e35_10.0.26100.9168_none_0baaaac784db340f\winlogon.exe",
        r"C:\Windows\WinSxS\amd64_microsoft-windows-userinit_31bf3856ad364e35_10.0.26100.8972_none_77bb6b7a81d91217\r\userinit.exe",
        r"C:\Windows\explorer.exe",
        r"C:\WINDOWS\EXPLORER.EXE",
        r"%SystemRoot%\explorer.exe",
        r"%windir%\explorer.exe",
    ] {
        let candidate = score_executed_on(raw, &b);
        assert!(
            !candidate
                .evidence
                .iter()
                .any(|e| e.feature == "system_binary_name_outside_system_dir"),
            "the masquerade row accused {raw}, which is where Windows puts it: {:#?}",
            candidate.evidence
        );
    }
}

#[test]
fn the_system_scratch_directories_are_classified_as_temp() {
    for raw in [
        r"C:\Windows\Temp\a.exe",
        r"C:\Windows\SystemTemp\a.exe",
        r"C:\Windows\CbsTemp\a.exe",
        r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\a.exe",
        r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\a.exe",
    ] {
        assert_eq!(classify(&path(raw)), Zone::WindowsTemp, "{raw}");
    }

    for raw in [
        r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\a.exe",
        r"C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT",
        r"C:\Windows\ServiceProfiles\SomeOtherAccount\AppData\Local\Temp\a.exe",
        r"C:\Windows\SystemTemporary\a.exe",
        r"C:\Windows\Tasks\a.exe",
    ] {
        assert_eq!(classify(&path(raw)), Zone::WindowsOther, "{raw}");
    }
}

#[test]
fn system_scratch_directory_updaters_are_not_findings() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\Windows\SystemTemp\GoogleUpdater_chrome_Unpacker_BeginUnzipping4392_1797005037\151.0.7922.173_chrome_installer_uncompressed.exe",
        r"C:\Windows\SystemTemp\GoogleUpdater_chrome_Unpacker_BeginUnzipping15596_331614189\cr_4a6ca.tmp\setup.exe",
        r"C:\Windows\SystemTemp\google7860_403476743\bin\updater.exe",
        r"C:\Windows\SystemTemp\c034c76b-664e-43e6-86b2-7e0a54598fe5\MpRecovery.exe",
        r"C:\Windows\SystemTemp\c034c76b-664e-43e6-86b2-7e0a54598fe5\MpSigStub.exe",
        r"C:\Windows\Temp\{54106D84-F4CC-40B5-9660-909117B8066E}\.be\VC_redist.x64.exe",
        r"C:\Windows\CbsTemp\cbs.exe",
    ] {
        let candidate = score_executed_on(raw, &b);
        let p = candidate.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", candidate.evidence);
    }
}

#[test]
fn unsigned_managed_assemblies_in_the_framework_stores_are_not_findings() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\Windows\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll",
        r"C:\Windows\assembly\GAC_64\System.Data\v4.0_4.0.0.0__b77a5c561934e089\System.Data.dll",
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\PresentationFramework.dll",
        r"C:\Program Files\WindowsPowerShell\Modules\Pester\3.4.0\bin\Pester.dll",
        r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\Microsoft.Windows.SDK.dll",
        r"C:\Program Files (x86)\Steam\bin\cef\cef.win7x64\managed\SteamUI.dll",
    ] {
        let managed = score_unsigned_on(raw, true, &b);
        let p = managed.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", managed.evidence);
        assert!(
            managed.evidence.iter().any(|e| e.feature == "unsigned_managed_assembly"),
            "{raw} did not take the managed row: {:#?}",
            managed.evidence
        );

        let native = score_unsigned_on(raw, false, &b);
        let native_row = if raw.starts_with(r"C:\Program Files") {
            "unsigned_in_program_files"
        } else {
            "unsigned_in_system_zone"
        };
        assert!(
            native.evidence.iter().any(|e| e.feature == native_row),
            "the native twin of {raw} lost its zone's unsigned row: {:#?}",
            native.evidence
        );
        if native_row == "unsigned_in_system_zone" {
            assert!(
                native.probability() > p,
                "{raw}: native {:.4} did not outscore managed {p:.4}",
                native.probability()
            );
        } else {
            assert!(
                native.probability() < p,
                "{raw}: native {:.4} did not come in under managed {p:.4}",
                native.probability()
            );
        }
    }
}

#[test]
fn the_laptops_unsigned_conventional_zone_candidates_separate_by_image_kind() {
    let laptop_prior = laptop_prior();
    let b = busy_machine_baseline();

    let mut jetbrains = Candidate::new(CandidateId(0), laptop_prior);
    let jb = path(r"C:\Program Files\JetBrains\ETW Host\16\Updater\EtwHostServiceUpdater.exe");
    jetbrains.observe(Observation::about_path(
        ArtifactSource::ScheduledTask { file: "EtwHostServiceUpdater".into() },
        jb.clone(),
        ObservationKind::Persistence {
            kind: PersistenceKind::ScheduledTask,
            raw_value: jb.raw().to_string(),
        },
    ));
    jetbrains.observe(Observation::about_path(
        ArtifactSource::FileContent,
        jb.clone(),
        ObservationKind::Signature(mm_core::SignatureStatus::Unsigned),
    ));
    jetbrains.observe(Observation::about_path(
        ArtifactSource::FileContent,
        jb,
        ObservationKind::ManagedAssembly,
    ));
    jetbrains.evidence = mm_score::extract(&jetbrains, &b, &Weights::embedded());
    let managed_p = jetbrains.probability();
    assert!(
        managed_p < 0.05,
        "the clean laptop's #3 candidate still scores {managed_p:.4}: {:#?}",
        jetbrains.evidence
    );

    let mut imdisk = Candidate::new(CandidateId(0), laptop_prior);
    let im = path(r"%SystemRoot%\system32\imdsksvc.exe");
    imdisk.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SYSTEM".into(), key: "Services\\ImDisk".into() },
        im.clone(),
        ObservationKind::Persistence {
            kind: PersistenceKind::Service,
            raw_value: im.raw().to_string(),
        },
    ));
    imdisk.observe(Observation::about_path(
        ArtifactSource::FileContent,
        im,
        ObservationKind::Signature(mm_core::SignatureStatus::Unsigned),
    ));
    imdisk.evidence = mm_score::extract(&imdisk, &b, &Weights::embedded());
    assert!(
        imdisk.evidence.iter().any(|e| e.feature == "unsigned_in_system_zone"),
        "a native unsigned service binary lost the full weight: {:#?}",
        imdisk.evidence
    );
    assert!(
        imdisk.probability() > managed_p * 2.0,
        "native {:.4} and managed {managed_p:.4} are not separated",
        imdisk.probability()
    );
}

#[test]
fn a_managed_assembly_in_a_user_zone_keeps_the_user_zone_weight() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\Users\bob\AppData\Local\Temp\stage.dll",
        r"C:\Users\bob\Downloads\stage.exe",
        r"C:\ProgramData\stage.exe",
    ] {
        let managed = score_unsigned_on(raw, true, &b);
        assert!(
            managed.evidence.iter().any(|e| e.feature == "unsigned_in_user_zone"),
            "{raw} was discounted outside the zones where the census was taken: {:#?}",
            managed.evidence
        );
        assert!(
            !managed.evidence.iter().any(|e| e.feature == "unsigned_managed_assembly"),
            "{raw} took the managed row in a user zone: {:#?}",
            managed.evidence
        );
        let native = score_unsigned_on(raw, false, &b);
        assert_eq!(
            format!("{:.6}", native.probability()),
            format!("{:.6}", managed.probability()),
            "{raw}: being managed changed the score in a user zone"
        );
    }
}

fn score_unsigned_on(raw: &str, managed: bool, baseline: &Baseline) -> Candidate {
    let p = path(raw);
    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.observe(Observation::about_path(
        ArtifactSource::Mft,
        p.clone(),
        ObservationKind::FileExists {
            size: 262_144,
            created: None,
            modified: None,
            mft_modified: None,
            record: None,
        },
    ));
    candidate.observe(Observation::about_path(
        ArtifactSource::FileContent,
        p.clone(),
        ObservationKind::Signature(mm_core::SignatureStatus::Unsigned),
    ));
    if managed {
        candidate.observe(Observation::about_path(
            ArtifactSource::FileContent,
            p,
            ObservationKind::ManagedAssembly,
        ));
    }
    candidate.evidence = mm_score::extract(&candidate, baseline, &Weights::embedded());
    candidate
}

#[test]
fn portable_tools_outside_the_standard_zones_are_not_findings() {
    let b = busy_machine_baseline();
    for raw in [
        r"C:\Tools\PE-bear\PE-bear.exe",
        r"C:\Tools\WhoIs\whois64.exe",
        r"C:\autoruns\autoruns64.exe",
        r"C:\pestudio\pestudio.exe",
        r"C:\dnspy\bin\dnSpy.exe",
        r"D:\Games\steamapps\common\game\game.exe",
        r"W:\TRASH\Downloads\MediaCreationTool_22H2.exe",
        r"C:\$WinREAgent\Scratch\882E9142-5961-4F16-B0EE-267FFFF6807E\dismhost.exe",
    ] {
        let candidate = score_executed_on(raw, &b);
        let p = candidate.probability();
        assert!(p < 0.5, "{raw} scored {p:.4}: {:#?}", candidate.evidence);
        assert!(p < 0.2, "{raw} scored {p:.4}, uncomfortably close to a finding");
    }
}

#[test]
fn defenders_own_service_stays_far_below_the_threshold_from_winre() {
    let vm_prior = tightest_vm_prior();
    let raw = r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.26040.7-0\MpDefenderCoreService.exe";

    let mut candidate = Candidate::new(CandidateId(0), vm_prior);
    candidate.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SYSTEM".into(), key: "Services".into() },
        path(raw),
        ObservationKind::Persistence { kind: PersistenceKind::Service, raw_value: raw.to_string() },
    ));
    candidate.observe(Observation::about_path(
        ArtifactSource::FileContent,
        path(raw),
        ObservationKind::Signature(mm_core::SignatureStatus::Unknown {
            reason: "no catalog store reachable from the recovery environment".into(),
        }),
    ));
    candidate.evidence =
        mm_score::extract(&candidate, &busy_machine_baseline(), &Weights::embedded());

    let p = candidate.probability();
    assert!(p < 0.5, "Defender's own service scored {p:.4}: {:#?}", candidate.evidence);
    assert!(
        p < 0.35,
        "Defender's own service scored {p:.4} on a clean machine — the ProgramData row has \
         eaten the margin that keeps it off the report: {:#?}",
        candidate.evidence
    );
    assert!(
        candidate.evidence.iter().any(|e| e.feature == "executable_in_programdata"),
        "the location row did not fire, so this test is not measuring the margin it claims \
         to measure: {:#?}",
        candidate.evidence
    );
}

#[test]
fn a_service_dropper_in_programdata_now_clears_the_threshold() {
    let vm_prior = hardest_vm_prior();
    let raw = r"C:\ProgramData\SecuritySvc\wnhostsvc.exe";

    let mut candidate = Candidate::new(CandidateId(0), vm_prior);
    candidate.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SYSTEM".into(), key: "Services".into() },
        path(raw),
        ObservationKind::Persistence { kind: PersistenceKind::Service, raw_value: raw.to_string() },
    ));
    candidate.observe(Observation::about_path(
        ArtifactSource::Prefetch,
        path(raw),
        ObservationKind::Executed { when: None, run_count: Some(4) },
    ));
    candidate.evidence =
        mm_score::extract(&candidate, &busy_machine_baseline(), &Weights::embedded());

    let p = candidate.probability();
    assert!(
        p >= 0.5,
        "the ProgramData service dropper still scores {p:.4}: {:#?}",
        candidate.evidence
    );
    assert!(
        candidate.evidence.iter().any(|e| e.feature == "executable_in_programdata"),
        "it cleared without the location weight — this test is measuring something else: {:#?}",
        candidate.evidence
    );
}

#[test]
fn the_four_new_location_rows_are_placed_on_the_existing_scale() {
    let w = Weights::embedded();
    let of = |name: &str| w.get(name).expect(name).log_lr;

    let rare = of("executable_rare_for_zone_on_this_machine");
    let appdata = of("executable_in_user_appdata");
    let user_temp = of("executable_in_user_temp");

    for name in [
        "executable_in_programdata",
        "executable_in_user_profile",
        "executable_in_windows_directory",
        "executable_outside_standard_zones",
    ] {
        assert_eq!(w.get(name).unwrap().group, "location", "`{name}` left the location group");
        assert!(of(name) > 0.0, "`{name}` must say something or it is not worth a row");
        let programdata = name == "executable_in_programdata";
        if !programdata {
            assert!(
                of(name) <= rare,
                "`{name}` ({}) outranks the measured claim ({rare})",
                of(name)
            );
        }
        for stronger in [
            "executable_in_user_temp",
            "executable_in_windows_temp",
            "executable_at_volume_root",
            "executable_in_recycle_bin",
        ] {
            if programdata && of(stronger) == user_temp {
                assert!(
                    of(name) <= of(stronger),
                    "`{name}` ({}) passed {stronger} ({}) - a sanctioned install directory                      must not outrank a staging directory nothing is meant to persist in",
                    of(name),
                    of(stronger)
                );
                continue;
            }
            assert!(
                of(name) < of(stronger),
                "`{name}` ({}) must stay below {stronger} ({})",
                of(name),
                of(stronger)
            );
        }
    }

    for name in [
        "executable_in_user_profile",
        "executable_in_windows_directory",
        "executable_outside_standard_zones",
    ] {
        assert!(
            of(name) <= appdata,
            "`{name}` ({}) holds a large share of a clean machine's executables and must not \
             outrank AppData ({appdata})",
            of(name)
        );
    }
}

#[test]
fn every_zone_either_carries_a_location_weight_or_is_deliberately_silent() {
    let b = busy_machine_baseline();
    let w = Weights::embedded();
    let has_location = |c: &Candidate| {
        c.evidence.iter().any(|e| w.get(&e.feature).map(|x| x.group.as_str()) == Some("location"))
    };

    for (zone, raw) in [
        (Zone::UserTemp, r"C:\Users\bob\AppData\Local\Temp\x.exe"),
        (Zone::VolumeRoot, r"C:\x.exe"),
        (Zone::RecycleBin, r"C:\$Recycle.Bin\S-1-5-21-1\$RABCDEF.exe"),
        (Zone::WindowsTemp, r"C:\Windows\Temp\x.exe"),
        (Zone::UserAppData, r"C:\Users\bob\AppData\Roaming\x.exe"),
        (Zone::UserDownloads, r"C:\Users\bob\Downloads\x.exe"),
        (Zone::ProgramData, r"C:\ProgramData\Vendor\x.exe"),
        (Zone::UserProfile, r"C:\Users\bob\Desktop\x.exe"),
        (Zone::WindowsOther, r"C:\Windows\Tasks\x.exe"),
        (Zone::Other, r"D:\tools\x.exe"),
    ] {
        assert_eq!(classify(&path(raw)), zone, "{raw}");
        let candidate = score_executed_on(raw, &b);
        assert!(
            has_location(&candidate),
            "{raw} sits in {zone:?} and collected no location evidence at all: {:#?}",
            candidate.evidence
        );
    }

    for (zone, raw) in [
        (Zone::SystemDir, r"C:\Windows\System32\x.exe"),
        (Zone::WinSxs, r"C:\Windows\WinSxS\amd64_a\x.exe"),
        (Zone::ProgramFiles, r"C:\Program Files\Vendor\x.exe"),
    ] {
        assert_eq!(classify(&path(raw)), zone, "{raw}");
        let candidate = score_executed_on(raw, &b);
        assert!(
            !has_location(&candidate),
            "{raw} sits in {zone:?}, where software is meant to live, and collected location \
             evidence anyway: {:#?}",
            candidate.evidence
        );
    }
}

fn score_autostart(
    raw_value: &str,
    kind: PersistenceKind,
    signature: Option<mm_core::SignatureStatus>,
) -> f64 {
    score_autostart_at(REALISTIC_PRIOR, raw_value, kind, signature)
}

fn score_autostart_at(
    prior: f64,
    raw_value: &str,
    kind: PersistenceKind,
    signature: Option<mm_core::SignatureStatus>,
) -> f64 {
    let target = NormalizedPath::from_command_line(raw_value)
        .unwrap_or_else(|| panic!("`{raw_value}` must normalize to a path"));
    let mut candidate = Candidate::new(CandidateId(0), prior);
    candidate.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "autostart".into() },
        target.clone(),
        ObservationKind::Persistence { kind, raw_value: raw_value.to_string() },
    ));
    if let Some(status) = signature {
        candidate.observe(Observation::about_path(
            ArtifactSource::FileContent,
            target,
            ObservationKind::Signature(status),
        ));
    }
    candidate.evidence =
        mm_score::extract(&candidate, &busy_machine_baseline(), &Weights::embedded());
    candidate.probability()
}

fn signed_by(who: &str) -> Option<mm_core::SignatureStatus> {
    Some(mm_core::SignatureStatus::EmbeddedValid { signer: who.to_string() })
}

fn fired_interaction(candidate: &Candidate) -> Option<&str> {
    candidate
        .evidence
        .iter()
        .map(|e| e.feature.as_str())
        .find(|f| f.starts_with("persistence_targets_"))
}

fn autostart_only(raw: &str, kind: PersistenceKind) -> Candidate {
    let target = NormalizedPath::from_command_line(raw).unwrap();
    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "autostart".into() },
        target,
        ObservationKind::Persistence { kind, raw_value: raw.to_string() },
    ));
    candidate.evidence =
        mm_score::extract(&candidate, &busy_machine_baseline(), &Weights::embedded());
    candidate
}

#[test]
fn the_real_benign_autostart_entries_into_a_user_profile_are_not_findings() {
    for (raw, kind, signer) in [
        (
            r#""C:\Users\analyst\AppData\Local\Discord\Update.exe" --processStart Discord.exe"#,
            PersistenceKind::RunKey,
            "Discord Inc.",
        ),
        (
            r#""C:\Users\analyst\AppData\Local\FigmaAgent\figma_agent.exe""#,
            PersistenceKind::RunKey,
            "Figma, Inc.",
        ),
        (
            r#""C:\Users\analyst\AppData\Local\Google\GoogleUpdater\152.0.7933.0\updater.exe" --wake"#,
            PersistenceKind::RunKey,
            "Google LLC",
        ),
        (
            r"C:\Users\analyst\AppData\Local\Google\GoogleUpdater\152.0.7933.0\updater.exe",
            PersistenceKind::ScheduledTask,
            "Google LLC",
        ),
        (
            r"C:\Users\analyst\AppData\Local\PowerToys\PowerToys.exe",
            PersistenceKind::ScheduledTask,
            "Microsoft Corporation",
        ),
        (
            r"\??\C:\Users\analyst\Downloads\Sandboxie-Plus\SbieDrv.sys",
            PersistenceKind::Service,
            "David Xanatos",
        ),
    ] {
        let p = score_autostart(raw, kind, signed_by(signer));
        assert!(p < 0.5, "{raw} scored {p:.4} — a clean machine's own autostart entry");
        assert!(
            p < 0.1,
            "{raw} scored {p:.4}, uncomfortably close to a finding for a program signed by \
             {signer} that ships this way on purpose"
        );
    }
}

#[test]
fn the_real_benign_autostart_entries_survive_having_no_signature_verdict() {
    for (raw, kind) in [
        (r"C:\Users\analyst\AppData\Local\Discord\Update.exe", PersistenceKind::RunKey),
        (r"C:\Users\analyst\AppData\Local\FigmaAgent\figma_agent.exe", PersistenceKind::RunKey),
        (r"C:\Users\analyst\AppData\Local\PowerToys\PowerToys.exe", PersistenceKind::ScheduledTask),
        (r"\??\C:\Users\analyst\Downloads\Sandboxie-Plus\SbieDrv.sys", PersistenceKind::Service),
    ] {
        let p = score_autostart(raw, kind, None);
        assert!(
            p < 0.5,
            "{raw} scored {p:.4} with no signature read. These weights are now large enough \
             that an unread signature alone would decide whether a clean machine's own updater \
             is the top finding."
        );
    }
}

#[test]
fn windows_defender_in_programdata_does_not_collect_the_interaction() {
    for (raw, kind) in [
        (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe",
            PersistenceKind::Service,
        ),
        (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\NisSrv.exe",
            PersistenceKind::Service,
        ),
        (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MpDefenderCoreService.exe",
            PersistenceKind::Service,
        ),
        (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MpCmdRun.exe",
            PersistenceKind::ScheduledTask,
        ),
    ] {
        assert_eq!(classify(&path(raw)), Zone::ProgramData, "{raw}");
        let candidate = autostart_only(raw, kind);
        if let Some(f) = fired_interaction(&candidate) {
            panic!(
                "{raw} collected `{f}` — ProgramData is Defender's own home on every Windows \
                 machine and is excluded from the interaction on purpose"
            );
        }
        let p = candidate.probability();
        assert!(p < 0.25, "{raw} scored {p:.4}");
    }
}

#[test]
fn per_user_com_registrations_do_not_collect_the_interaction() {
    for raw in [
        r"C:\Users\analyst\AppData\Local\PowerToys\PowerToys.PowerRenameExt.dll",
        r"C:\Users\analyst\AppData\Local\PowerToys\WinUI3Apps\PowerToys.ImageResizerExt.dll",
        r"C:\Users\analyst\AppData\Local\PowerToys\PowerToys.MonacoPreviewHandlerCpp.dll",
        r"C:\Users\analyst\AppData\Local\Discord\app-1.0.9253\Discord.exe",
        r"C:\Users\analyst\AppData\Local\Chromium\Application\147.0.7727.137\notification_helper.exe",
        r"C:\Users\analyst\AppData\Local\camoufox\camoufox\Cache\notificationserver.dll",
        r"C:\Users\analyst\AppData\Local\Google\Chrome SxS\Application\154.0.8011.0\notification_helper.exe",
    ] {
        for kind in [PersistenceKind::ComServer, PersistenceKind::ComHijack] {
            let candidate = autostart_only(raw, kind);
            if let Some(f) = fired_interaction(&candidate) {
                panic!(
                    "{raw} registered as {kind:?} collected `{f}`; per-user COM registration is \
                     how PowerToys, Discord and Chromium all install themselves"
                );
            }
        }
    }
}

#[test]
fn an_autostart_value_with_no_location_collects_no_interaction() {
    for (raw, kind) in [
        ("explorer.exe", PersistenceKind::WinlogonShell),
        ("kerberos", PersistenceKind::LsaProvider),
        ("msv1_0", PersistenceKind::LsaProvider),
    ] {
        let target = NormalizedPath::from_command_line(raw).unwrap();
        assert_eq!(classify(&target), Zone::Unlocated, "{raw}");
        let candidate = autostart_only(raw, kind);
        if let Some(f) = fired_interaction(&candidate) {
            panic!("`{raw}` names no location at all and collected `{f}`");
        }
    }
}

#[test]
fn the_most_ordinary_shape_malware_takes_is_now_reported() {
    let vm_prior = hardest_vm_prior();

    for (raw, kind) in [
        (r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe", PersistenceKind::RunKey),
        (r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe", PersistenceKind::ScheduledTask),
        (r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe", PersistenceKind::Service),
        (r"C:\Users\Bob\Downloads\svcupdate.exe", PersistenceKind::RunKey),
        (r"C:\Users\Bob\Downloads\svcupdate.exe", PersistenceKind::ScheduledTask),
        (r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe", PersistenceKind::RunKey),
        (r"C:\Windows\Temp\svcupdate.exe", PersistenceKind::RunKey),
    ] {
        let p = score_autostart_at(vm_prior, raw, kind, Some(mm_core::SignatureStatus::Unsigned));
        assert!(p >= 0.5, "{raw} started by a {kind:?} scored {p:.4} and would not be reported");
    }

    let weakest = score_autostart(
        r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe",
        PersistenceKind::RunKey,
        Some(mm_core::SignatureStatus::Unsigned),
    );
    assert!(
        (0.40..0.50).contains(&weakest),
        "at a prior of {REALISTIC_PRIOR} the weakest cell scores {weakest:.4}; it was 0.475 when \
         these rows were measured, and if it has moved then the sensitivity table in the doc \
         comment above — and the claim in the weight table's rationale — is now wrong"
    );

    for raw in [r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe", r"C:\Windows\Temp\svcupdate.exe"]
    {
        let p =
            score_autostart(raw, PersistenceKind::RunKey, Some(mm_core::SignatureStatus::Unsigned));
        assert!(p >= 0.5, "{raw} scored {p:.4} even at the harsher prior it was meant to survive");
    }
}

#[test]
fn location_alone_does_not_collect_the_interaction() {
    let b = busy_machine_baseline();
    let w = Weights::embedded();
    for raw in [
        r"C:\Users\bob\AppData\Roaming\Vendor\x.exe",
        r"C:\Users\bob\Downloads\x.exe",
        r"C:\Users\bob\Desktop\x.exe",
        r"C:\Users\bob\AppData\Local\Temp\x.exe",
        r"C:\Windows\Temp\x.exe",
    ] {
        let candidate = score_executed_on(raw, &b);
        if let Some(f) = fired_interaction(&candidate) {
            panic!("{raw} has no autostart entry at all and collected `{f}`");
        }
    }

    assert_eq!(
        w.get("executable_in_user_appdata").unwrap().log_lr,
        1.5,
        "the marginal AppData row moved; 22% of a clean machine's executables live there"
    );
}

#[test]
fn the_interaction_rows_supersede_location_and_stack_with_the_mechanism() {
    let w = Weights::embedded();
    let profile = w.get("persistence_targets_user_profile").unwrap();
    let scratch = w.get("persistence_targets_scratch_space").unwrap();

    assert_eq!(profile.group, "location", "must supersede the plain location rows");
    assert_eq!(scratch.group, "location");

    for name in
        ["executable_in_user_appdata", "executable_in_user_downloads", "executable_in_user_profile"]
    {
        assert!(
            profile.log_lr > w.get(name).unwrap().log_lr,
            "`{name}` would win the group over the better-conditioned claim"
        );
    }
    for name in [
        "executable_in_user_temp",
        "executable_in_windows_temp",
        "executable_in_recycle_bin",
        "executable_at_volume_root",
    ] {
        assert!(scratch.log_lr > w.get(name).unwrap().log_lr, "`{name}` would win the group");
    }
    assert!(
        scratch.log_lr > profile.log_lr,
        "scratch space measured 0 benign autostart entries on both machines, a user profile 6"
    );

    for name in ["persistence_run_key", "persistence_service", "persistence_scheduled_task"] {
        assert_ne!(
            w.get(name).unwrap().group,
            profile.group,
            "`{name}` and the interaction must be able to stack — they are the two halves of \
             one conditional decomposition, not one fact stated twice"
        );
    }

    assert!(
        profile.log_lr < w.get("persistence_run_key").unwrap().log_lr,
        "the refinement outweighs the mechanism it refines"
    );
}

#[test]
fn the_appdata_and_downloads_rows_clear_the_threshold_at_the_vm_prior() {
    let vm_prior = hardest_vm_prior();

    let b = busy_machine_baseline();
    let w = Weights::embedded();
    let score = |raw: &str, kind: PersistenceKind| {
        let target = path(raw);
        let mut c = Candidate::new(CandidateId(0), vm_prior);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            target.clone(),
            ObservationKind::FileExists {
                size: 148_480,
                created: None,
                modified: None,
                mft_modified: None,
                record: None,
            },
        ));
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            target.clone(),
            ObservationKind::Signature(mm_core::SignatureStatus::Unsigned),
        ));
        c.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "NTUSER.DAT".into(), key: "Run".into() },
            target,
            ObservationKind::Persistence { kind, raw_value: raw.to_string() },
        ));
        c.evidence = mm_score::extract(&c, &b, &w);
        c.probability()
    };

    for (raw, kind, expected) in [
        (r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe", PersistenceKind::RunKey, 0.608),
        (
            r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe",
            PersistenceKind::ScheduledTask,
            0.698,
        ),
        (r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe", PersistenceKind::Service, 0.654),
        (r"C:\Users\Bob\Downloads\svcupdate.exe", PersistenceKind::RunKey, 0.608),
        (r"C:\Users\Bob\Downloads\svcupdate.exe", PersistenceKind::ScheduledTask, 0.698),
        (r"C:\Users\Bob\Downloads\svcupdate.exe", PersistenceKind::Service, 0.654),
    ] {
        let p = score(raw, kind);
        assert!(p >= 0.5, "{raw} + {kind:?} scored {p:.4}, still missed");
        assert!(
            (p - expected).abs() < 0.005,
            "{raw} + {kind:?} scored {p:.4}, but the weight table's rationale claims {expected:.3}"
        );
    }
}
