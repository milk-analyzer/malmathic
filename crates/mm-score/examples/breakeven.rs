use chrono::{Duration, TimeZone, Utc};
use mm_core::{
    ArtifactSource, Candidate, CandidateId, NormalizedPath, Observation, ObservationKind,
    PersistenceKind, SignatureStatus,
};
use mm_score::baseline::BaselineBuilder;
use mm_score::{Baseline, Weights};

fn path(p: &str) -> NormalizedPath {
    NormalizedPath::parse(p).unwrap()
}

fn baseline() -> Baseline {
    let mut b = BaselineBuilder::new();
    for i in 0..12_000 {
        b.observe(&path(&format!(r"C:\Windows\System32\f{i}.dll")));
    }
    for dir in [
        r"C:\Users\Bob\AppData\Roaming\Vendor",
        r"C:\Users\Bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        r"C:\Users\Bob\AppData\Local\Temp",
        r"C:\Users\Bob\Downloads",
        r"C:\ProgramData\Vendor",
        r"C:\Program Files\Vendor",
    ] {
        for i in 0..20 {
            b.observe(&path(&format!(r"{dir}\neighbour{i}.exe")));
            b.observe(&path(&format!(r"{dir}\readme{i}.txt")));
        }
    }
    for i in 0..20 {
        b.observe(&path(&format!(r"C:\Users\Bob\Documents\Reports\q{i}.docx")));
    }
    b.observe(&path(r"C:\Users\Bob\Documents\Reports\svcupdate.exe"));
    b.build()
}

#[derive(Clone, Copy, PartialEq)]
enum Fate {
    OnDisk,
    ExecutedNowAbsent,
    SelfDeleted,
}

#[derive(Clone, Copy, PartialEq)]
enum Extra {
    None,
    Packed,
}

fn arrival_for(p: &NormalizedPath) -> Option<mm_core::OutOfBandArrival> {
    match mm_score::zone::classify(p) {
        mm_score::zone::Zone::SystemDir => {
            Some(mm_core::OutOfBandArrival::NotAComponentStoreLink { hard_links: 1 })
        }
        mm_score::zone::Zone::ProgramFiles => {
            Some(mm_core::OutOfBandArrival::AfterItsDirectory { days_later: 180 })
        }
        _ => None,
    }
}

fn build(file: &str, persistence: Option<PersistenceKind>, fate: Fate, extra: Extra) -> Candidate {
    let p = path(file);
    let mut c = Candidate::new(CandidateId(0), 0.0);
    let ran = Utc.with_ymd_and_hms(2026, 8, 20, 14, 3, 11).unwrap();

    match fate {
        Fate::OnDisk => {
            c.observe(Observation::about_path(
                ArtifactSource::Mft,
                p.clone(),
                ObservationKind::FileExists {
                    size: 148_480,
                    created: Some(ran - Duration::minutes(4)),
                    modified: Some(ran - Duration::minutes(4)),
                    mft_modified: Some(ran - Duration::minutes(4)),
                    record: None,
                },
            ));
            c.observe(Observation::about_path(
                ArtifactSource::FileContent,
                p.clone(),
                ObservationKind::Signature(SignatureStatus::Unsigned),
            ));
            if let Some(arrival) = arrival_for(&p) {
                c.observe(Observation::about_path(
                    ArtifactSource::Mft,
                    p.clone(),
                    ObservationKind::ArrivedOutOfBand(arrival),
                ));
            }
        }
        Fate::ExecutedNowAbsent => c.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            p.clone(),
            ObservationKind::Executed { when: Some(ran), run_count: Some(1) },
        )),
        Fate::SelfDeleted => {
            c.observe(Observation::about_path(
                ArtifactSource::Prefetch,
                p.clone(),
                ObservationKind::Executed { when: Some(ran), run_count: Some(1) },
            ));
            c.observe(Observation::about_path(
                ArtifactSource::Mft,
                p.clone(),
                ObservationKind::FileDeleted {
                    when: Some(ran + Duration::seconds(90)),
                    record: Some(4242),
                    sequence: None,
                },
            ));
        }
    }

    if let Some(kind) = persistence {
        c.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "persistence".into() },
            p.clone(),
            ObservationKind::Persistence { kind, raw_value: p.raw().to_string() },
        ));
    }

    if extra == Extra::Packed {
        c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            p,
            ObservationKind::PeAnomaly {
                detail: "section .text has entropy 7.91 (T1027.002)".into(),
            },
        ));
    }

    c
}

const ROWS: &[(&str, &str)] = &[
    (r"AppData\Roaming", r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe"),
    (r"AppData\Local\Temp", r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe"),
    ("Downloads", r"C:\Users\Bob\Downloads\svcupdate.exe"),
    (
        "in Startup folder",
        r"C:\Users\Bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\svcupdate.exe",
    ),
    ("ProgramData", r"C:\ProgramData\Vendor\svcupdate.exe"),
    ("Program Files", r"C:\Program Files\Vendor\svcupdate.exe"),
    (r"Windows\SystemTemp", r"C:\Windows\SystemTemp\svcupdate.exe"),
    ("side-load PF dll", r"C:\Program Files\Vendor\uxtheme.dll"),
    ("side-load Sys32 dll", r"C:\Windows\System32\uxtheme.dll"),
];

const COLUMNS: &[(&str, Option<PersistenceKind>)] = &[
    ("none", None),
    ("Run/Startup", Some(PersistenceKind::RunKey)),
    ("task", Some(PersistenceKind::ScheduledTask)),
    ("service", Some(PersistenceKind::Service)),
    ("COM hijack", Some(PersistenceKind::ComHijack)),
];

fn n_star(w: f64) -> String {
    let n = w.exp();
    if n < 1.0 {
        "never".to_string()
    } else if n >= 1.0e9 {
        format!("{n:.0e}")
    } else {
        format!("{n:.0}")
    }
}

fn table(title: &str, fate: Fate, extra: Extra, baseline: &Baseline, weights: &Weights) {
    println!("-- {title} --");
    println!(
        "   W = evidence sum;  N* = e^W = the largest candidate population that still reports it"
    );
    print!("{:<22}", "");
    for (name, _) in COLUMNS {
        print!("{name:>20}");
    }
    println!();
    for (label, file) in ROWS {
        print!("{label:<22}");
        for (_, kind) in COLUMNS {
            let mut c = build(file, *kind, fate, extra);
            c.evidence = mm_score::extract(&c, baseline, weights);
            let w = c.logit();
            print!("{:>12}{:>8}", format!("W={w:.1}"), n_star(w));
        }
        println!();
    }
    println!();
}

fn main() {
    let baseline = baseline();
    let weights = Weights::embedded();

    println!("reference laptop: 17,847 candidates -> prior -9.7896  (self-excluded)");
    println!("                  18,840 candidates -> prior -9.8437  (unfiltered; 993 of them");
    println!(
        "                                                       this project's own build tree."
    );
    println!("                                                       RECORD ONLY: the report that");
    println!(
        "                                                       produced this row was destroyed"
    );
    println!(
        "                                                       2026-08-27 and cannot be re-run.)"
    );
    println!("VM, live elevated:  2,256 candidates -> prior -7.7213");
    println!("VM, from WinRE:     2,371 candidates -> prior -7.7711  (same volume, 4 min later)");
    println!("VM, live, corrected 9,918 effective   -> prior -9.2021  (+7,662 records the walk");
    println!("                                                        could not place)\n");

    table("STILL ON DISK, unsigned, name unique", Fate::OnDisk, Extra::None, &baseline, &weights);
    table(
        "STILL ON DISK, unsigned, name unique, PACKED",
        Fate::OnDisk,
        Extra::Packed,
        &baseline,
        &weights,
    );
    table("RAN ONCE AND VANISHED", Fate::ExecutedNowAbsent, Extra::None, &baseline, &weights);
    table("RAN ONCE AND DELETED ITSELF", Fate::SelfDeleted, Extra::None, &baseline, &weights);

    println!("-- the cells near the line, across plausible candidate populations --");
    let watched: &[(&str, &str, Option<PersistenceKind>)] = &[
        (
            "ProgramData + service",
            r"C:\ProgramData\Vendor\svcupdate.exe",
            Some(PersistenceKind::Service),
        ),
        (
            "ProgramData + Run key",
            r"C:\ProgramData\Vendor\svcupdate.exe",
            Some(PersistenceKind::RunKey),
        ),
        (
            "Sys32 side-load + service",
            r"C:\Windows\System32\uxtheme.dll",
            Some(PersistenceKind::Service),
        ),
        (
            "Program Files + task",
            r"C:\Program Files\Vendor\svcupdate.exe",
            Some(PersistenceKind::ScheduledTask),
        ),
        (
            "Program Files + service",
            r"C:\Program Files\Vendor\svcupdate.exe",
            Some(PersistenceKind::Service),
        ),
        (
            "Program Files + Run key",
            r"C:\Program Files\Vendor\svcupdate.exe",
            Some(PersistenceKind::RunKey),
        ),
        (
            r"AppData\Roaming + Run key",
            r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe",
            Some(PersistenceKind::RunKey),
        ),
    ];
    const POPULATIONS: &[f64] = &[1500.0, 2256.0, 2371.0, 3000.0, 5000.0, 9918.0, 17847.0, 50000.0];
    print!("{:<28}", "");
    for n in POPULATIONS {
        print!("{:>9.0}", n);
    }
    println!();
    for (label, file, kind) in watched {
        print!("{label:<28}");
        let mut c = build(file, *kind, Fate::OnDisk, Extra::None);
        c.evidence = mm_score::extract(&c, &baseline, &weights);
        let w = c.logit();
        for n in POPULATIONS {
            let logit = w - n.ln();
            let p = 1.0 / (1.0 + (-logit).exp());
            print!("{:>8.3}{}", p, if p >= 0.5 { "*" } else { " " });
        }
        println!("   W={w:.1}  N*={}", n_star(w));
    }
}
