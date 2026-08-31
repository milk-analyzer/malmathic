use chrono::{Duration, TimeZone, Utc};
use mm_core::{
    ArtifactSource, Candidate, CandidateId, NormalizedPath, Observation, ObservationKind,
    PersistenceKind, SignatureStatus,
};
use mm_score::baseline::BaselineBuilder;
use mm_score::{Baseline, Weights};

const DEFAULT_PRIOR: f64 = -7.6700;

const THRESHOLD: f64 = 0.5;

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

fn baseline_with_one_compressed(compressed: &str) -> Baseline {
    let mut b = BaselineBuilder::new();
    for i in 0..12_000 {
        b.observe(&path(&format!(r"C:\Windows\System32\f{i}.dll")));
    }
    for dir in [
        r"C:\Users\Bob\AppData\Roaming\Vendor",
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
    b.observe_file(&path(compressed), true);
    b.build()
}

fn baseline_with_decoys(payload: &str, n: usize, conventional: bool) -> Baseline {
    let name = path(payload).file_name().expect("a payload has a name").to_string();
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
        r"C:\Windows\SystemTemp",
        r"C:\Windows\SystemTemp\GoogleUpdater_Unpacker_1",
    ] {
        for i in 0..20 {
            b.observe(&path(&format!(r"{dir}\neighbour{i}.exe")));
            b.observe(&path(&format!(r"{dir}\readme{i}.txt")));
        }
    }
    for i in 0..20 {
        b.observe(&path(&format!(r"C:\Users\Bob\Documents\Reports\q{i}.docx")));
    }
    b.observe(&path(payload));
    for i in 0..n {
        let decoy = if conventional {
            format!(r"C:\Program Files\Decoy{i}\{name}")
        } else {
            format!(r"C:\Users\Bob\AppData\Local\Decoy{i}\{name}")
        };
        for j in 0..12 {
            let sibling = if conventional {
                format!(r"C:\Program Files\Decoy{i}\lib{j}.dll")
            } else {
                format!(r"C:\Users\Bob\AppData\Local\Decoy{i}\data{j}.dat")
            };
            b.observe(&path(&sibling));
        }
        b.observe(&path(&decoy));
    }
    b.build()
}

struct Row {
    label: &'static str,
    file: &'static str,
}

const ROWS: &[Row] = &[
    Row { label: r"AppData\Roaming", file: r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe" },
    Row { label: r"AppData\Local\Temp", file: r"C:\Users\Bob\AppData\Local\Temp\svcupdate.exe" },
    Row { label: "Downloads", file: r"C:\Users\Bob\Downloads\svcupdate.exe" },
    Row {
        label: "in Startup folder",
        file: r"C:\Users\Bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\svcupdate.exe",
    },
    Row { label: "ProgramData", file: r"C:\ProgramData\Vendor\svcupdate.exe" },
    Row { label: "Program Files", file: r"C:\Program Files\Vendor\svcupdate.exe" },
    Row { label: r"Windows\SystemTemp", file: r"C:\Windows\SystemTemp\svcupdate.exe" },
    Row {
        label: r"Windows\SystemTemp\unpack",
        file: r"C:\Windows\SystemTemp\GoogleUpdater_Unpacker_1\svcupdate.exe",
    },
    Row { label: "side-loaded DLL", file: r"C:\Program Files\Vendor\uxtheme.dll" },
];

const COLUMNS: &[(&str, Option<PersistenceKind>)] = &[
    ("none", None),
    ("Run key", Some(PersistenceKind::RunKey)),
    ("Startup", Some(PersistenceKind::StartupFolder)),
    ("task", Some(PersistenceKind::ScheduledTask)),
    ("service", Some(PersistenceKind::Service)),
    ("Winlogon", Some(PersistenceKind::WinlogonShell)),
];

#[derive(Clone, Copy, PartialEq)]
enum Fate {
    OnDisk,
    ExecutedNowAbsent,
    SelfDeleted,
}

#[derive(Clone, Copy)]
enum Extra {
    None,
    RandomName,
    Packed,
    Timestomped,
    MarkOfTheWeb,
    LoneAmongDocuments,
    Managed,
    ManagedPacked,
    CompactOsLzx,
    CompactOsUnreadable,
}

fn build(
    file: &str,
    persistence: Option<PersistenceKind>,
    fate: Fate,
    extra: Extra,
    prior: f64,
) -> Candidate {
    let p = match extra {
        Extra::RandomName => {
            let replaced = file
                .replace("svcupdate.exe", "a3f91c4e2b8d07f6.exe")
                .replace("uxtheme.dll", "a3f91c4e2b8d07f6.dll");
            path(&replaced)
        }
        Extra::LoneAmongDocuments => path(
            &file
                .replace(r"C:\Users\Bob\AppData\Roaming\Vendor", r"C:\Users\Bob\Documents\Reports"),
        ),
        _ => path(file),
    };

    let mut c = Candidate::new(CandidateId(0), prior);
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
            if matches!(extra, Extra::CompactOsLzx) {
                c.observe(Observation::about_path(
                    ArtifactSource::Mft,
                    p.clone(),
                    ObservationKind::CompactOsCompressed {
                        algorithm: "LZX".into(),
                        readable: true,
                    },
                ));
                c.observe(Observation::about_path(
                    ArtifactSource::FileContent,
                    p.clone(),
                    ObservationKind::Signature(SignatureStatus::Unsigned),
                ));
            } else if matches!(extra, Extra::CompactOsUnreadable) {
                c.observe(Observation::about_path(
                    ArtifactSource::Mft,
                    p.clone(),
                    ObservationKind::CompactOsCompressed {
                        algorithm: "WIM-backed".into(),
                        readable: false,
                    },
                ));
                c.observe(Observation::about_path(
                    ArtifactSource::FileContent,
                    p.clone(),
                    ObservationKind::Signature(SignatureStatus::Unknown {
                        reason: "the file is Compact-OS backed by a WIM image elsewhere on the \
                                 volume, so its bytes are not in the file itself"
                            .into(),
                    }),
                ));
            } else {
                c.observe(Observation::about_path(
                    ArtifactSource::FileContent,
                    p.clone(),
                    ObservationKind::Signature(SignatureStatus::Unsigned),
                ));
            }
            if let Some(arrival) = arrival_for(&p) {
                c.observe(Observation::about_path(
                    ArtifactSource::Mft,
                    p.clone(),
                    ObservationKind::ArrivedOutOfBand(arrival),
                ));
            }
        }
        Fate::ExecutedNowAbsent => {
            c.observe(Observation::about_path(
                ArtifactSource::Prefetch,
                p.clone(),
                ObservationKind::Executed { when: Some(ran), run_count: Some(1) },
            ));
        }
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

    match extra {
        Extra::Packed => c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            p,
            ObservationKind::PeAnomaly {
                detail: "section .text has entropy 7.91 (T1027.002)".into(),
            },
        )),
        Extra::Timestomped => c.observe(Observation::about_path(
            ArtifactSource::Mft,
            p,
            ObservationKind::PeAnomaly {
                detail:
                    "$SI creation time precedes $FN and has no sub-second component (T1070.006)"
                        .into(),
            },
        )),
        Extra::Managed => c.observe(Observation::about_path(
            ArtifactSource::FileContent,
            p,
            ObservationKind::ManagedAssembly,
        )),
        Extra::ManagedPacked => {
            c.observe(Observation::about_path(
                ArtifactSource::FileContent,
                p.clone(),
                ObservationKind::ManagedAssembly,
            ));
            c.observe(Observation::about_path(
                ArtifactSource::FileContent,
                p,
                ObservationKind::PeAnomaly {
                    detail: "section .text has entropy 7.91 (T1027.002)".into(),
                },
            ));
        }
        Extra::MarkOfTheWeb => c.observe(Observation::about_path(
            ArtifactSource::ZoneIdentifier,
            p,
            ObservationKind::DownloadedFrom {
                zone: mm_core::UrlZone::Internet,
                host_url: Some("http://example.invalid/x.exe".into()),
                referrer_url: None,
            },
        )),
        _ => {}
    }

    c
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

fn score(c: &mut Candidate, baseline: &Baseline, weights: &Weights) -> f64 {
    c.evidence = mm_score::extract(c, baseline, weights);
    c.probability()
}

fn score_under_the_old_name_rule(c: &mut Candidate, baseline: &Baseline, weights: &Weights) -> f64 {
    let fresh = mm_score::extract(c, baseline, weights);
    let mut set = mm_score::weights::EvidenceSet::new();
    for e in fresh {
        set.offer(weights, &e.feature, e.detail, e.sources);
    }
    if let Some(p) = &c.path {
        if let Some(name) = p.file_name() {
            let n = baseline.name_occurrences(name);
            if n >= 3 && baseline.name_occurrences_in_conventional_zones(name) == 0 {
                set.offer(
                    weights,
                    "name_recurs_on_machine",
                    format!("`{name}` appears {n} times on this machine"),
                    vec![],
                );
            }
        }
    }
    c.evidence = set.into_evidence();
    c.probability()
}

fn mark(p: f64) -> &'static str {
    if p >= THRESHOLD {
        "*"
    } else {
        " "
    }
}

fn main() {
    let prior: f64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(DEFAULT_PRIOR);
    let baseline = baseline();
    let weights = Weights::embedded();

    println!("prior = {prior:.4}   threshold = {THRESHOLD}   `*` = reported\n");

    for (fate, title) in [
        (Fate::OnDisk, "STILL ON DISK, unsigned, name unique"),
        (
            Fate::ExecutedNowAbsent,
            "RAN ONCE AND VANISHED (execution artifact, no file, no deletion time)",
        ),
        (Fate::SelfDeleted, "RAN ONCE AND DELETED ITSELF (deletion timed within ten minutes)"),
    ] {
        println!("-- {title} --");
        print!("{:<20}", "");
        for (name, _) in COLUMNS {
            print!("{name:>16}");
        }
        println!();
        for row in ROWS {
            print!("{:<20}", row.label);
            for (_, kind) in COLUMNS {
                let mut c = build(row.file, *kind, fate, Extra::None, prior);
                let p = score(&mut c, &baseline, &weights);
                print!("{:>15.3}{}", p, mark(p));
            }
            println!();
        }
        println!();
    }

    println!("-- one more fact, on top of STILL ON DISK + the named persistence --");
    print!("{:<20}", "");
    for (name, _) in COLUMNS {
        print!("{name:>16}");
    }
    println!();
    for (extra, label) in [
        (Extra::RandomName, "+ random name"),
        (Extra::Packed, "+ packed"),
        (Extra::Timestomped, "+ timestomped"),
        (Extra::MarkOfTheWeb, "+ MotW internet"),
        (Extra::Managed, "+ managed .NET"),
        (Extra::ManagedPacked, "+ managed .NET, packed"),
    ] {
        for row in ROWS {
            print!("{:<20}", format!("{} {}", row.label, label));
            for (_, kind) in COLUMNS {
                let mut c = build(row.file, *kind, Fate::OnDisk, extra, prior);
                let p = score(&mut c, &baseline, &weights);
                print!("{:>15.3}{}", p, mark(p));
            }
            println!();
        }
        println!();
    }

    println!("-- `compact /c /exe:LZX` on the sample: what the bypass buys, per row --");
    println!("   plain  = still on disk, unsigned, verdict read");
    println!("   lzx    = the same file `compact /c /exe:LZX`ed — decoded now, so verdict read");
    println!("   unread = a Compact-OS backing this build cannot decode, compression priced\n");
    print!("{:<24}", "");
    for (name, _) in COLUMNS {
        print!("{:>26}", name);
    }
    println!();
    for row in ROWS {
        print!("{:<24}", row.label);
        for (_, kind) in COLUMNS {
            let mut plain = build(row.file, *kind, Fate::OnDisk, Extra::None, prior);
            let plain_p = score(&mut plain, &baseline, &weights);

            let compressed_baseline = baseline_with_one_compressed(row.file);
            let mut lzx = build(row.file, *kind, Fate::OnDisk, Extra::CompactOsLzx, prior);
            let lzx_p = score(&mut lzx, &compressed_baseline, &weights);

            let mut unread =
                build(row.file, *kind, Fate::OnDisk, Extra::CompactOsUnreadable, prior);
            let unread_p = score(&mut unread, &compressed_baseline, &weights);

            print!(
                "  {:.3}{} {:.3}{} {:.3}{}",
                plain_p,
                mark(plain_p),
                lzx_p,
                mark(lzx_p),
                unread_p,
                mark(unread_p)
            );
        }
        println!();
    }
    println!();

    println!(
        "-- a dropper alone in a directory of documents (lone_executable_among_documents +4.1) --"
    );
    for (_, kind) in COLUMNS {
        let mut c = build(
            r"C:\Users\Bob\AppData\Roaming\Vendor\svcupdate.exe",
            *kind,
            Fate::OnDisk,
            Extra::LoneAmongDocuments,
            prior,
        );
        let p = score(&mut c, &baseline, &weights);
        println!(
            "  Documents, {:<10} {:.3}{}",
            kind.map(|k| k.label()).unwrap_or("none"),
            p,
            mark(p)
        );
    }

    println!("\n-- side-loaded DLL, the persistence a DLL really gets --");
    for (label, kind) in [
        ("nothing", None),
        ("COM server", Some(PersistenceKind::ComServer)),
        ("COM hijack", Some(PersistenceKind::ComHijack)),
    ] {
        let mut c =
            build(r"C:\Program Files\Vendor\uxtheme.dll", kind, Fate::OnDisk, Extra::None, prior);
        let p = score(&mut c, &baseline, &weights);
        println!("  {label:<12} {:.3}{}   [{}]", p, mark(p), evidence_line(&c));
        let mut c =
            build(r"C:\Program Files\Vendor\uxtheme.dll", kind, Fate::OnDisk, Extra::Packed, prior);
        let p = score(&mut c, &baseline, &weights);
        println!(
            "  {:<12} {:.3}{}   [{}]",
            format!("{label} + packed"),
            p,
            mark(p),
            evidence_line(&c)
        );
        let mut c = build(
            r"C:\Program Files\Vendor\uxtheme.dll",
            kind,
            Fate::OnDisk,
            Extra::Managed,
            prior,
        );
        let p = score(&mut c, &baseline, &weights);
        println!(
            "  {:<12} {:.3}{}   [{}]",
            format!("{label} + managed"),
            p,
            mark(p),
            evidence_line(&c)
        );
    }

    println!("\n-- a DLL side-loaded into the system directory --");
    for (label, kind) in [
        ("nothing", None),
        ("COM server", Some(PersistenceKind::ComServer)),
        ("COM hijack", Some(PersistenceKind::ComHijack)),
        ("service", Some(PersistenceKind::Service)),
    ] {
        for (extra, suffix) in
            [(Extra::None, ""), (Extra::Packed, " + packed"), (Extra::Managed, " + managed")]
        {
            let mut c = build(r"C:\Windows\System32\uxtheme.dll", kind, Fate::OnDisk, extra, prior);
            let p = score(&mut c, &baseline, &weights);
            println!(
                "  {:<22} {:.3}{}   [{}]",
                format!("{label}{suffix}"),
                p,
                mark(p),
                evidence_line(&c)
            );
        }
    }

    println!("\n-- decoy copies of the payload's own name: what each one buys --");
    println!("   OLD = the rule before this round: any name seen 3+ times collects -1.2");
    println!("   NEW = -1.2 only when at least one copy sits where Windows ships executables");
    println!("   ADMIN = the same decoys written into Program Files, which needs the privilege\n");
    print!("{:<22}", "");
    for n in 0..=3 {
        print!("{:>26}", format!("{n} decoy(s)"));
    }
    println!();
    for row in ROWS {
        for (label, kind) in [("service", Some(PersistenceKind::Service)), ("none", None)] {
            print!("{:<22}", format!("{} / {label}", row.label));
            for n in 0..=3 {
                let user = baseline_with_decoys(row.file, n, false);
                let admin = baseline_with_decoys(row.file, n, true);
                let mut old = build(row.file, kind, Fate::OnDisk, Extra::None, prior);
                let old_p = score_under_the_old_name_rule(&mut old, &user, &weights);
                let mut new = build(row.file, kind, Fate::OnDisk, Extra::None, prior);
                let new_p = score(&mut new, &user, &weights);
                let mut adm = build(row.file, kind, Fate::OnDisk, Extra::None, prior);
                let adm_p = score(&mut adm, &admin, &weights);
                print!(
                    "  {:.3}{}{:.3}{}{:.3}{}",
                    old_p,
                    mark(old_p),
                    new_p,
                    mark(new_p),
                    adm_p,
                    mark(adm_p)
                );
            }
            println!();
        }
    }
    println!("\n   columns per cell: OLD  NEW  ADMIN");

    println!("\n-- the other two threshold counts: what writing one more file buys --");
    for extra_exes in 0..2 {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!(r"C:\Windows\System32\f{i}.dll")));
        }
        for i in 0..20 {
            b.observe(&path(&format!(r"C:\Users\Bob\Documents\Reports\q{i}.docx")));
        }
        b.observe(&path(r"C:\Users\Bob\Documents\Reports\svcupdate.exe"));
        for i in 0..extra_exes {
            b.observe(&path(&format!(r"C:\Users\Bob\Documents\Reports\filler{i}.exe")));
        }
        let b = b.build();
        let mut c = build(
            r"C:\Users\Bob\Documents\Reports\svcupdate.exe",
            Some(PersistenceKind::Service),
            Fate::OnDisk,
            Extra::None,
            prior,
        );
        let p = score(&mut c, &b, &weights);
        println!(
            "  lone executable, {extra_exes} extra .exe written beside it   {p:.3}{}   [{}]",
            mark(p),
            evidence_line(&c)
        );
    }
    for zone_exes in [1usize, 5, 6] {
        let mut b = BaselineBuilder::new();
        for i in 0..12_000 {
            b.observe(&path(&format!(r"C:\Windows\System32\f{i}.dll")));
        }
        for i in 0..5 {
            b.observe(&path(&format!(r"C:\Tools\Vendor\readme{i}.txt")));
        }
        b.observe(&path(r"C:\Tools\Vendor\svcupdate.exe"));
        for i in 1..zone_exes {
            b.observe(&path(&format!(r"C:\Tools\Filler{i}\thing.exe")));
        }
        let b = b.build();
        let mut c = build(
            r"C:\Tools\Vendor\svcupdate.exe",
            Some(PersistenceKind::Service),
            Fate::OnDisk,
            Extra::None,
            prior,
        );
        let p = score(&mut c, &b, &weights);
        println!(
            "  zone rarity, {zone_exes} executable(s) in `elsewhere`        {p:.3}{}   [{}]",
            mark(p),
            evidence_line(&c)
        );
    }

    println!("\n-- evidence behind the bare `service, on disk` cell of each row --");
    for row in ROWS {
        let mut c =
            build(row.file, Some(PersistenceKind::Service), Fate::OnDisk, Extra::None, prior);
        let p = score(&mut c, &baseline, &weights);
        println!("  {:<20} {:.3}  [{}]", row.label, p, evidence_line(&c));
    }
}

fn evidence_line(c: &Candidate) -> String {
    c.evidence
        .iter()
        .map(|e| format!("{}{:+.1}", e.feature, e.log_lr))
        .collect::<Vec<_>>()
        .join(" ")
}
