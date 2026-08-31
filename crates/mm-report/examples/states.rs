use mm_core::{
    Acquisition, ArtifactSource, Candidate, CandidateId, Evidence, FileHash, NormalizedPath,
    Observation, ObservationKind, Recovery,
};
use mm_report::{Coverage, CoverageStatus, Report, Target};

fn rebuild(base: &Report, edit: impl FnOnce(&mut Report)) -> Report {
    let mut report: Report =
        serde_json::from_str(&base.to_json()).expect("a report round-trips through its own JSON");
    edit(&mut report);
    report
}

fn target() -> Target {
    Target {
        display_name: "D:".into(),
        device_path: "\\\\?\\Volume{2c3d4e5f-0000-0000-0000-300300000000}".into(),
        volume_serial: "5f4e3d2c1b0a9988".into(),
    }
}

fn candidate(id: u64, path: &str, evidence: &[(f64, &str)], prior: f64) -> Candidate {
    let mut c = Candidate::new(CandidateId(id as u32), prior);
    c.path = Some(NormalizedPath::parse(path).expect(path));
    for (lr, detail) in evidence {
        c.evidence.push(Evidence::new("planted", *lr, *detail).from(ArtifactSource::Mft));
    }
    c
}

fn healthy_coverage() -> Coverage {
    let mut c = Coverage::default();
    c.record_timed("SOFTWARE hive", CoverageStatus::Read { observations: 6679 }, 3.1);
    c.record_timed("SYSTEM hive", CoverageStatus::Read { observations: 1407 }, 1.2);
    c.record_timed("Amcache", CoverageStatus::Read { observations: 2090 }, 2.8);
    c.record_timed("Prefetch", CoverageStatus::Read { observations: 982 }, 1.9);
    c.record_timed("Defender quarantine", CoverageStatus::Absent, 0.04);
    c.record_timed(
        "live process memory",
        CoverageStatus::NotAvailableHere {
            reason: "running from the recovery environment; no processes exist".into(),
        },
        0.0,
    );
    c.record_timed("$MFT", CoverageStatus::Read { observations: 2941 }, 84.2);
    c.record_timed("code signatures", CoverageStatus::Read { observations: 227 }, 20.4);
    c.files_enumerated = 130_897;
    c.deleted_records_seen = 523;
    c.baseline_usable = true;
    c
}

fn report(candidates: Vec<Candidate>, coverage: Coverage) -> Report {
    Report::new(
        "0.1.0",
        "recovery environment (WinRE/WinPE)",
        target(),
        candidates,
        coverage,
        false,
    )
}

fn banner(name: &str) {
    println!("\n\n################ {name} ################\n");
}

fn full() -> bool {
    std::env::args().any(|a| a == "--full")
}

fn show(report: &Report) {
    if full() {
        print!("{}", mm_report::text::render(report));
    }
    let console = mm_report::text::console(report);
    print!("{console}");
    let file_lines = mm_report::text::render(report).lines().count();
    let console_lines = console.lines().count();
    let over: Vec<&str> = console.lines().filter(|l| l.chars().count() > 78).collect();
    let widest_within =
        console.lines().map(|l| l.chars().count()).filter(|n| *n <= 78).max().unwrap_or(0);
    println!(
        "    [measured] console {console_lines} lines vs report.txt {file_lines} lines; widest line inside 78 cols is {widest_within}; {} line(s) overflow, all paths",
        over.len()
    );
}

fn real(name: &str) -> Option<Report> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../VM_TESTS").join(name);
    let text = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

fn real_runs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("test_4 - njRAT: 2 findings, p = 1.00 each", "test_4/report.json"),
        ("test_3 - clean machine: NOTHING FOUND", "test_3/report.json"),
        ("test_2 winre - NOTHING CLEARED, one came close", "test_2/winre/report.json"),
        ("test_2 live - NOTHING FOUND, a second volume named", "test_2/live/report.json"),
    ]
}

fn main() {
    let which =
        std::env::args().nth(1).filter(|a| !a.starts_with("--")).unwrap_or_else(|| "all".into());
    let run = |n: &str| which == "all" || which == n;

    if run("real") {
        for (label, file) in real_runs() {
            match real(file) {
                Some(report) => {
                    banner(&format!("REAL RUN - {label}"));
                    show(&report);
                }
                None => banner(&format!("REAL RUN - {label} - NOT ON DISK ({file})")),
            }
        }
    }

    if run("derived") {
        if let Some(base) = real("test_4/report.json") {
            banner("DERIVED from test_4 - ONE finding, not two");
            let mut one = rebuild(&base, |r| {
                let keep = r.candidates.remove(0);
                r.candidates.retain(|c| c.probability() < r.threshold);
                r.candidates.insert(0, keep);
            });
            one.set_case_directory(base.case_directory.clone().unwrap_or_default());
            show(&one);

            banner("DERIVED from test_4 - the sample could NOT be recovered");
            let lost = rebuild(&base, |r| {
                for c in r.candidates.iter_mut().take(2) {
                    c.acquisition = Acquisition::Failed {
                        reason: "the clusters this record names have been reallocated to \
                                 another file; what is there now is not this file"
                            .into(),
                    };
                    c.acquired_hash = None;
                }
            });
            show(&lost);

            banner("DERIVED from test_4 - the same run with --no-samples");
            let withheld = rebuild(&base, |r| {
                for c in r.candidates.iter_mut() {
                    if let Acquisition::Bytes { via, size, recovery, .. } = &c.acquisition {
                        c.acquisition = Acquisition::Withheld {
                            via: via.clone(),
                            size: *size,
                            recovery: recovery.clone(),
                        };
                    }
                }
            });
            show(&withheld);

            banner("DERIVED from test_4 - the hash DISAGREES with what Amcache recorded");
            let changed = rebuild(&base, |r| {
                for c in r.candidates.iter_mut().take(1) {
                    for check in c.hash_checks.iter_mut() {
                        check.agrees = false;
                        check.recorded = "0000000000000000000000000000000000000000".into();
                    }
                }
            });
            show(&changed);

            banner("DERIVED from test_4 - a stage FAILED, and it still found both");
            let broken = rebuild(&base, |r| {
                r.coverage.record_timed(
                    "Defender quarantine",
                    CoverageStatus::Failed {
                        reason: "the quarantine store is present but every entry failed to \
                                 decrypt"
                            .into(),
                    },
                    0.9,
                );
            });
            show(&broken);
        }

        if let Some(base) = real("test_3/report.json") {
            banner("DERIVED from test_3 - clean machine, but a stage FAILED");
            let broken = rebuild(&base, |r| {
                r.coverage.record_timed(
                    "$MFT",
                    CoverageStatus::Failed {
                        reason: "read error at cluster 1 449 984: the volume returned a \
                                 device I/O error"
                            .into(),
                    },
                    12.6,
                );
            });
            show(&broken);

            banner("DERIVED from test_3 - the walk never ran, so there is NO base rate");
            let unmeasured = rebuild(&base, |r| {
                r.set_enumeration(mm_core::Enumeration::not_attempted());
                r.coverage.record_timed(
                    "$MFT",
                    CoverageStatus::Failed {
                        reason: "the $MFT's own run list could not be read; no walk happened"
                            .into(),
                    },
                    0.4,
                );
            });
            show(&unmeasured);
        }
    }

    if run("one-finding-recovered") {
        banner("ONE FINDING - bytes recovered intact");
        let mut c = candidate(
            1,
            "C:\\Users\\Bob\\AppData\\Local\\Temp\\svcupdate.exe",
            &[
                (4.3, "the Run key that starts this file points into the user temp"),
                (3.2, "set to start automatically (T1547.001)"),
                (1.1, "unsigned"),
            ],
            -7.67,
        );
        c.record_acquired_hash(&FileHash::compute(b"the planted sample's bytes"), true);
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 148_992,
            saved_as: "malmathic-case\\samples\\C001-svcupdate.exe".into(),
            recovery: Recovery::Intact,
        };
        show(&report(vec![c], healthy_coverage()));
    }

    if run("one-finding-hash-changed") {
        banner("ONE FINDING - the file no longer matches the hash Amcache recorded");
        let mut c = candidate(
            1,
            "C:\\Windows\\System32\\svchost.exe",
            &[
                (4.9, "Windows Defender logged a detection on this file"),
                (3.2, "set to start automatically (T1547.001)"),
                (2.4, "a system binary whose signature does not verify"),
            ],
            -7.67,
        );
        c.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                NormalizedPath::parse("C:\\Windows\\System32\\svchost.exe").unwrap(),
                ObservationKind::HashRecovered,
            )
            .with_hash(
                FileHash::from_sha1_hex("3f2a91c4bd77e0155ab3c9e8d147f0b62c8ad934").unwrap(),
            ),
        );
        c.record_acquired_hash(&FileHash::compute(b"the bytes at that path today"), true);
        c.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 55_320,
            saved_as: "malmathic-case\\samples\\C001-svchost.exe".into(),
            recovery: Recovery::Intact,
        };
        show(&report(vec![c], healthy_coverage()));
    }

    if run("one-finding-not-attempted") {
        banner("ONE FINDING - acquisition NOT attempted (the silent state)");
        let c = candidate(
            1,
            "C:\\Users\\Bob\\AppData\\Local\\Temp\\svcupdate.exe",
            &[
                (4.3, "the Run key that starts this file points into the user temp"),
                (3.2, "set to start automatically (T1547.001)"),
                (1.1, "unsigned"),
            ],
            -7.67,
        );
        show(&report(vec![c], healthy_coverage()));
    }

    if run("one-finding-acq-failed") {
        banner("ONE FINDING - acquisition FAILED");
        let mut c = candidate(
            1,
            "C:\\Users\\Bob\\Downloads\\svcupdate.exe",
            &[
                (4.8, "execution artifacts record this file running, but it is no longer on disk"),
                (3.2, "set to start automatically (T1547.001)"),
                (1.1, "unsigned"),
            ],
            -7.67,
        );
        c.acquisition = Acquisition::Failed {
            reason: "clusters reallocated to another file since deletion".into(),
        };
        show(&report(vec![c], healthy_coverage()));
    }

    if run("one-finding-hash-only") {
        banner("ONE FINDING - hash only, no bytes");
        let mut c = candidate(
            1,
            "C:\\Users\\Bob\\Downloads\\svcupdate.exe",
            &[
                (4.8, "execution artifacts record this file running, but it is no longer on disk"),
                (3.2, "set to start automatically (T1547.001)"),
                (1.1, "unsigned"),
            ],
            -7.67,
        );
        c.hash = FileHash::compute(b"amcache recorded this");
        c.acquisition = Acquisition::HashOnly { via: ArtifactSource::Amcache };
        show(&report(vec![c], healthy_coverage()));
    }

    if run("three-findings") {
        banner("THREE FINDINGS - the VM run");
        let mut a = candidate(
            1,
            "C:\\Users\\Bob\\AppData\\Local\\Temp\\svcupdate.exe",
            &[
                (4.3, "the Run key that starts this file points into the user temp"),
                (3.2, "set to start automatically (T1547.001)"),
                (1.1, "unsigned"),
            ],
            -7.67,
        );
        a.record_acquired_hash(&FileHash::compute(b"sample one"), true);
        a.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 148_992,
            saved_as: "malmathic-case\\samples\\C001-svcupdate.exe".into(),
            recovery: Recovery::Intact,
        };

        let mut b = candidate(
            2,
            "C:\\ProgramData\\Vendor\\svcupdate.exe",
            &[
                (3.4, "installed as a service (T1543.003)"),
                (2.6, "an executable under ProgramData"),
                (1.1, "unsigned"),
                (1.8, "created inside the incident window"),
            ],
            -7.67,
        );
        b.record_acquired_hash(&FileHash::compute(b"sample two"), true);
        b.acquisition = Acquisition::Bytes {
            via: ArtifactSource::DefenderQuarantine,
            size: 96_256,
            saved_as: "malmathic-case\\samples\\C002-svcupdate.exe".into(),
            recovery: Recovery::Confirmed { against: "Amcache".into() },
        };

        let mut d = candidate(
            3,
            "C:\\Users\\Bob\\Downloads\\dropper.exe",
            &[
                (4.8, "execution artifacts record this file running, but it is no longer on disk"),
                (1.8, "created inside the incident window"),
                (1.0, "no other file on this machine is named dropper.exe"),
                (1.1, "unsigned"),
            ],
            -7.67,
        );
        d.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                NormalizedPath::parse("C:\\Users\\Bob\\Downloads\\dropper.exe").unwrap(),
                ObservationKind::HashRecovered,
            )
            .with_hash(
                FileHash::from_sha1_hex("9c1f0b7d2e4a6538ff01b9c7d3e5a24680bd1f37").unwrap(),
            ),
        );
        d.record_acquired_hash(&FileHash::compute(b"carved"), false);
        d.acquisition = Acquisition::Bytes {
            via: ArtifactSource::Mft,
            size: 61_440,
            saved_as: "malmathic-case\\samples\\C003-dropper.exe".into(),
            recovery: Recovery::Partial {
                detail: "3 of 15 clusters have been reallocated to another file; the hash does \
                         not match the one Amcache recorded"
                    .into(),
            },
        };
        show(&report(vec![a, b, d], healthy_coverage()));
    }

    if run("mft-failed") {
        banner("COULD NOT LOOK - the $MFT walk failed");
        let mut cov = Coverage::default();
        cov.record_timed("SOFTWARE hive", CoverageStatus::Read { observations: 6679 }, 3.1);
        cov.record_timed(
            "$MFT",
            CoverageStatus::Failed {
                reason: "read error at cluster 1449984: the volume returned a device I/O error"
                    .into(),
            },
            12.6,
        );
        cov.record_timed("code signatures", CoverageStatus::Read { observations: 0 }, 0.0);
        cov.files_enumerated = 0;
        cov.deleted_records_seen = 0;
        cov.baseline_usable = false;
        cov.warn(
            "the filesystem walk did not complete; location and rarity evidence was unavailable \
             for every candidate",
        );
        let c = candidate(
            1,
            "C:\\Windows\\System32\\svchost.exe",
            &[(1.0, "no other file on this machine is named svchost.exe")],
            -2.5,
        );
        show(&report(vec![c], cov));
    }

    if run("hive-missing") {
        banner("COULD NOT LOOK - the SOFTWARE hive is missing");
        let mut cov = healthy_coverage();
        cov.artifacts.clear();
        cov.record_timed(
            "SOFTWARE hive",
            CoverageStatus::Failed {
                reason: "\\Windows\\System32\\config\\SOFTWARE not found on this volume".into(),
            },
            0.1,
        );
        cov.record_timed(
            "SYSTEM hive",
            CoverageStatus::Failed { reason: "hive header is not a valid regf signature".into() },
            0.1,
        );
        cov.record_timed("$MFT", CoverageStatus::Read { observations: 2941 }, 84.2);
        cov.warn(
            "no registry persistence could be read; a sample that persists only through the \
             registry would not appear here at all",
        );
        show(&report(vec![], cov));
    }

    if run("lzx") {
        banner("COULD NOT LOOK - the Compact-OS decoder met LZX");
        let mut cov = healthy_coverage();
        cov.warn(
            "412 files are Compact-OS compressed with LZX, which this build cannot decode; their \
             bytes were not read and their signatures could not be checked",
        );
        let mut c = candidate(
            1,
            "C:\\Program Files\\Vendor\\svcupdate.exe",
            &[
                (3.4, "installed as a service (T1543.003)"),
                (2.6, "an executable under ProgramData"),
                (2.0, "unsigned"),
            ],
            -7.67,
        );
        c.acquisition = Acquisition::Failed {
            reason: "the file is Compact-OS compressed with LZX; this build decodes XPRESS only"
                .into(),
        };
        show(&report(vec![c], cov));
    }

    if run("catalog-failed") {
        banner("COULD NOT LOOK - the catalog store could not be read");
        let mut cov = healthy_coverage();
        cov.record_timed(
            "catalog store",
            CoverageStatus::Failed {
                reason: "\\Windows\\System32\\CatRoot is present but every catalog failed to parse"
                    .into(),
            },
            4.2,
        );
        cov.warn(
            "no code signature could be attributed to a Microsoft catalog; every catalog-signed \
             system binary reads as unsigned",
        );
        let c = candidate(
            1,
            "C:\\Windows\\System32\\svchost.exe",
            &[(1.1, "unsigned"), (2.6, "an executable under ProgramData")],
            -7.67,
        );
        show(&report(vec![c], cov));
    }
}
