use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use mm_env::{DiscoveredVolume, Environment};

#[derive(Subcommand)]
pub enum Diagnostic {
    /// Why the $MFT walk lost a directory, and whether a parent reference is stale.
    #[command(long_about = "\
Prints one $MFT record and every ancestor of it, a component at a time: the \
record header, every attribute, whether the base record carries a $FILE_NAME \
(the walk's single point of failure), every $ATTRIBUTE_LIST entry and whether \
the record it names claims this one as its base — and, for every parent \
reference, both halves of it against the sequence number the named record is \
carrying right now.\n\n\
That last line is what settles a stale reference. Equal sequences mean the \
name still points at the directory it was written for. A lower one in the \
reference means the directory is gone and something else holds its record \
number.\n\n\
Take the record numbers from two places. Every finding and near-miss now prints one:
  record   $MFT <R>, in use   /   $MFT <R>, FREE

and that is the number to bring back on a LATER run, to ask whether the record is still that file's. The other is the coverage warnings:\n  \
N file(s) were dropped because $MFT record <R> (`<name>`) could not be placed\n\n\
Examples:\n  \
malmathic diag mft --record 133583\n  \
malmathic diag mft \"\\Program Files\\Vendor\\Product\" --children\n  \
malmathic diag mft --record 50 --volume D:")]
    Mft {
        /// A volume-relative directory path, resolved one component at a time.
        path: Option<String>,

        /// An $MFT record number, as a coverage warning prints it.
        #[arg(long)]
        record: Option<u64>,

        /// Also check every child, which separates "the walk lost the
        /// directory" from "the walk lost every file in it".
        #[arg(long)]
        children: bool,

        #[command(flatten)]
        target: TargetArgs,
    },

    /// Count the $ATTRIBUTE_LIST population, under each candidate gate.
    #[command(
        name = "attribute-lists",
        long_about = "\
Walks the whole $MFT and counts, widest gate to narrowest, how many base \
records carry an $ATTRIBUTE_LIST — the number that prices widening the \
Compact-OS follower's gate, since every record that passes it costs one extra \
record read in the walk's hottest loop.\n\n\
Cross-check the `$ATTRIBUTE_LIST present` line against the run's own `$MFT \
records with an $ATTRIBUTE_LIST` coverage line. They should agree.\n\n\
--follow also performs the extra reads, so the cost is a wall clock rather \
than an estimate."
    )]
    AttributeLists {
        /// Also read the extension records, so the cost is measured rather
        /// than estimated.
        #[arg(long)]
        follow: bool,

        #[command(flatten)]
        target: TargetArgs,
    },

    /// Capture a Compact-OS stream beside its plaintext, for the LZX corpus.
    #[command(
        name = "lzx-capture",
        long_about = "\
Captures WOF-compressed files as compressed stream AND plaintext, side by \
side, so the LZX decoder can be checked against Microsoft's own bytes rather \
than against an inference.\n\n\
It needs both halves at once: the stream comes off raw NTFS (Win32 refuses \
`WofCompressedData` by name), and the plaintext comes back through the mounted \
WOF filter. WinRE has both. An unelevated live session has only the second.\n\n\
--mount defaults to the drive letter the chosen volume is mounted at, which is \
the letter WinRE assigned and not the one the machine boots as. Give --mount \
explicitly only if that is wrong.\n\n\
Every plaintext is refused unless its length matches the file record, it is \
not all zeroes, and an .exe/.dll/.sys begins MZ. A capture of nulls labelled \
as Microsoft's plaintext would be worse than no capture at all.\n\n\
--out must not be on the volume being read, must not already exist, and must \
not be inside malmathic's own tree or beside its binary. Each of those is \
refused in words. --overwrite lifts the second one and nothing else; a capture \
takes a WinRE session to make, so the file already at that path may be the \
only one there is."
    )]
    LzxCapture {
        /// Where to write the capture. Put it on external media.
        #[arg(long, short)]
        out: PathBuf,

        /// Destroy an existing file at `--out` and write the capture over it.
        #[arg(long)]
        overwrite: bool,

        /// The mounted root of the same volume. Defaults to the chosen
        /// volume's own drive letter.
        #[arg(long)]
        mount: Option<String>,

        /// Capture every WOF algorithm, not LZX alone.
        #[arg(long)]
        all_algorithms: bool,

        /// Most samples to take.
        #[arg(long, default_value_t = 12)]
        limit: usize,

        #[command(flatten)]
        target: TargetArgs,
    },

    /// Read a capture back and say what is in it.
    #[command(name = "lzx-describe")]
    LzxDescribe {
        /// The capture file written by `lzx-capture`.
        file: PathBuf,
    },
}

#[derive(Args, Clone, Debug, Default)]
pub struct TargetArgs {
    /// Use this volume instead of the one found automatically. A drive
    /// letter, or any part of a volume GUID.
    #[arg(long)]
    pub volume: Option<String>,

    /// Read a raw disk image instead of an attached device.
    #[arg(long, conflicts_with = "volume")]
    pub image: Option<PathBuf>,
}

enum AnyVolume {
    Attached(mm_env::OpenVolume),
    Image(mm_env::ImageVolume),
}

macro_rules! on_volume {
    ($any:expr, |$volume:ident| $body:expr) => {
        match &$any {
            AnyVolume::Attached($volume) => $body,
            AnyVolume::Image($volume) => $body,
        }
    };
}

pub fn run(diagnostic: &Diagnostic) -> ExitCode {
    if let Diagnostic::LzxDescribe { file } = diagnostic {
        return describe_capture(file);
    }

    if let Diagnostic::Mft { path: None, record: None, .. } = diagnostic {
        eprintln!(
            "Give a directory path or --record <n>.\n\n\
             The record numbers are in the run's own coverage warnings:\n  \
             N file(s) were dropped because $MFT record <R> (`<name>`) could not be placed"
        );
        return ExitCode::from(2);
    }

    let target = match diagnostic {
        Diagnostic::Mft { target, .. }
        | Diagnostic::AttributeLists { target, .. }
        | Diagnostic::LzxCapture { target, .. } => target,
        Diagnostic::LzxDescribe { .. } => unreachable!("handled above"),
    };

    let opened = match open_target(target) {
        Ok(opened) => opened,
        Err(code) => return code,
    };
    eprintln!("Target: {}\n", opened.label);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let result = match diagnostic {
        Diagnostic::Mft { path, record, children, .. } => {
            let query = mm_raw::diag::MftQuery {
                path: path.as_deref(),
                record: *record,
                children: *children,
            };
            on_volume!(opened.volume, |volume| mm_raw::diag::mft(volume, &query, &mut out)).map(
                |findings| {
                    if findings.found_a_fault() {
                        ExitCode::from(1)
                    } else {
                        ExitCode::SUCCESS
                    }
                },
            )
        }
        Diagnostic::AttributeLists { follow, .. } => {
            on_volume!(opened.volume, |volume| mm_raw::diag::attribute_lists(
                volume, *follow, &mut out
            ))
            .map(|_| ExitCode::SUCCESS)
        }
        Diagnostic::LzxCapture {
            out: destination,
            mount,
            all_algorithms,
            limit,
            overwrite,
            ..
        } => {
            let mount = match mount.clone().or_else(|| opened.mount.clone()) {
                Some(mount) => mount,
                None => {
                    eprintln!(
                        "This volume is not mounted at a drive letter, so the WOF filter has \
                         nowhere to hand the plaintext back through.\n\
                         Give --mount <root of the same volume> explicitly."
                    );
                    return ExitCode::from(2);
                }
            };
            if mm_env::capture::refuses_to_write_onto(&mount, destination) {
                eprintln!(
                    "Refusing to write {} onto {mount}, which is the volume being read.\n\
                     Put the capture on external media: --out E:\\lzx.mmcap",
                    destination.display()
                );
                return ExitCode::from(2);
            }
            let destination = match crate::casedir::guard_file(
                destination,
                &crate::casedir::Location::detect(),
                "capture",
                *overwrite,
            ) {
                Ok(path) => path,
                Err(refusal) => {
                    eprintln!("\n{refusal}");
                    return ExitCode::from(2);
                }
            };
            let options = mm_env::capture::CaptureOptions {
                mount: &mount,
                any_algorithm: *all_algorithms,
                limit: *limit,
            };
            let _ = writeln!(
                out,
                "plaintext will be read through {mount}, which must be the same volume"
            );
            on_volume!(opened.volume, |volume| mm_env::capture::capture(volume, &options, &mut out))
                .map(|outcome| write_capture(&outcome, &destination, &mut out))
        }
        Diagnostic::LzxDescribe { .. } => unreachable!("handled above"),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Opened {
    volume: AnyVolume,
    label: String,
    mount: Option<String>,
}

fn open_target(target: &TargetArgs) -> Result<Opened, ExitCode> {
    if let Some(image) = &target.image {
        return open_image(image);
    }

    let environment = Environment::detect();
    if !environment.can_read_raw_volumes() {
        eprintln!(
            "malmathic needs administrator rights to read volumes directly.\n\
             \n\
             Reading raw NTFS is not optional — it is how the tool reaches files\n\
             Windows has locked, and how it works when no registry is mounted.\n\
             \n\
             Re-run from an elevated prompt, or boot into WinRE and run it there\n\
             (in WinRE it is already privileged, and the malware cannot interfere).\n\
             \n\
             To try this against a disk image instead, which needs no privileges:\n\
             \x20 malmathic diag … --image <file>"
        );
        return Err(ExitCode::from(2));
    }

    let volumes = match mm_env::discover_volumes() {
        Ok(volumes) => volumes,
        Err(e) => {
            eprintln!("could not enumerate volumes: {e}");
            return Err(ExitCode::from(2));
        }
    };

    let Some(chosen) = crate::choose_volume(&volumes, target.volume.as_deref()) else {
        eprint!("\n{}", no_volume_message(&volumes, target.volume.as_deref()));
        return Err(ExitCode::from(2));
    };

    match mm_env::open_volume(&chosen.device_path) {
        Ok(volume) => Ok(Opened {
            volume: AnyVolume::Attached(volume),
            label: format!("{} ({})", chosen.display_name(), chosen.device_path),
            mount: chosen.mount_points.first().cloned(),
        }),
        Err(e) => {
            eprint!(
                "\ncould not open {}: {e}\n\n{}",
                chosen.device_path,
                unopenable_message(&volumes)
            );
            Err(ExitCode::from(2))
        }
    }
}

fn no_volume_message(volumes: &[DiscoveredVolume], asked: Option<&str>) -> String {
    let listing = crate::render_volumes(volumes);
    match asked {
        Some(asked) => format!(
            "{listing}No volume matches `{asked}`.\n\
             \n\
             WinRE assigns its own drive letters: the volume that boots as C: is\n\
             commonly D: there, and may have no letter at all. Name one of the\n\
             volumes above — a drive letter, or any part of a volume GUID — or\n\
             leave --volume off entirely, and the Windows installation is found\n\
             the same way the analysis finds it.{}\n",
            suggestion(volumes)
        ),
        None => format!(
            "{listing}No Windows installation is reachable, so there is nothing to\n\
             diagnose automatically. Name one of the volumes above with --volume.{}\n",
            suggestion(volumes)
        ),
    }
}

fn unopenable_message(volumes: &[DiscoveredVolume]) -> String {
    format!(
        "{}Name another volume with --volume.{}\n",
        crate::render_volumes(volumes),
        suggestion(volumes)
    )
}

fn suggestion(volumes: &[DiscoveredVolume]) -> String {
    let best = volumes.iter().find(|v| v.status.holds_windows()).or_else(|| {
        volumes.iter().find(|v| matches!(v.status, mm_env::VolumeStatus::NtfsNoWindows { .. }))
    });
    match best {
        Some(volume) => format!("\n\nTry:  malmathic diag … --volume {}", volume.display_name()),
        None => String::new(),
    }
}

fn open_image(image: &std::path::Path) -> Result<Opened, ExitCode> {
    let partitions = match mm_env::find_ntfs_partitions(image) {
        Ok(partitions) => partitions,
        Err(e) => {
            eprintln!("could not read {}: {e}", image.display());
            return Err(ExitCode::from(2));
        }
    };
    if partitions.is_empty() {
        eprintln!("No NTFS partition found in {}.", image.display());
        return Err(ExitCode::from(2));
    }

    let mut fallback = None;
    for partition in &partitions {
        match mm_env::open_partition(image, *partition) {
            Ok(volume) => {
                let label = format!("{}@{}", image.display(), partition.offset);
                if volume.is_windows_install() {
                    return Ok(Opened { volume: AnyVolume::Image(volume), label, mount: None });
                }
                if fallback.is_none() {
                    fallback =
                        Some(Opened { volume: AnyVolume::Image(volume), label, mount: None });
                }
            }
            Err(e) => eprintln!("  offset {:<12} unreadable: {e}", partition.offset),
        }
    }
    match fallback {
        Some(opened) => {
            eprintln!("no Windows installation in {}; using {}", image.display(), opened.label);
            Ok(opened)
        }
        None => {
            eprintln!("No NTFS partition in {} could be opened.", image.display());
            Err(ExitCode::from(2))
        }
    }
}

fn describe_capture(file: &std::path::Path) -> ExitCode {
    let bytes = match std::fs::read(file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("could not read {}: {e}", file.display());
            return ExitCode::from(2);
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match mm_env::capture::describe(&bytes, &file.display().to_string(), &mut out) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn write_capture<W: Write>(
    outcome: &mm_env::capture::CaptureOutcome,
    destination: &std::path::Path,
    out: &mut W,
) -> ExitCode {
    if outcome.samples.is_empty() {
        eprintln!(
            "\nNothing was captured. Either this volume has no Compact-OS files of the\n\
             algorithm asked for — try --all-algorithms — or the plaintext side is not\n\
             readable through the mounted root, which means the WOF filter is not\n\
             attached there and this is not a machine the capture can be taken on."
        );
        return ExitCode::from(1);
    }
    let bytes = mm_env::capture::write_capture(&outcome.samples);
    if let Err(e) = std::fs::write(destination, &bytes) {
        eprintln!("\ncould not write {}: {e}", destination.display());
        return ExitCode::FAILURE;
    }
    let _ = writeln!(out, "\nwrote {} bytes to {}", bytes.len(), destination.display());
    for sample in &outcome.samples {
        let _ = writeln!(
            out,
            "  {} -> chunk sizes consistent with the bytes: {:?}",
            sample.path,
            mm_env::capture::consistent_chunk_sizes(sample)
        );
    }
    let _ = writeln!(
        out,
        "\nBring that file back and run `malmathic diag lzx-describe` on it. It holds the\n\
         compressed stream and the exact plaintext for every sample, so the LZX decoder\n\
         can be tested against Microsoft's own bytes rather than against a guess."
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use mm_raw::diag::{MftFindings, MftQuery};

    use super::{no_volume_message, open_target, suggestion, Diagnostic, TargetArgs};
    use crate::testimage::{Builder, IndexLayout, Presence, ROOT_RECORD};
    use crate::Cli;

    const NOW: u16 = 5;
    const THEN: u16 = 4;

    fn windows(builder: &mut Builder) {
        let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
        builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
        let config = builder.directory(system32, "config");
        builder.resident_file(config, "SYSTEM", b"regf", Presence::Live);
    }

    fn chrome_with_a_leftover() -> (Builder, u64, u64) {
        let mut builder = Builder::new();
        windows(&mut builder);
        let locales = builder.directories(
            ROOT_RECORD,
            "Program Files\\Google\\Chrome\\Application\\150.0.7871.187\\Locales",
        );
        let pak = builder.resident_file(locales, "sw_NEUTER.pak", b"pak data", Presence::Live);
        builder.set_sequence(pak, NOW);
        let orphaned = builder.directory(pak, "Locales");
        for i in 0..6 {
            builder.resident_file(orphaned, &format!("{i}_NEUTER.pak"), b"old", Presence::Live);
        }
        (builder, pak, orphaned)
    }

    fn run_mft(builder: Builder, query: MftQuery<'_>) -> (String, MftFindings) {
        let volume = builder.open();
        let mut out = Vec::new();
        let findings = mm_raw::diag::mft(&volume, &query, &mut out).expect("a Vec never fails");
        (String::from_utf8(out).expect("the diagnostic prints UTF-8"), findings)
    }

    #[test]
    fn the_mft_diagnostic_prints_both_halves_of_a_stale_parent_reference() {
        let (mut builder, pak, orphaned) = chrome_with_a_leftover();
        builder.set_parent_sequence(orphaned, THEN);
        let (text, findings) =
            run_mft(builder, MftQuery { record: Some(orphaned), ..MftQuery::default() });

        assert_eq!(findings.stale_parents, 1, "{text}");
        assert!(findings.current_parents >= 1, "{text}");
        assert!(
            text.contains(&format!("parent record {pak}, reference sequence {THEN}")),
            "both halves of the reference are printed: {text}"
        );
        assert!(
            text.contains(&format!("the record carries sequence {NOW} -> STALE by 1")),
            "and what the named record is carrying now: {text}"
        );
        assert!(text.contains("FILE, not a directory"), "{text}");
        assert!(findings.found_a_fault());
    }

    #[test]
    fn a_reference_as_new_as_its_record_reads_as_current() {
        let (mut builder, _pak, orphaned) = chrome_with_a_leftover();
        builder.set_sequence(_pak, 1);
        let (text, findings) =
            run_mft(builder, MftQuery { record: Some(orphaned), ..MftQuery::default() });

        assert_eq!(findings.stale_parents, 0, "{text}");
        assert!(findings.current_parents >= 1, "{text}");
        assert!(text.contains("-> CURRENT"), "{text}");
        assert!(!text.contains("STALE"), "{text}");
    }

    #[test]
    fn a_directory_whose_name_spilled_is_named_as_the_failure() {
        let mut builder = Builder::new();
        windows(&mut builder);
        let magician =
            builder.directories(ROOT_RECORD, "Program Files (x86)\\Samsung\\Samsung Magician");
        builder.resident_file(magician, "Magician.exe", b"MZ", Presence::Live);
        builder.spill_index(magician, IndexLayout::RootInExtension);
        builder.spill_file_name(magician);

        let (text, findings) =
            run_mft(builder, MftQuery { record: Some(magician), ..MftQuery::default() });

        assert!(findings.records_the_walk_loses >= 1, "{text}");
        assert!(text.contains("*** THIS IS THE FAILURE"), "{text}");
        assert!(
            text.contains("$FILE_NAME live in extension records and NONE in the base"),
            "the $ATTRIBUTE_LIST is followed and the layout named: {text}"
        );
        assert!(findings.found_a_fault());
    }

    #[test]
    fn a_healthy_directory_reaches_the_root_and_reports_no_fault() {
        let mut builder = Builder::new();
        windows(&mut builder);
        let (text, findings) =
            run_mft(builder, MftQuery { path: Some("\\Windows\\System32"), ..MftQuery::default() });

        assert!(findings.reaches_root, "{text}");
        assert_eq!(findings.records_the_walk_loses, 0, "{text}");
        assert_eq!(findings.stale_parents, 0, "{text}");
        assert!(!findings.found_a_fault(), "{text}");
        assert!(text.contains("it reaches the root"), "{text}");
        assert_eq!(findings.chain.last(), Some(&5));
    }

    #[test]
    fn resolution_names_the_component_that_stopped_it() {
        let mut builder = Builder::new();
        windows(&mut builder);
        let (text, findings) = run_mft(
            builder,
            MftQuery { path: Some("\\Windows\\NoSuchPlace\\Deeper"), ..MftQuery::default() },
        );

        assert_eq!(findings.stopped_at.as_deref(), Some("NoSuchPlace"));
        assert_eq!(findings.target, None);
        assert!(text.contains("does not list an entry named `NoSuchPlace`"), "{text}");
        assert!(text.contains("resolution stops here"), "{text}");
    }

    #[test]
    fn children_separates_a_lost_directory_from_lost_files() {
        let mut builder = Builder::new();
        windows(&mut builder);
        let dir = builder.directories(ROOT_RECORD, "Vendor\\Product");
        let good = builder.resident_file(dir, "good.exe", b"MZ", Presence::Live);
        let bad = builder.resident_file(dir, "bad.exe", b"MZ", Presence::Live);
        builder.spill_file_name(bad);
        let _ = good;

        let (text, findings) =
            run_mft(builder, MftQuery { record: Some(dir), children: true, ..MftQuery::default() });

        assert_eq!(findings.children_placed, 1, "{text}");
        assert_eq!(findings.children_lost, 1, "{text}");
        assert!(text.contains("bad.exe"), "the lost child is named: {text}");
        assert!(findings.found_a_fault());
    }

    #[test]
    fn the_attribute_list_census_counts_what_the_image_holds() {
        let mut builder = Builder::new();
        windows(&mut builder);
        let dir = builder.directories(ROOT_RECORD, "Vendor");
        for i in 0..3 {
            let record = builder.resident_file(dir, &format!("s{i}.dll"), b"MZ", Presence::Live);
            builder.spill_file_name(record);
        }
        let volume = builder.open();

        let mut out = Vec::new();
        let census = mm_raw::diag::attribute_lists(&volume, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();

        assert_eq!(census.with_list, 3, "{text}");
        assert_eq!(census.with_list_unnamed, 3, "a name in the base is what spilled: {text}");
        assert_eq!(census.extension_records, 3, "{text}");
        assert!(census.base_records >= 3, "{text}");
        assert_eq!(census.with_list_si_reparse_no_attribute, 0, "{text}");
        assert!(text.contains("<- widest gate"), "{text}");
        assert!(text.contains("$MFT records with an $ATTRIBUTE_LIST"), "{text}");

        let mut followed = Vec::new();
        let with_follow = mm_raw::diag::attribute_lists(&volume, true, &mut followed).unwrap();
        assert_eq!(with_follow.with_list, census.with_list);
    }

    #[test]
    fn a_record_beyond_the_mft_is_refused_in_words() {
        let mut builder = Builder::new();
        windows(&mut builder);
        let (text, findings) =
            run_mft(builder, MftQuery { record: Some(u64::MAX), ..MftQuery::default() });
        assert!(text.contains("THE RECORD WOULD NOT READ"), "{text}");
        assert_eq!(findings.records_the_walk_loses, 1);
        assert!(!findings.reaches_root);
    }

    #[test]
    fn the_command_line_the_winre_session_needed_parses() {
        let cli = Cli::parse_from(["malmathic", "diag", "mft", "--record", "133583"]);
        let Some(crate::Command::Diag { what: Diagnostic::Mft { record, path, children, target } }) =
            &cli.command
        else {
            panic!("expected a diag mft command");
        };
        assert_eq!(*record, Some(133_583));
        assert_eq!(*path, None);
        assert!(!*children);
        assert_eq!(target.volume, None, "no volume named means auto-detect");
        assert_eq!(target.image, None);
    }

    #[test]
    fn a_diagnostic_takes_the_same_volume_selection_as_the_analysis() {
        for name in ["D:", "0b1c2d3e"] {
            let cli = Cli::parse_from(["malmathic", "diag", "attribute-lists", "--volume", name]);
            let Some(crate::Command::Diag { what: Diagnostic::AttributeLists { target, .. } }) =
                &cli.command
            else {
                panic!("expected a diag attribute-lists command");
            };
            assert_eq!(target.volume.as_deref(), Some(name));
        }

        let cli =
            Cli::parse_from(["malmathic", "diag", "mft", "--record", "5", "--image", "d.img"]);
        let Some(crate::Command::Diag { what: Diagnostic::Mft { target, .. } }) = &cli.command
        else {
            panic!("expected a diag mft command");
        };
        assert_eq!(target.image.as_deref(), Some(std::path::Path::new("d.img")));

        assert!(Cli::try_parse_from([
            "malmathic",
            "diag",
            "mft",
            "--record",
            "5",
            "--image",
            "d.img",
            "--volume",
            "D:"
        ])
        .is_err());
    }

    #[test]
    fn a_capture_does_not_overwrite_unless_it_is_told_to() {
        let cli = Cli::parse_from(["malmathic", "diag", "lzx-capture", "--out", "E:\\lzx.mmcap"]);
        let Some(crate::Command::Diag { what: Diagnostic::LzxCapture { overwrite, out, .. } }) =
            &cli.command
        else {
            panic!("expected a diag lzx-capture command");
        };
        assert!(!overwrite, "a plain capture refuses to replace what is there");
        assert_eq!(out, std::path::Path::new("E:\\lzx.mmcap"));

        let insisted = Cli::parse_from([
            "malmathic",
            "diag",
            "lzx-capture",
            "--out",
            "E:\\lzx.mmcap",
            "--overwrite",
        ]);
        let Some(crate::Command::Diag { what: Diagnostic::LzxCapture { overwrite, .. } }) =
            &insisted.command
        else {
            panic!("expected a diag lzx-capture command");
        };
        assert!(overwrite);

        let mut command = Cli::command();
        let diag = command.find_subcommand_mut("diag").expect("diag is a subcommand");
        let capture = diag.find_subcommand_mut("lzx-capture").expect("lzx-capture is a subcommand");
        let help = capture.render_long_help().to_string();
        assert!(help.contains("--overwrite"), "{help}");
        assert!(help.contains("must not already exist"), "{help}");
    }

    #[test]
    fn a_bare_command_line_is_still_a_triage_run() {
        let cli = Cli::parse_from(["malmathic"]);
        assert!(cli.command.is_none());
        let cli = Cli::parse_from(["malmathic", "--json", "--out", "E:\\case"]);
        assert!(cli.command.is_none());
        assert!(cli.json);
    }

    #[test]
    fn help_names_the_diagnostics_and_how_the_volume_is_found() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("diag"), "{help}");
        assert!(help.contains("malmathic diag --help"), "{help}");
        assert!(help.contains("drive letters"), "{help}");

        let mut diag = Cli::command();
        let diag = diag.find_subcommand_mut("diag").expect("diag is a subcommand");
        let text = diag.render_long_help().to_string();
        for expected in ["mft", "attribute-lists", "lzx-capture", "lzx-describe"] {
            assert!(text.contains(expected), "`{expected}` missing from: {text}");
        }
    }

    #[test]
    fn an_unopenable_image_is_refused_with_a_reason() {
        let target = TargetArgs {
            volume: None,
            image: Some(std::env::temp_dir().join("malmathic-no-such-image.img")),
        };
        assert!(open_target(&target).is_err());
    }

    #[test]
    fn the_suggestion_names_a_volume_that_exists() {
        let volumes = winre_shaped_volumes();
        assert!(suggestion(&volumes).contains("--volume D:"), "{}", suggestion(&volumes));

        assert_eq!(suggestion(&[]), "", "no suggestion is better than one nobody can follow");
        let locked = vec![discovered("C", mm_env::VolumeStatus::Locked)];
        assert_eq!(suggestion(&locked), "");
    }

    fn discovered(name: &str, status: mm_env::VolumeStatus) -> mm_env::DiscoveredVolume {
        mm_env::DiscoveredVolume {
            device_path: format!("\\\\?\\Volume{{{name}}}"),
            mount_points: vec![format!("{name}:\\")],
            status,
        }
    }

    fn winre_shaped_volumes() -> Vec<mm_env::DiscoveredVolume> {
        vec![
            discovered(
                "C",
                mm_env::VolumeStatus::NtfsNoWindows {
                    serial: 0x1122,
                    reason: "no \\Windows\\System32\\config\\SYSTEM".into(),
                },
            ),
            discovered(
                "D",
                mm_env::VolumeStatus::WindowsInstall { serial: 0x3344, cluster_size: 4096 },
            ),
            discovered("X", mm_env::VolumeStatus::NotNtfs(mm_raw::VolumeKind::Fat)),
        ]
    }

    #[test]
    fn naming_the_wrong_volume_prints_the_volumes_that_were_found() {
        let volumes = winre_shaped_volumes();
        let text = no_volume_message(&volumes, Some("C"));

        assert!(text.contains("Volumes (3 found)"), "{text}");
        assert!(text.contains("D:"), "the volume that does hold Windows is named: {text}");
        assert!(text.contains("No volume matches `C`"), "{text}");
        assert!(
            text.contains("WinRE assigns its own drive letters"),
            "it says why the letter is wrong: {text}"
        );
        assert!(text.contains("Try:  malmathic diag … --volume D:"), "{text}");
    }

    #[test]
    fn finding_no_windows_volume_still_lists_what_was_found() {
        let volumes = vec![discovered("C", mm_env::VolumeStatus::Locked)];
        let text = no_volume_message(&volumes, None);
        assert!(text.contains("BitLocker, LOCKED"), "{text}");
        assert!(text.contains("manage-bde -unlock"), "{text}");
        assert!(text.contains("Name one of the volumes above with --volume"), "{text}");
        assert!(!text.contains("Try:  malmathic"), "no suggestion nobody can follow: {text}");
    }

    #[test]
    #[ignore = "prints a transcript rather than asserting anything"]
    fn show_the_failure_messages() {
        println!("--- wrong volume named ---");
        print!("{}", no_volume_message(&winre_shaped_volumes(), Some("C")));
        println!("--- nothing found ---");
        print!("{}", no_volume_message(&[discovered("C", mm_env::VolumeStatus::Locked)], None));
    }

    #[test]
    #[ignore = "writes a fixture image rather than asserting anything"]
    fn write_the_synthetic_volume_for_a_manual_run() {
        let (mut builder, pak, orphaned) = chrome_with_a_leftover();
        builder.set_parent_sequence(orphaned, THEN);
        let magician =
            builder.directories(ROOT_RECORD, "Program Files (x86)\\Samsung\\Samsung Magician");
        builder.resident_file(magician, "Magician.exe", b"MZ", Presence::Live);
        builder.spill_index(magician, IndexLayout::RootInExtension);
        builder.spill_file_name(magician);

        let path = std::env::temp_dir().join("malmathic-diag.img");
        std::fs::write(&path, builder.bytes()).expect("the fixture writes");
        println!("wrote {}", path.display());
        println!("  the leftover directory record is {orphaned}, naming record {pak}");
        println!("  Samsung Magician, whose $FILE_NAME spilled, is record {magician}");

        let mut stream = 60u32.to_le_bytes().to_vec();
        stream.extend_from_slice(&[0u8; 200]);
        let capture = mm_env::capture::write_capture(&[mm_env::capture::Sample {
            path: "\\Windows\\System32\\example.dll".into(),
            provider: 2,
            algorithm: mm_raw::wof::ALGORITHM_LZX,
            declared: 40_000,
            stream,
            plain: b"MZ".iter().copied().chain(std::iter::repeat_n(0x90, 39_998)).collect(),
        }]);
        let capture_path = std::env::temp_dir().join("malmathic-diag.mmcap");
        std::fs::write(&capture_path, capture).expect("the capture writes");
        println!("wrote {}", capture_path.display());
    }
}
