mod acquire;
#[cfg(test)]
mod after_cleanup;
#[cfg(test)]
mod arrival_wiring;
mod casedir;
#[cfg(test)]
mod compact_os;
mod console;
mod deep;
#[cfg(test)]
mod deep_carve;
#[cfg(test)]
mod degraded;
#[cfg(test)]
mod deleted_index_entries;
mod diag;
#[cfg(test)]
mod encrypted;
mod explain;
#[cfg(test)]
mod ghost_recovery;
#[cfg(test)]
mod hostile_data;
#[cfg(test)]
mod hostile_index;
#[cfg(test)]
mod index_completeness;
mod index_slack;
#[cfg(test)]
mod junctions;
#[cfg(test)]
mod lost_directories;
#[cfg(test)]
mod matrix;
#[cfg(test)]
mod orphaned_deleted;
#[cfg(test)]
mod other_volume;
mod pipeline;
mod progress;
#[cfg(test)]
mod recovery_states;
#[cfg(test)]
mod recycle_bin_recovery;
mod redact;
#[cfg(test)]
mod scenario;
#[cfg(test)]
mod spilled_index;
#[cfg(test)]
mod stale_parents;
#[cfg(test)]
mod task_sweep;
#[cfg(test)]
mod testimage;
#[cfg(test)]
mod usn_wiring;

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};
use mm_env::{DiscoveredVolume, Environment, VolumeStatus};
use mm_raw::Volume;
use mm_report::Target;

#[derive(Parser)]
#[command(
    name = "malmathic",
    version,
    about = "Finds the most likely malware sample on an infected Windows machine",
    long_about = "Reads forensic artifacts straight from NTFS and the registry hives, ranks \
                  candidate files by probability with the reasoning shown, and recovers the \
                  sample — or at least its hash — when the file itself is gone.\n\n\
                  Works on a live system and from a WinRE command prompt. Never touches the \
                  network. The analysis never writes to the volume it is reading; the case \
                  directory does if you leave it there, which the run says out loud and \
                  --deep refuses outright. Point --out at other media.\n\n\
                  A case directory that already holds a report or a sample\\ is never \
                  overwritten: that is refused, and --overwrite-case is the only way past \
                  it.\n\n\
                  With no subcommand it triages the machine. `malmathic explain <feature>` \
                  prints the weight behind any feature id a report names, why it is \
                  that number, and how often it fires on a machine known to be clean; \
                  it reads nothing and needs no volume. `malmathic redact <report.json>` \
                  writes a copy with user names, machine names, SIDs, volume ids and case \
                  paths pseudonymised, so a report can be shared. `malmathic diag` holds the \
                  per-component diagnostics: why the $MFT walk lost a directory and whether a \
                  parent reference is stale, the $ATTRIBUTE_LIST census, and the Compact-OS \
                  capture. They take the same --volume and the same auto-detection as the \
                  analysis, because WinRE assigns its own drive letters and nobody at a \
                  recovery console should have to guess one. Run `malmathic diag --help` \
                  there; with no network it is the only documentation you have."
)]
struct Cli {
    /// Diagnostics instead of a triage run. See `malmathic diag --help`.
    #[command(subcommand)]
    command: Option<Command>,

    /// Case directory. Default: cases\<volume>-<time> on the drive holding the exe; a double-click launch asks first; required with --image.
    #[arg(long, short)]
    out: Option<PathBuf>,

    /// Destroy an existing case directory and write this run in its place.
    #[arg(long)]
    overwrite_case: bool,

    /// Analyze this volume instead of the one found automatically.
    #[arg(long)]
    volume: Option<String>,

    /// Analyze a raw disk image instead of an attached device.
    #[arg(long, conflicts_with_all = ["volume", "list_volumes"])]
    image: Option<PathBuf>,

    /// List every volume and what was found on it, then exit.
    #[arg(long)]
    list_volumes: bool,

    /// List the snapshot chain behind an `--image` VMDK and exit.
    #[arg(long, requires = "image")]
    list_snapshots: bool,

    /// How many top-ranked candidates to try to recover samples for.
    #[arg(long, default_value_t = 10)]
    acquire_top: usize,

    /// Recover and hash the samples, but do not write them into the case
    /// directory.
    #[arg(long)]
    no_samples: bool,

    /// Also write report.redacted.txt and .json into the case directory, with
    /// user names, machine names, SIDs and volume ids pseudonymised.
    #[arg(long)]
    redact: bool,

    /// Also search the volume's unallocated clusters for the bytes of files
    /// the ordinary recovery chain could not reach.
    #[arg(long)]
    deep: bool,

    /// How far down the ranked list to verify code signatures.
    #[arg(long, default_value_t = 200)]
    verify_top: usize,

    /// Print the machine-readable report instead of the human one.
    #[arg(long)]
    json: bool,

    /// Suppress per-stage progress on stderr.
    #[arg(long)]
    quiet: bool,

    /// Wait for Enter before exiting, whatever the console looks like.
    #[arg(long, overrides_with = "no_pause")]
    pause: bool,

    /// Never wait for Enter: neither for the case directory nor at the end.
    #[arg(long, overrides_with = "pause")]
    no_pause: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Per-component diagnostics for a volume, for use at a WinRE console.
    Diag {
        #[command(subcommand)]
        what: diag::Diagnostic,
    },

    /// Print the weight behind a feature id in a report, and the measurement
    /// behind that weight.
    Explain {
        /// Feature ids, as printed beside the evidence rows in a report.
        #[arg(value_name = "FEATURE")]
        features: Vec<String>,
    },

    /// Write a copy of a report.json with user names, machine names, SIDs,
    /// volume ids and case paths pseudonymised, fit to share.
    Redact {
        /// The report.json to redact.
        report: PathBuf,

        /// Where to write the redacted JSON; its .txt twin goes beside it.
        /// Defaults to <name>.redacted.json next to the input.
        #[arg(long, short)]
        out: Option<PathBuf>,

        /// Replace an existing redacted report.
        #[arg(long)]
        overwrite: bool,

        /// Keep URLs whole instead of cutting them to their host.
        #[arg(long)]
        keep_urls: bool,
    },
}

impl Cli {
    fn pause_request(&self) -> Option<bool> {
        match (self.pause, self.no_pause) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = triage(&cli);
    console::pause_if_the_window_will_close(cli.pause_request());
    code
}

fn triage(cli: &Cli) -> ExitCode {
    let environment = Environment::detect();

    eprintln!("malmathic {} · {}", env!("CARGO_PKG_VERSION"), environment.label());

    if let Some(Command::Diag { what }) = &cli.command {
        return diag::run(what);
    }

    if let Some(Command::Explain { features }) = &cli.command {
        return explain::run(features);
    }

    if let Some(Command::Redact { report, out, overwrite, keep_urls }) = &cli.command {
        return redact::run(report, out.as_deref(), *overwrite, *keep_urls);
    }

    if cli.image.is_none() && !environment.can_read_raw_volumes() {
        eprintln!(
            "\nmalmathic needs administrator rights to read volumes directly.\n\
             \n\
             Reading raw NTFS is not optional — it is how the tool reaches files\n\
             Windows has locked, and how it works when no registry is mounted.\n\
             \n\
             Re-run from an elevated prompt, or boot into WinRE and run it there\n\
             (in WinRE it is already privileged, and the malware cannot interfere)."
        );
        return ExitCode::FAILURE;
    }

    match run(cli, environment) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli, environment: Environment) -> mm_core::Result<ExitCode> {
    if let Some(image) = &cli.image {
        return run_image(cli, image);
    }

    let volumes = mm_env::discover_volumes()?;

    if cli.list_volumes {
        eprint!("{}", render_volumes(&volumes));
        return Ok(ExitCode::SUCCESS);
    }

    let Some(chosen) = choose_volume(&volumes, cli.volume.as_deref()) else {
        eprint!("{}", render_volumes(&volumes));
        report_no_target(&volumes);
        return Ok(ExitCode::FAILURE);
    };

    eprintln!("Target: {} ({})", chosen.display_name(), chosen.device_path);
    let Some(case) = place_case(cli, environment, chosen) else {
        return Ok(ExitCode::FAILURE);
    };
    eprintln!("Case:   {}\n", case.path().display());
    for warning in case.warnings() {
        eprintln!("{warning}\n");
    }
    eprintln!(
        "Reading artifacts and walking the filesystem; this takes a few minutes.\n\
         Each stage prints what it read and what it cost."
    );

    let volume = mm_env::open_volume(&chosen.device_path)?;
    let target = Target {
        display_name: chosen.display_name(),
        device_path: chosen.device_path.clone(),
        volume_serial: format!("{:016x}", volume.serial()),
    };
    Ok(analyze(cli, &case, &volume, environment, target))
}

fn run_image(cli: &Cli, image: &Path) -> mm_core::Result<ExitCode> {
    if cli.out.is_none() && !cli.list_snapshots {
        eprintln!("\n{}", casedir::image_needs_out(image));
        return Ok(ExitCode::FAILURE);
    }

    let moment = describe_chain(image, cli.list_snapshots);
    if cli.list_snapshots {
        if moment.is_none() {
            eprintln!("{} is not a VMDK chain, so it has no snapshots to list.", image.display());
            return Ok(ExitCode::FAILURE);
        }
        return Ok(ExitCode::SUCCESS);
    }

    let partitions = mm_env::find_ntfs_partitions(image)?;
    if partitions.is_empty() {
        eprintln!("No NTFS partition found in {}.", image.display());
        return Ok(ExitCode::FAILURE);
    }
    eprintln!("{} NTFS partition(s) in {}", partitions.len(), image.display());

    let mut chosen = None;
    for partition in &partitions {
        match mm_env::open_partition(image, *partition) {
            Ok(volume) => {
                let windows = volume.is_windows_install();
                eprintln!(
                    "  offset {:<12} NTFS, {}",
                    partition.offset,
                    if windows { "Windows installation" } else { "no Windows" }
                );
                if windows && chosen.is_none() {
                    chosen = Some((*partition, volume));
                }
            }
            Err(e) => eprintln!("  offset {:<12} unreadable: {e}", partition.offset),
        }
    }

    let Some((partition, volume)) = chosen else {
        eprintln!("\n{}", mm_core::Error::NoWindowsVolume);
        return Ok(ExitCode::FAILURE);
    };

    let requested = cli.out.clone().unwrap_or_else(|| casedir::beside_the_image(image));
    let case = match casedir::prepare_case(
        &requested,
        &casedir::Location::detect(),
        &[],
        cli.deep,
        cli.overwrite_case,
    ) {
        Ok(plan) => plan,
        Err(refusal) => {
            eprintln!("\n{refusal}");
            return Ok(ExitCode::FAILURE);
        }
    };
    eprintln!("\nCase: {}\n", case.path().display());
    for warning in case.warnings() {
        eprintln!("{warning}\n");
    }
    if !cli.no_samples {
        eprintln!("{}", image_sample_notice(case.path()));
    }

    let base = format!("{}@{}", image.display(), partition.offset);
    let display_name = match &moment {
        Some(moment) => format!("{base} — {moment}"),
        None => base,
    };
    let target = Target {
        display_name,
        device_path: image.display().to_string(),
        volume_serial: format!("{:016x}", volume.serial()),
    };
    Ok(analyze(cli, &case, &volume, Environment::Image, target))
}

fn analyze<R: Read + Seek>(
    cli: &Cli,
    case: &casedir::Plan,
    volume: &Volume<R>,
    environment: Environment,
    target: Target,
) -> ExitCode {
    let output_dir = case.path().to_path_buf();
    let options = pipeline::Options {
        output_dir: output_dir.clone(),
        acquire_top: cli.acquire_top,
        write_samples: !cli.no_samples,
        deep: cli.deep,
        verify_top: cli.verify_top,
        progress: if cli.quiet { progress::Style::Silent } else { progress::Style::detect() },
    };

    let started = Instant::now();
    let mut report = pipeline::run(volume, environment, target, &options);
    seal_run(started, &output_dir, &mut report);
    let written = write_case(case, &report, cli.redact);

    if cli.json {
        println!("{}", report.to_json());
    } else {
        println!("{}", mm_report::text::render(&report));
    }
    console::closing_summary(&report);
    if written {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn describe_chain(image: &Path, full: bool) -> Option<String> {
    let Ok(mm_env::ImageFile::Vmdk(vmdk)) = mm_env::ImageFile::open(image) else {
        return None;
    };
    let view = mm_env::SnapshotView::of(image, vmdk.info());
    eprintln!("{}", vmdk.info().summary());
    eprint!("{}", view.describe());
    if !view.times_agree_with_chain() {
        eprintln!(
            "  NOTE: the recorded snapshot times do not run the same way the chain does.\n  \
             The chain is verified by content id and is what was read; the names and\n  \
             times come from a host-side file that disagrees with it."
        );
    }
    if full {
        let dir = image.parent().unwrap_or(Path::new("."));
        eprint!("{}", view.available(dir));
    }
    eprintln!("\n{}\n", view.provenance());
    view.top().map(|link| link.moment.describe())
}

fn choose_volume<'a>(
    volumes: &'a [DiscoveredVolume],
    requested: Option<&str>,
) -> Option<&'a DiscoveredVolume> {
    if let Some(want) = requested {
        let want_lower = want.to_ascii_lowercase();
        return volumes.iter().find(|v| {
            v.device_path.to_ascii_lowercase().contains(&want_lower)
                || v.display_name().to_ascii_lowercase().starts_with(&want_lower)
        });
    }
    volumes.iter().find(|v| v.status.holds_windows())
}

fn render_volumes(volumes: &[DiscoveredVolume]) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(out, "Volumes ({} found):", volumes.len());
    for volume in volumes {
        let name = volume.display_name();
        match &volume.status {
            VolumeStatus::WindowsInstall { serial, cluster_size } => {
                let _ = writeln!(out, "  {name:<20} NTFS, Windows installation");
                let _ = writeln!(
                    out,
                    "  {:<20}   serial {serial:016x}, {cluster_size}-byte clusters",
                    ""
                );
            }
            VolumeStatus::NtfsNoWindows { reason, .. } => {
                let _ = writeln!(out, "  {name:<20} NTFS, no Windows");
                let _ = writeln!(out, "  {:<20}   {reason}", "");
            }
            VolumeStatus::Locked => {
                let _ = writeln!(out, "  {name:<20} BitLocker, LOCKED");
                let _ = writeln!(
                    out,
                    "  {:<20}   unlock first:  manage-bde -unlock {name} -RecoveryPassword <key>",
                    ""
                );
            }
            VolumeStatus::NotNtfs(kind) => {
                let _ = writeln!(out, "  {name:<20} {} — not analyzable", kind.label());
            }
            VolumeStatus::Inaccessible(reason) => {
                let _ = writeln!(out, "  {name:<20} unreadable: {reason}");
            }
        }
    }
    let _ = writeln!(out);
    out
}

fn report_no_target(volumes: &[DiscoveredVolume]) {
    let locked = volumes.iter().filter(|v| matches!(v.status, VolumeStatus::Locked)).count();
    if locked > 0 {
        eprintln!(
            "No Windows installation is reachable: {locked} volume(s) are BitLocker-locked.\n\
             Unlock them with `manage-bde -unlock` and run again."
        );
    } else {
        eprintln!("{}", mm_core::Error::NoWindowsVolume);
    }
}

fn image_sample_notice(output_dir: &Path) -> String {
    format!(
        "! This run will write recovered samples into {}\\sample\\.\n\
         ! Those bytes are the malware itself, unmodified, and your own antivirus\n\
         ! will see them land. --no-samples reads and hashes them without writing\n\
         ! any of it out: same candidates, same scores, same evidence, same\n\
         ! SHA-256/SHA-1/MD5 — only the copy is missing.\n",
        output_dir.display()
    )
}

fn place_case(
    cli: &Cli,
    environment: Environment,
    chosen: &DiscoveredVolume,
) -> Option<casedir::Plan> {
    let location = casedir::Location::detect();
    let suggested = suggest_output_dir(cli, &location, &chosen.display_name());
    let asking =
        cli.out.is_none() && console::should_ask(cli.pause_request(), console::Console::detect());
    if asking {
        media_notes(environment, &suggested);
        volume_note(&suggested, &chosen.mount_points, cli.deep);
    }
    let mut offer = Some(suggested.as_path());
    for attempt in 1..=3 {
        let requested =
            if asking { console::ask_case_directory(offer)? } else { suggested.clone() };
        if !asking || requested != suggested {
            media_notes(environment, &requested);
        }
        match casedir::prepare_case(
            &requested,
            &location,
            &chosen.mount_points,
            cli.deep,
            cli.overwrite_case,
        ) {
            Ok(plan) => return Some(plan),
            Err(refusal) => {
                eprintln!("\n{refusal}\n");
                if !asking || attempt == 3 {
                    return None;
                }
                if requested == suggested {
                    offer = None;
                }
            }
        }
    }
    None
}

fn suggest_output_dir(cli: &Cli, location: &casedir::Location, volume: &str) -> PathBuf {
    match &cli.out {
        Some(explicit) => explicit.clone(),
        None => casedir::suggest_case(location, volume, &casedir::stamp(chrono::Local::now())),
    }
}

fn media_notes(environment: Environment, case: &Path) {
    warn_if_volatile(environment, case);
    warn_if_remote(case);
}

fn warn_if_volatile(environment: Environment, case: &Path) {
    if environment != Environment::Recovery {
        return;
    }
    let Ok(system_drive) = std::env::var("SystemDrive") else { return };
    if casedir::drive_of(case).is_some_and(|drive| drive.eq_ignore_ascii_case(&system_drive)) {
        eprintln!(
            "! {} is on {system_drive}, the recovery environment's RAM disk, and will\n\
             ! be lost on reboot. Put the case on other media: --out <drive>:\\cases\\<name>\n",
            case.display()
        );
    }
}

fn warn_if_remote(case: &Path) {
    if casedir::is_remote(case) {
        eprintln!(
            "! {} is on a network share: the case, live samples included, would cross\n\
             ! the network and sit where other machines can reach it. Other media is\n\
             ! better: --out <drive>:\\cases\\<name>\n",
            case.display()
        );
    }
}

fn volume_note(suggested: &Path, mounts: &[String], deep: bool) {
    let Some(mount) = casedir::overlapping_mount(suggested, mounts) else { return };
    if deep {
        eprintln!(
            "! {} is on {mount}, the volume --deep would carve, so it will be refused.\n\
             ! Type a directory on other media.\n",
            suggested.display()
        );
    } else {
        eprintln!(
            "! {} is on {mount}, the volume being analysed. Other media is better;\n\
             ! Enter accepts it anyway.\n",
            suggested.display()
        );
    }
}

fn seal_run(started: Instant, output_dir: &Path, report: &mut mm_report::Report) {
    report.set_wall_clock(started.elapsed().as_secs_f64());

    let case_dir = match std::fs::canonicalize(output_dir) {
        Ok(resolved) => {
            let shown = resolved.display().to_string();
            match shown.strip_prefix(r"\\?\") {
                Some(stripped) => stripped.to_string(),
                None => shown,
            }
        }
        Err(_) => output_dir.display().to_string(),
    };
    report.set_case_directory(case_dir);
}

fn write_case(case: &casedir::Plan, report: &mm_report::Report, redact: bool) -> bool {
    let output_dir = case.path();
    if let Err(e) = std::fs::create_dir_all(output_dir) {
        eprintln!("error: could not create {}: {e}", output_dir.display());
        return false;
    }
    let write = |name: &str, contents: String| match std::fs::write(output_dir.join(name), contents)
    {
        Ok(()) => true,
        Err(e) => {
            eprintln!("error: could not write {name}: {e}");
            false
        }
    };
    let text = write("report.txt", mm_report::text::render(report));
    let json = write("report.json", report.to_json());
    let mut redacted_pair = true;
    if redact {
        match mm_report::redact::redact(report, mm_report::redact::Options::default()) {
            Ok((redacted, _)) => {
                redacted_pair = write("report.redacted.txt", mm_report::text::render(&redacted))
                    & write("report.redacted.json", redacted.to_json());
            }
            Err(e) => {
                eprintln!("error: could not redact the report: {e}");
                redacted_pair = false;
            }
        }
    }
    text && json && redacted_pair
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(name: &str, status: VolumeStatus) -> DiscoveredVolume {
        DiscoveredVolume {
            device_path: format!("\\\\?\\Volume{{{name}}}"),
            mount_points: vec![format!("{name}:\\")],
            status,
        }
    }

    fn windows(name: &str) -> DiscoveredVolume {
        volume(name, VolumeStatus::WindowsInstall { serial: 1, cluster_size: 4096 })
    }

    #[test]
    fn the_windows_volume_is_chosen_over_data_volumes() {
        let volumes = vec![
            volume("W", VolumeStatus::NtfsNoWindows { serial: 2, reason: String::new() }),
            volume("S", VolumeStatus::Locked),
            windows("C"),
        ];
        assert_eq!(choose_volume(&volumes, None).unwrap().display_name(), "C:");
    }

    #[test]
    fn no_windows_volume_means_no_target() {
        let volumes =
            vec![volume("W", VolumeStatus::NtfsNoWindows { serial: 2, reason: String::new() })];
        assert!(choose_volume(&volumes, None).is_none());
        assert!(choose_volume(&[], None).is_none());
    }

    #[test]
    fn an_explicit_volume_overrides_the_automatic_choice() {
        let volumes = vec![
            windows("C"),
            volume("W", VolumeStatus::NtfsNoWindows { serial: 2, reason: String::new() }),
        ];
        assert_eq!(choose_volume(&volumes, Some("W")).unwrap().display_name(), "W:");
        assert_eq!(choose_volume(&volumes, Some("w:")).unwrap().display_name(), "W:");
        assert!(choose_volume(&volumes, Some("Z")).is_none());
    }

    #[test]
    fn a_volume_can_be_chosen_by_its_guid() {
        let volumes = vec![windows("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fa")];
        assert!(choose_volume(&volumes, Some("0b1c2d3e")).is_some());
    }

    fn tool_at(dir: &str) -> casedir::Location {
        casedir::Location { source_tree: None, binary_dir: Some(PathBuf::from(dir)) }
    }

    #[test]
    fn an_explicit_output_directory_is_respected() {
        let cli = Cli::parse_from(["malmathic", "--out", "D:\\case"]);
        assert_eq!(
            suggest_output_dir(&cli, &tool_at(r"E:\tools"), "C:"),
            PathBuf::from("D:\\case")
        );
    }

    #[test]
    fn the_wall_clock_and_case_directory_reach_the_saved_report() {
        let mut report = mm_report::Report::new(
            "0.1.0",
            "WinRE",
            Target {
                display_name: "D:".into(),
                device_path: "\\\\?\\Volume{a}".into(),
                volume_serial: "0".into(),
            },
            Vec::new(),
            mm_report::Coverage::default(),
            false,
        );
        assert!(report.wall_clock_seconds.is_none());

        let out = std::env::temp_dir().join("malmathic-seal-run-test");
        std::fs::create_dir_all(&out).unwrap();
        seal_run(Instant::now(), &out, &mut report);

        assert!(report.wall_clock_seconds.unwrap() >= 0.0);
        assert!(report.case_directory.is_some());

        let json = report.to_json();
        assert!(json.contains("wall_clock_seconds"), "{json}");
        assert!(json.contains("case_directory"), "{json}");

        let dir = report.case_directory.unwrap();
        assert!(Path::new(&dir).is_absolute(), "{dir}");
        assert!(!dir.starts_with(r"\\?\"), "{dir}");

        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn overwriting_a_case_is_never_the_default() {
        assert!(!Cli::parse_from(["malmathic"]).overwrite_case);
        assert!(Cli::parse_from(["malmathic", "--overwrite-case"]).overwrite_case);
    }

    #[test]
    fn an_image_run_has_no_output_default_and_a_live_run_is_offered_one_on_the_tools_drive() {
        let over_an_image = Cli::parse_from(["malmathic", "--image", "disk.vmdk"]);
        assert!(over_an_image.out.is_none(), "nothing to fall back on, on purpose");

        let live = Cli::parse_from(["malmathic"]);
        let suggested = suggest_output_dir(&live, &tool_at(r"E:\tools"), "C:");
        assert!(suggested.starts_with(r"E:\cases"), "{}", suggested.display());
        let name = suggested.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("C-20"), "{name}");
        assert_eq!(name.len(), "C-20260830-164205".len(), "{name}");
    }

    #[test]
    fn the_image_refusal_names_the_image_and_a_directory_beside_it() {
        let cli =
            Cli::parse_from(["malmathic", "--image", r"D:\vms\njrat\snapshot4\njrat-000004.vmdk"]);
        let image = cli.image.as_deref().expect("--image was given");
        assert!(cli.out.is_none(), "which is what run_image refuses on");

        let text = casedir::image_needs_out(image).to_string();
        assert!(text.contains(r"D:\vms\njrat\snapshot4\njrat-000004.vmdk"), "{text}");
        assert!(text.contains(r"D:\vms\njrat\snapshot4\njrat-000004-case"), "{text}");
        assert!(text.contains("--out"), "{text}");
    }

    #[test]
    fn listing_snapshots_needs_no_output_directory() {
        let cli = Cli::parse_from(["malmathic", "--image", "disk.vmdk", "--list-snapshots"]);
        assert!(cli.list_snapshots);
        assert!(cli.out.is_none());
    }

    #[test]
    fn a_report_can_be_redacted_from_the_command_line() {
        let cli = Cli::parse_from(["malmathic", "redact", r"E:\case\report.json", "--keep-urls"]);
        let Some(Command::Redact { report, out, overwrite, keep_urls }) = &cli.command else {
            panic!("expected a redact command");
        };
        assert_eq!(report, Path::new(r"E:\case\report.json"));
        assert!(out.is_none());
        assert!(!overwrite);
        assert!(keep_urls);
        assert!(!Cli::parse_from(["malmathic"]).redact, "the sharable copy is opt-in");
        assert!(Cli::parse_from(["malmathic", "--redact"]).redact);
    }

    #[test]
    fn defaults_are_sensible() {
        let cli = Cli::parse_from(["malmathic"]);
        assert!(cli.out.is_none());
        assert!(!cli.overwrite_case, "nothing is destroyed unless it was asked for");
        assert!(!cli.json);
        assert!(!cli.quiet, "progress is on unless the user turns it off");
        assert_eq!(cli.acquire_top, 10);
        assert_eq!(cli.verify_top, 200);
        assert_eq!(cli.pause_request(), None, "with no flag the console decides");
        assert!(!cli.no_samples, "a plain run keeps the sample it recovers");
    }

    #[test]
    fn no_samples_stops_the_bytes_reaching_the_case_directory() {
        let plain = Cli::parse_from(["malmathic"]);
        let held = Cli::parse_from(["malmathic", "--no-samples"]);
        assert!(!plain.no_samples, "a plain run writes samples");
        assert!(held.no_samples, "--no-samples withholds them");

        let over_an_image = Cli::parse_from(["malmathic", "--image", "disk.vmdk", "--no-samples"]);
        assert!(over_an_image.no_samples);
        assert_eq!(over_an_image.image.as_deref(), Some(Path::new("disk.vmdk")));
    }

    #[test]
    fn an_image_run_offers_no_samples_and_never_assumes_it() {
        let dir = Path::new(r"D:\vms\njrat\snapshot4\njrat-000004-case");
        let notice = image_sample_notice(dir);
        assert!(notice.contains(r"D:\vms\njrat\snapshot4\njrat-000004-case\sample\"), "{notice}");
        assert!(notice.contains("--no-samples"), "{notice}");

        let over_an_image = Cli::parse_from(["malmathic", "--image", "disk.vmdk"]);
        assert!(
            !over_an_image.no_samples,
            "--image must not imply --no-samples; a silent change to what the case \
             directory holds is the defect this tool keeps fixing"
        );
    }

    #[test]
    fn either_pause_flag_overrides_the_console_and_neither_is_the_default() {
        assert_eq!(Cli::parse_from(["malmathic", "--pause"]).pause_request(), Some(true));
        assert_eq!(Cli::parse_from(["malmathic", "--no-pause"]).pause_request(), Some(false));
    }

    #[test]
    fn the_last_pause_flag_wins() {
        assert_eq!(
            Cli::parse_from(["malmathic", "--pause", "--no-pause"]).pause_request(),
            Some(false)
        );
        assert_eq!(
            Cli::parse_from(["malmathic", "--no-pause", "--pause"]).pause_request(),
            Some(true)
        );
    }
}
