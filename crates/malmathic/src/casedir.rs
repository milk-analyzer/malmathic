use std::ffi::OsString;
use std::path::{Component, Path, PathBuf, Prefix, PrefixComponent};

#[derive(Clone, Debug, Default)]
pub struct Location {
    pub source_tree: Option<PathBuf>,
    pub binary_dir: Option<PathBuf>,
}

impl Location {
    pub fn detect() -> Self {
        let built_from = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .filter(|root| root.is_dir())
            .map(Path::to_path_buf);
        Self {
            source_tree: built_from,
            binary_dir: std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf)),
        }
    }

    #[cfg(test)]
    pub fn nowhere() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug)]
pub enum Refusal {
    Occupied { dir: PathBuf, found: Vec<&'static str> },
    FileExists { path: PathBuf, bytes: u64, what: &'static str },
    InSourceTree { target: PathBuf, tree: PathBuf, what: &'static str },
    BesideBinary { target: PathBuf, binary_dir: PathBuf, what: &'static str },
    OnVolumeBeingCarved { target: PathBuf, mount: String },
    ImageNeedsOut { image: PathBuf, suggestion: PathBuf },
    CouldNotCreate { dir: PathBuf, reason: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Occupied { dir, found } => write!(
                f,
                "Refusing to overwrite a case that is already there.\n\
                 \n  \
                 {}\n  \
                 already holds {}.\n\
                 \n\
                 That is somebody's result — possibly yours, from a machine that has\n\
                 moved on since. Writing this run into it would destroy it, and a\n\
                 destroyed measurement cannot be taken again.\n\
                 \n\
                 Pick one:\n  \
                 --out <a directory that is not that one>\n  \
                 --overwrite-case      destroy what is there and write this run instead\n\
                 \n\
                 malmathic will not make that choice for you.",
                dir.display(),
                english_list(&found.iter().map(|m| as_written(m)).collect::<Vec<_>>()),
            ),
            Refusal::FileExists { path, bytes, what } => {
                let why = if *what == "capture" {
                    "A capture needs a WinRE session and a mounted WOF filter to take, so\n\
                     the one on disk may not be re-takeable from where you are standing.\n\
                     \n"
                } else {
                    ""
                };
                write!(
                    f,
                    "Refusing to overwrite an existing {what}.\n\
                     \n  \
                     {} — {bytes} bytes, already there.\n\
                     \n\
                     {why}Write somewhere else, or pass --overwrite to destroy it.",
                    path.display()
                )
            }
            Refusal::InSourceTree { target, tree, what } => write!(
                f,
                "Refusing to write a {what} inside malmathic's own source tree.\n\
                 \n  \
                 {what}: {}\n  \
                 tree: {}\n\
                 \n\
                 malmathic does not exclude its own output from analysis, on purpose: a\n\
                 build tree full of fresh unsigned executables is exactly what a triage\n\
                 should have an opinion about. That only stays honest if the tool does\n\
                 not also write there. A case in this tree becomes evidence in the next\n\
                 run, and the run after that inherits the one before it.\n\
                 \n\
                 Give --out a directory outside the tree:\n  \
                 --out C:\\cases\\<name>\n\
                 \n\
                 There is no flag for this one. --overwrite-case does not lift it.",
                target.display(),
                tree.display(),
            ),
            Refusal::BesideBinary { target, binary_dir, what } => write!(
                f,
                "Refusing to write a {what} beside the malmathic binary.\n\
                 \n  \
                 {what}: {}\n  \
                 binary: {}\n\
                 \n\
                 The folder holding the tool is what gets copied to the next stick and\n\
                 the next machine. A case in it travels along, and sample\\C001.bin in\n\
                 it is live malware, unmodified. Cases get a folder of their own:\n  \
                 --out <drive>:\\cases\\<name>\n\
                 \n\
                 There is no flag for this one.",
                target.display(),
                binary_dir.display(),
            ),
            Refusal::OnVolumeBeingCarved { target, mount } => write!(
                f,
                "Refusing to write the case onto {mount}, which is the volume being read.\n\
                 \n  \
                 case: {}\n\
                 \n\
                 --deep reads this volume's unallocated clusters, because that is where\n\
                 the bytes of a deleted file still are. Writing the case onto the same\n\
                 volume allocates some of those clusters first — the samples alone run\n\
                 to hundreds of megabytes. The evidence would be destroyed by the act of\n\
                 looking for it.\n\
                 \n  \
                 --out <other drive>:\\cases\\<name>      external media\n\
                 \n\
                 Without --deep the case may be written there, with a warning: an\n\
                 ordinary run does not read free space, so it costs contamination but\n\
                 not the thing it came for.",
                target.display(),
            ),
            Refusal::ImageNeedsOut { image, suggestion } => write!(
                f,
                "--image needs --out.\n\
                 \n\
                 An image is somebody else's disk, and where the case about it goes is\n\
                 not a question this tool may answer by guessing. The guess it used to\n\
                 make — `malmathic-case` in the working directory — put a 2,847-candidate\n\
                 analysis of an infected VM into this project's own repository and\n\
                 destroyed the reference run that was already there.\n\
                 \n\
                 Beside the image is usually right, and would be:\n  \
                 --out \"{}\"\n\
                 \n\
                 That is a suggestion and not a default, because malmathic cannot tell\n\
                 whether\n  \
                 {}\n\
                 sits in a scratch directory or on an evidence store that must not be\n\
                 written to. You can. Say which.",
                suggestion.display(),
                image.display(),
            ),
            Refusal::CouldNotCreate { dir, reason } => write!(
                f,
                "Could not create the case directory {}: {reason}\n\
                 \n\
                 Give --out a directory on media that can be written:\n  \
                 --out <other drive>:\\cases\\<name>",
                dir.display()
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Plan {
    dir: PathBuf,
    warnings: Vec<String>,
}

impl Plan {
    pub fn path(&self) -> &Path {
        &self.dir
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

const RESULT_MARKERS: [&str; 3] = ["report.json", "report.txt", "sample"];

pub fn prepare_case(
    dir: &Path,
    location: &Location,
    mounts: &[String],
    deep: bool,
    overwrite: bool,
) -> Result<Plan, Refusal> {
    let absolute = absolute(dir);

    if let Some(refusal) = refuse_placement(&absolute, location, "case directory") {
        return Err(refusal);
    }

    let mut warnings = Vec::new();
    if let Some(mount) = overlapping_mount(&absolute, mounts) {
        if deep {
            return Err(Refusal::OnVolumeBeingCarved {
                target: absolute,
                mount: mount.to_string(),
            });
        }
        warnings.push(format!(
            "! The case is being written to {mount}, the volume being analysed.\n\
             ! That volume is the evidence: the case directory adds $MFT records,\n\
             ! changes directory timestamps, and consumes free space which may hold\n\
             ! deleted files this run has not read yet. Nothing else in the run\n\
             ! writes to it. This does.\n\
             ! Put the case on other media with --out <other drive>:\\cases\\<name>."
        ));
    }

    if !overwrite {
        let found = occupied_by(&absolute);
        if !found.is_empty() {
            return Err(Refusal::Occupied { dir: absolute, found });
        }
    }

    if let Err(e) = std::fs::create_dir_all(&absolute) {
        return Err(Refusal::CouldNotCreate { dir: absolute, reason: e.to_string() });
    }

    Ok(Plan { dir: absolute, warnings })
}

pub fn guard_file(
    path: &Path,
    location: &Location,
    what: &'static str,
    overwrite: bool,
) -> Result<PathBuf, Refusal> {
    let absolute = absolute(path);
    if let Some(refusal) = refuse_placement(&absolute, location, what) {
        return Err(refusal);
    }
    if !overwrite {
        if let Ok(meta) = std::fs::metadata(&absolute) {
            return Err(Refusal::FileExists { path: absolute, bytes: meta.len(), what });
        }
    }
    Ok(absolute)
}

pub fn beside_the_image(image: &Path) -> PathBuf {
    let stem = image
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "image".to_string());
    let parent = image.parent().unwrap_or_else(|| Path::new("."));
    absolute(&parent.join(format!("{stem}-case")))
}

pub fn image_needs_out(image: &Path) -> Refusal {
    Refusal::ImageNeedsOut { image: image.to_path_buf(), suggestion: beside_the_image(image) }
}

pub fn suggest_case(location: &Location, volume: &str, stamp: &str) -> PathBuf {
    let root = location
        .binary_dir
        .as_deref()
        .and_then(drive_root)
        .or_else(|| std::env::current_dir().ok().as_deref().and_then(drive_root))
        .unwrap_or_else(|| PathBuf::from("."));
    let name = format!("{}-{stamp}", case_label(volume));
    let binary_dir = location.binary_dir.as_deref().map(absolute);
    ["cases", "malmathic-cases"]
        .into_iter()
        .map(|folder| root.join(folder).join(&name))
        .find(|candidate| {
            binary_dir.as_deref().is_none_or(|dir| !beside_the_binary(candidate, dir))
        })
        .unwrap_or_else(|| root.join("cases").join(&name))
}

pub fn stamp(now: chrono::DateTime<chrono::Local>) -> String {
    now.format("%Y%m%d-%H%M%S").to_string()
}

pub fn drive_of(path: &Path) -> Option<String> {
    let root = drive_root(path)?;
    let prefix = root.components().next()?;
    Some(prefix.as_os_str().to_string_lossy().to_uppercase())
}

pub fn is_remote(path: &Path) -> bool {
    matches!(
        absolute(path).components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::UNC(..))
    )
}

pub fn overlapping_mount<'a>(target: &Path, mounts: &'a [String]) -> Option<&'a str> {
    let absolute = absolute(target);
    mounts
        .iter()
        .find(|mount| mm_env::capture::refuses_to_write_onto(mount, &absolute))
        .map(String::as_str)
}

fn case_label(volume: &str) -> String {
    let label: String = volume.chars().filter(char::is_ascii_alphanumeric).take(16).collect();
    if label.is_empty() {
        "volume".to_string()
    } else {
        label
    }
}

fn drive_root(path: &Path) -> Option<PathBuf> {
    let path = absolute(path);
    let mut components = path.components();
    let Component::Prefix(prefix) = components.next()? else { return None };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(..)) {
        return None;
    }
    if !matches!(components.next(), Some(Component::RootDir)) {
        return None;
    }
    let mut root = PathBuf::from(prefix.as_os_str());
    root.push("\\");
    Some(root)
}

fn occupied_by(dir: &Path) -> Vec<&'static str> {
    RESULT_MARKERS.iter().copied().filter(|name| dir.join(name).exists()).collect()
}

fn refuse_placement(target: &Path, location: &Location, what: &'static str) -> Option<Refusal> {
    let stated =
        location.source_tree.as_deref().map(absolute).filter(|tree| is_within(target, tree));
    if let Some(tree) = source_tree_above(target).or(stated) {
        return Some(Refusal::InSourceTree { target: target.to_path_buf(), tree, what });
    }
    if let Some(dir) = &location.binary_dir {
        let dir = absolute(dir);
        if beside_the_binary(target, &dir) {
            return Some(Refusal::BesideBinary {
                target: target.to_path_buf(),
                binary_dir: dir,
                what,
            });
        }
    }
    None
}

fn beside_the_binary(target: &Path, binary_dir: &Path) -> bool {
    if binary_dir.parent().is_some() {
        return is_within(target, binary_dir);
    }
    same_path(target, binary_dir)
        || target.parent().is_some_and(|parent| same_path(parent, binary_dir))
}

fn same_path(a: &Path, b: &Path) -> bool {
    is_within(a, b) && is_within(b, a)
}

fn source_tree_above(target: &Path) -> Option<PathBuf> {
    target.ancestors().find(|dir| is_our_workspace(dir)).map(Path::to_path_buf)
}

fn is_our_workspace(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file()
        && dir.join("crates").join("mm-core").join("Cargo.toml").is_file()
        && dir.join("crates").join("malmathic").join("Cargo.toml").is_file()
}

fn absolute(path: &Path) -> PathBuf {
    let joined = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());

    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => out.push(plain_prefix(&prefix)),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn plain_prefix(prefix: &PrefixComponent<'_>) -> OsString {
    match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            OsString::from(format!("{}:", char::from(letter)))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut unc = OsString::from("\\\\");
            unc.push(server);
            unc.push("\\");
            unc.push(share);
            unc
        }
        Prefix::Verbatim(_) | Prefix::DeviceNS(_) => prefix.as_os_str().to_os_string(),
    }
}

fn is_within(child: &Path, parent: &Path) -> bool {
    let mut theirs = parent.components();
    let mut ours = child.components();
    loop {
        match (theirs.next(), ours.next()) {
            (None, _) => return true,
            (Some(_), None) => return false,
            (Some(a), Some(b)) => {
                let a = a.as_os_str().to_string_lossy().to_lowercase();
                let b = b.as_os_str().to_string_lossy().to_lowercase();
                if a != b {
                    return false;
                }
            }
        }
    }
}

fn as_written(marker: &str) -> String {
    if marker == "sample" {
        "sample\\".to_string()
    } else {
        marker.to_string()
    }
}

fn english_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("malmathic-casedir-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[test]
    fn a_fresh_directory_is_prepared_and_created() {
        let root = scratch("fresh");
        let case = root.join("case");
        let plan = prepare_case(&case, &Location::nowhere(), &[], false, false)
            .expect("a fresh directory is allowed");
        assert_eq!(plan.path(), case.as_path());
        assert!(case.is_dir(), "prepare_case creates it, so the pipeline can write into it");
        assert!(plan.warnings().is_empty(), "{:?}", plan.warnings());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_existing_but_empty_directory_is_not_a_result() {
        let root = scratch("empty");
        std::fs::write(root.join("notes.txt"), "chain of custody").unwrap();
        assert!(prepare_case(&root, &Location::nowhere(), &[], false, false).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_holding_a_result_is_refused_marker_by_marker() {
        for marker in RESULT_MARKERS {
            let root = scratch(&format!("occupied-{marker}"));
            if marker == "sample" {
                std::fs::create_dir_all(root.join(marker)).unwrap();
            } else {
                std::fs::write(root.join(marker), "{}").unwrap();
            }
            let refusal = prepare_case(&root, &Location::nowhere(), &[], false, false)
                .expect_err("a result is already there");
            let text = refusal.to_string();
            assert!(text.contains(marker), "the refusal names what it found: {text}");
            assert!(text.contains("--overwrite-case"), "and how to insist: {text}");
            assert!(matches!(refusal, Refusal::Occupied { .. }), "{refusal:?}");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn the_refusal_names_every_marker_it_found() {
        let root = scratch("occupied-all");
        std::fs::write(root.join("report.json"), "{}").unwrap();
        std::fs::write(root.join("report.txt"), "").unwrap();
        std::fs::create_dir_all(root.join("sample")).unwrap();
        let text = prepare_case(&root, &Location::nowhere(), &[], false, false)
            .expect_err("occupied")
            .to_string();
        assert!(text.contains("report.json, report.txt and sample\\"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn overwrite_case_is_the_only_way_past_an_existing_result() {
        let root = scratch("overwrite");
        std::fs::write(root.join("report.json"), "{}").unwrap();
        assert!(prepare_case(&root, &Location::nowhere(), &[], false, false).is_err());
        assert!(
            prepare_case(&root, &Location::nowhere(), &[], false, true).is_ok(),
            "--overwrite-case lifts this one"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_case_inside_malmathics_own_tree_is_refused_with_no_override() {
        let root = scratch("tree");
        std::fs::write(root.join("Cargo.toml"), "[workspace]").unwrap();
        for crate_name in ["mm-core", "malmathic"] {
            let dir = root.join("crates").join(crate_name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("Cargo.toml"), "[package]").unwrap();
        }

        let case = root.join("malmathic-case");
        let refusal = prepare_case(&case, &Location::nowhere(), &[], false, false)
            .expect_err("inside our own tree");
        assert!(matches!(refusal, Refusal::InSourceTree { .. }), "{refusal:?}");
        let text = refusal.to_string();
        assert!(text.contains("source tree"), "{text}");
        assert!(text.contains("There is no flag for this one"), "{text}");

        let insisted = prepare_case(&case, &Location::nowhere(), &[], false, true)
            .expect_err("--overwrite-case is not a licence to write here");
        assert!(matches!(insisted, Refusal::InSourceTree { .. }), "{insisted:?}");
        assert!(insisted.to_string().contains("--overwrite-case does not lift it"));
        assert!(!case.exists(), "a refused directory is not created");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn somebody_elses_rust_project_is_not_refused() {
        let root = scratch("their-project");
        std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        assert!(prepare_case(&root.join("case"), &Location::nowhere(), &[], false, false).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_case_beside_the_binary_is_refused() {
        let root = scratch("stick");
        let location = Location { source_tree: None, binary_dir: Some(root.clone()) };

        let refusal = prepare_case(&root.join("malmathic-case"), &location, &[], false, false)
            .expect_err("beside the binary");
        assert!(matches!(refusal, Refusal::BesideBinary { .. }), "{refusal:?}");
        assert!(refusal.to_string().contains("live malware"), "{refusal}");

        let elsewhere = root.parent().unwrap().join("malmathic-casedir-stick-cases");
        let _ = std::fs::remove_dir_all(&elsewhere);
        assert!(prepare_case(&elsewhere, &location, &[], false, false).is_ok());

        let _ = std::fs::remove_dir_all(&elsewhere);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_binary_in_the_root_of_its_drive_refuses_only_that_root() {
        for root in [r"Q:\", r"\\?\Q:\"] {
            let location = Location { source_tree: None, binary_dir: Some(PathBuf::from(root)) };
            for beside in
                [r"Q:\malmathic-case", r"\\?\Q:\malmathic-case", r"Q:", r"Q:malmathic-case", r"Q:\"]
            {
                let refusal =
                    refuse_placement(&absolute(Path::new(beside)), &location, "case directory")
                        .unwrap_or_else(|| panic!("{beside} sits beside the binary in {root}"));
                assert!(matches!(refusal, Refusal::BesideBinary { .. }), "{refusal:?}");
            }
            for deeper in [r"Q:\cases\x", r"\\?\Q:\cases\x", r"Q:cases\x"] {
                assert!(
                    refuse_placement(&absolute(Path::new(deeper)), &location, "case directory")
                        .is_none(),
                    "{deeper} is what the refusal itself suggests, so it must be allowed"
                );
            }
        }
    }

    #[test]
    fn a_binary_in_a_folder_still_refuses_everything_under_that_folder() {
        let location = Location { source_tree: None, binary_dir: Some(PathBuf::from(r"D:\tools")) };
        assert!(
            refuse_placement(Path::new(r"D:\tools\cases\x"), &location, "case directory").is_some()
        );
        assert!(refuse_placement(Path::new(r"D:\cases\x"), &location, "case directory").is_none());
    }

    #[test]
    fn the_suggested_case_is_in_cases_on_the_drive_holding_the_binary() {
        let at = |dir: &str| Location { source_tree: None, binary_dir: Some(PathBuf::from(dir)) };
        assert_eq!(
            suggest_case(&at(r"D:\tools"), "C:", "20260830-164205"),
            PathBuf::from(r"D:\cases\C-20260830-164205")
        );
        assert_eq!(
            suggest_case(&at(r"D:\"), "C:", "20260830-164205"),
            PathBuf::from(r"D:\cases\C-20260830-164205")
        );
        assert_eq!(
            suggest_case(&at(r"\\?\D:\deep\er"), "C:", "20260830-164205"),
            PathBuf::from(r"D:\cases\C-20260830-164205")
        );
        assert_eq!(
            suggest_case(&at(r"\\nas\tools\mm"), "C:", "20260830-164205"),
            PathBuf::from(r"\\nas\tools\cases\C-20260830-164205")
        );
    }

    #[test]
    fn the_suggestion_is_never_refused_for_the_binary_that_made_it() {
        for dir in [r"Q:\", r"Q:\tools", r"Q:\a\b\c", r"Q:\cases", r"\\?\Q:\tools"] {
            let location = Location { source_tree: None, binary_dir: Some(PathBuf::from(dir)) };
            let suggested = suggest_case(&location, "C:", "20260830-164205");
            assert!(
                refuse_placement(&suggested, &location, "case directory").is_none(),
                "{} refused its own suggestion {}",
                dir,
                suggested.display()
            );
        }
    }

    #[test]
    fn a_binary_living_in_cases_itself_is_offered_the_next_best_folder() {
        let location = Location { source_tree: None, binary_dir: Some(PathBuf::from(r"Q:\cases")) };
        assert_eq!(
            suggest_case(&location, "C:", "20260830-164205"),
            PathBuf::from(r"Q:\malmathic-cases\C-20260830-164205")
        );
    }

    #[test]
    fn a_network_share_is_remote_and_a_drive_is_not() {
        assert!(is_remote(Path::new(r"\\nas\share\cases\x")));
        assert!(is_remote(Path::new(r"\\?\UNC\nas\share\cases\x")));
        assert!(!is_remote(Path::new(r"Q:\cases\x")));
        assert!(!is_remote(Path::new("cases")));
    }

    #[test]
    fn the_overlapping_mount_is_the_one_the_case_would_land_on() {
        let mounts = vec![r"C:\".to_string(), r"E:\".to_string()];
        assert_eq!(overlapping_mount(Path::new(r"e:\cases\x"), &mounts), Some(r"E:\"));
        assert_eq!(overlapping_mount(Path::new(r"E:cases\x"), &mounts), Some(r"E:\"));
        assert_eq!(overlapping_mount(Path::new(r"Q:\cases\x"), &mounts), None);
    }

    #[test]
    fn a_binary_of_unknown_location_still_gets_an_absolute_suggestion() {
        let suggested = suggest_case(&Location::nowhere(), "C:", "20260830-164205");
        assert!(suggested.is_absolute(), "{}", suggested.display());
        assert!(suggested.ends_with(r"cases\C-20260830-164205"), "{}", suggested.display());
    }

    #[test]
    fn the_case_is_named_after_the_volume_in_characters_a_directory_can_hold() {
        assert_eq!(case_label("C:"), "C");
        assert_eq!(case_label(r"E:\"), "E");
        assert_eq!(case_label("volume {6b6c9e1a-00…"), "volume6b6c9e1a00");
        assert_eq!(case_label(""), "volume");
        assert_eq!(case_label(":\\ /"), "volume");
        assert_eq!(case_label(&"a".repeat(40)).len(), 16);
    }

    #[test]
    fn the_stamp_is_local_time_to_the_second() {
        use chrono::TimeZone;
        let at = chrono::Local.with_ymd_and_hms(2026, 8, 30, 16, 42, 5).unwrap();
        assert_eq!(stamp(at), "20260830-164205");
    }

    #[test]
    fn the_drive_of_a_path_is_its_prefix_in_upper_case() {
        assert_eq!(drive_of(Path::new(r"x:\Windows\System32")).as_deref(), Some("X:"));
        assert_eq!(drive_of(Path::new(r"\\?\X:\cases")).as_deref(), Some("X:"));
        assert_eq!(drive_of(Path::new("Q:")).as_deref(), Some("Q:"));
        assert_eq!(drive_of(Path::new(r"\\nas\share\x")).as_deref(), Some(r"\\NAS\SHARE"));
        let here = std::env::current_dir().unwrap();
        assert_eq!(drive_of(Path::new("cases")), drive_of(&here));
    }

    #[test]
    fn the_volume_being_read_is_a_warning_until_deep_makes_it_a_refusal() {
        let root = scratch("volume");
        let mount = format!("{}\\", root.display());
        let case = root.join("case");

        let here = std::slice::from_ref(&mount);
        let plan = prepare_case(&case, &Location::nowhere(), here, false, false)
            .expect("an ordinary run may write there, loudly");
        assert_eq!(plan.warnings().len(), 1, "{:?}", plan.warnings());
        assert!(plan.warnings()[0].contains("the volume being analysed"), "{:?}", plan.warnings());

        let _ = std::fs::remove_dir_all(&case);
        let refusal = prepare_case(&case, &Location::nowhere(), &[mount], true, false)
            .expect_err("--deep carves the free space this would consume");
        assert!(matches!(refusal, Refusal::OnVolumeBeingCarved { .. }), "{refusal:?}");
        assert!(refusal.to_string().contains("unallocated clusters"), "{refusal}");

        let elsewhere = scratch("volume-other");
        let other = elsewhere.join("case");
        let plan = prepare_case(&other, &Location::nowhere(), &["Z:\\".into()], true, false)
            .expect("another volume is not the one being read");
        assert!(plan.warnings().is_empty(), "{:?}", plan.warnings());

        let _ = std::fs::remove_dir_all(&elsewhere);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_suggested_case_for_an_image_sits_beside_it_and_is_named_after_it() {
        let suggestion = beside_the_image(Path::new(r"D:\vms\njrat\disk-000005.vmdk"));
        assert_eq!(suggestion, PathBuf::from(r"D:\vms\njrat\disk-000005-case"));
        assert_ne!(suggestion, beside_the_image(Path::new(r"D:\vms\njrat\disk-000002.vmdk")));

        let bare = beside_the_image(Path::new("disk.vmdk"));
        assert!(bare.is_absolute(), "{}", bare.display());
        assert!(bare.ends_with("disk-case"), "{}", bare.display());
    }

    #[test]
    fn an_image_with_no_out_is_refused_in_words_that_can_be_retyped() {
        let text = image_needs_out(Path::new(r"D:\vms\njrat\disk-000005.vmdk")).to_string();
        assert!(text.starts_with("--image needs --out."), "{text}");
        assert!(text.contains(r"D:\vms\njrat\disk-000005-case"), "{text}");
        assert!(text.contains("evidence store"), "{text}");
    }

    #[test]
    fn a_capture_refuses_to_overwrite_an_existing_file() {
        let root = scratch("capture");
        let path = root.join("lzx.mmcap");
        assert!(guard_file(&path, &Location::nowhere(), "capture", false).is_ok());

        std::fs::write(&path, b"the only one anybody ever took").unwrap();
        let refusal = guard_file(&path, &Location::nowhere(), "capture", false)
            .expect_err("something is already there");
        assert!(matches!(refusal, Refusal::FileExists { .. }), "{refusal:?}");
        assert!(refusal.to_string().contains("30 bytes"), "{refusal}");
        assert!(guard_file(&path, &Location::nowhere(), "capture", true).is_ok());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_capture_obeys_the_same_placement_rules_as_a_case() {
        let root = scratch("capture-placement");
        let location = Location { source_tree: Some(root.clone()), binary_dir: None };
        let refusal = guard_file(&root.join("lzx.mmcap"), &location, "capture", true)
            .expect_err("inside the tree");
        assert!(matches!(refusal, Refusal::InSourceTree { what: "capture", .. }), "{refusal:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn containment_is_by_component_and_case_insensitive() {
        assert!(is_within(Path::new(r"C:\case\x"), Path::new(r"c:\CASE")));
        assert!(is_within(Path::new(r"C:\case"), Path::new(r"C:\case")));
        assert!(!is_within(Path::new(r"C:\case-two"), Path::new(r"C:\case")));
        assert!(!is_within(Path::new(r"C:\other"), Path::new(r"C:\case")));
        assert!(!is_within(Path::new(r"C:\case"), Path::new(r"C:\case\x")));
    }

    #[test]
    fn a_relative_walk_back_into_a_refused_tree_is_still_refused() {
        let root = scratch("dotdot");
        let location = Location { source_tree: Some(root.clone()), binary_dir: None };
        let sneaky = root.join("sub").join("..").join("case");
        let refusal = prepare_case(&sneaky, &location, &[], false, false)
            .expect_err("normalising puts it back inside the tree");
        assert!(matches!(refusal, Refusal::InSourceTree { .. }), "{refusal:?}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
