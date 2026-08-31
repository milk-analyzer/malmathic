use std::path::{Path, PathBuf};

use mm_env::snapshots::{Moment, SnapshotView};
use mm_env::vmdk::{Provenance, Vmdk};

fn vmware_dir(vm: &str) -> String {
    Path::new(&std::env::var("USERPROFILE").unwrap_or_default())
        .join("Documents")
        .join("Virtual Machines")
        .join(vm)
        .to_string_lossy()
        .into_owned()
}

const CHAIN_BASE: &str = "WIN11-LAB.vmdk";

struct Link {
    name: String,
    cid: String,
    parent_cid: String,
}

fn vm_dir() -> Option<PathBuf> {
    let dir: PathBuf =
        std::env::var("MM_VM_DIR").unwrap_or_else(|_| vmware_dir("WIN11-LAB")).into();
    if !dir.is_dir() {
        eprintln!(
            "SKIPPED: no VMware directory at {}. These tests verify the snapshot chain against \
             real VMDKs; set MM_VM_DIR to a directory holding a base disk and its deltas to run \
             them.",
            dir.display()
        );
        return None;
    }
    if !dir.join(CHAIN_BASE).is_file() {
        eprintln!(
            "SKIPPED: {} does not hold {CHAIN_BASE}. These tests are written against that \
             specific chain.",
            dir.display()
        );
        return None;
    }
    Some(dir)
}

fn newest_link(dir: &Path) -> PathBuf {
    let meta = mm_env::snapshots::VmMetadata::beside(&dir.join(CHAIN_BASE));
    let mut disks: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("the VM directory must be readable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("vmdk")))
        .collect();
    disks.sort();

    if let Some(current) = disks
        .iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| meta.is_current_disk(n)))
    {
        return current.clone();
    }

    disks
        .into_iter()
        .filter_map(|p| Vmdk::open(&p).ok().map(|v| (v.info().chain.len(), p)))
        .max_by_key(|(depth, _)| *depth)
        .map(|(_, p)| p)
        .expect("the VM directory must hold at least one readable VMDK")
}

fn chain_of(path: &Path) -> Vec<Link> {
    let vmdk = Vmdk::open(path)
        .unwrap_or_else(|e| panic!("{} must open as a VMDK chain: {e}", path.display()));
    vmdk.info()
        .chain
        .iter()
        .map(|l| Link {
            name: l.name.clone(),
            cid: l.cid.to_ascii_lowercase(),
            parent_cid: l.parent_cid.to_ascii_lowercase(),
        })
        .collect()
}

fn descriptor_ids(path: &Path) -> (String, String) {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("{} must open for reading: {e}", path.display()));
    let mut head = vec![0u8; 128 * 1024];
    let mut filled = 0;
    while filled < head.len() {
        match file.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => panic!("reading the head of {} failed: {e}", path.display()),
        }
    }
    head.truncate(filled);
    let text = String::from_utf8_lossy(&head);

    let mut cid = None;
    let mut parent = None;
    for line in text.split(['\n', '\r']) {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("CID=") {
            cid.get_or_insert_with(|| v.trim().to_ascii_lowercase());
        } else if let Some(v) = line.strip_prefix("parentCID=") {
            parent.get_or_insert_with(|| v.trim().to_ascii_lowercase());
        }
    }
    (
        cid.unwrap_or_else(|| panic!("{} has no CID= in its descriptor", path.display())),
        parent.unwrap_or_else(|| panic!("{} has no parentCID= in its descriptor", path.display())),
    )
}

#[test]
fn every_delta_links_back_to_the_base_by_cid() {
    let Some(dir) = vm_dir() else { return };

    let whole = chain_of(&newest_link(&dir));
    assert!(
        whole.len() >= 2,
        "these tests need a base and at least one delta; found {} link(s)",
        whole.len()
    );
    assert_eq!(
        whole.last().unwrap().name,
        CHAIN_BASE,
        "the chain must bottom out at the base disk"
    );

    for link in &whole {
        let (cid, parent) = descriptor_ids(&dir.join(&link.name));
        assert_eq!(link.cid, cid, "{} must carry the CID its descriptor holds", link.name);
        assert_eq!(
            link.parent_cid, parent,
            "{} must demand the parent its descriptor names",
            link.name
        );
    }

    let capacity = Vmdk::open(&dir.join(&whole[0].name)).expect("newest link opens").disk_size();

    for start in 0..whole.len() {
        let name = &whole[start].name;
        let path = dir.join(name);
        let vmdk = Vmdk::open(&path)
            .unwrap_or_else(|e| panic!("{} must open as a VMDK chain: {e}", path.display()));
        let chain = &vmdk.info().chain;

        let expected = &whole[start..];
        assert_eq!(
            chain.len(),
            expected.len(),
            "opening {name} must resolve {} link(s), not {}: {:?}",
            expected.len(),
            chain.len(),
            chain.iter().map(|l| &l.name).collect::<Vec<_>>()
        );

        for (link, want) in chain.iter().zip(expected) {
            assert_eq!(link.name, want.name, "chain order from {name}");
            assert_eq!(link.cid.to_ascii_lowercase(), want.cid, "CID of {} from {name}", want.name);
            assert_eq!(
                link.parent_cid.to_ascii_lowercase(),
                want.parent_cid,
                "parentCID of {} from {name}",
                want.name
            );
        }

        for pair in chain.windows(2) {
            assert_eq!(
                pair[0].parent_cid.to_ascii_lowercase(),
                pair[1].cid.to_ascii_lowercase(),
                "{} must be the parent of {}",
                pair[1].name,
                pair[0].name
            );
        }
        assert_eq!(
            chain.last().unwrap().parent_cid.to_ascii_lowercase(),
            "ffffffff",
            "the chain from {name} must end at a base disk"
        );

        assert_eq!(
            vmdk.disk_size(),
            capacity,
            "every link declares the same guest disk as the newest one"
        );
    }
}

#[test]
fn each_link_is_a_named_moment() {
    let Some(dir) = vm_dir() else { return };

    let path = newest_link(&dir);
    let newest = path.file_name().and_then(|n| n.to_str()).expect("the newest link has a name");
    let vmdk = Vmdk::open(&path).expect("the newest delta must open");
    let view = SnapshotView::of(&path, vmdk.info());

    assert_eq!(
        view.links.len(),
        vmdk.info().chain.len(),
        "the view must name exactly the links the chain resolved"
    );
    assert_eq!(
        view.links[0].moment,
        Moment::LiveState,
        "the disk the .vmx has attached is the live state, not a snapshot"
    );

    for link in &view.links[1..] {
        match &link.moment {
            Moment::Snapshot { name, created } => {
                assert!(!name.trim().is_empty(), "link {} must carry a snapshot name", link.name);
                assert!(created.is_some(), "snapshot {name:?} must carry a plausible time");
            }
            other => panic!("link {} should be a snapshot, got {other:?}", link.name),
        }
    }

    let names: Vec<&str> = view
        .links
        .iter()
        .filter_map(|l| match &l.moment {
            Moment::Snapshot { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "two links claim the same snapshot name: {names:?}");

    assert!(view.times_agree_with_chain(), "recorded times must agree with the chain's own order");

    let line = view.provenance();
    assert!(line.contains(newest), "got {line}");
    assert!(line.contains(CHAIN_BASE), "the base must be named too: {line}");
}

#[test]
fn different_links_are_different_disks() {
    let Some(dir) = vm_dir() else { return };

    let chain = chain_of(&newest_link(&dir));
    let mut newest = Vmdk::open(&dir.join(&chain[0].name)).expect("newest delta opens");
    let mut base = Vmdk::open(&dir.join(CHAIN_BASE)).expect("base opens");

    assert_eq!(newest.info().chain.len(), chain.len());
    assert_eq!(base.info().chain.len(), 1, "the base has no parent to read through");

    let capacity = newest.disk_size();
    let deepest = chain.len() - 1;

    let step = capacity / 4096;
    let mut differing = 0usize;
    let mut from_a_delta = 0usize;
    let mut from_the_base = 0usize;
    let mut sampled = 0usize;

    for index in 0..4096u64 {
        let at = index * step;
        let a = read_at(&mut newest, at);
        let b = read_at(&mut base, at);
        sampled += 1;
        if a != b {
            differing += 1;
        }
        match newest.provenance(at).expect("provenance must be answerable") {
            Provenance::Stored { link, .. } if link == deepest => from_the_base += 1,
            Provenance::Stored { link, .. } if link < deepest => from_a_delta += 1,
            _ => {}
        }
    }

    eprintln!(
        "measured over {sampled} samples: {differing} differ between the newest link and the \
         base; {from_a_delta} came from a delta, {from_the_base} from the base"
    );
    assert!(
        differing > 0,
        "the newest link and the base must not be byte-identical — five snapshots were taken \
         between them"
    );
    assert!(
        from_a_delta > 0,
        "at least some grains must be supplied by a delta, or the chain is not being walked"
    );
    assert!(
        from_the_base > 0,
        "at least some grains must fall through to the base, or the fall-through is not working"
    );
}

#[test]
fn reading_the_chain_does_not_touch_the_files() {
    let Some(dir) = vm_dir() else { return };

    let chain = chain_of(&newest_link(&dir));
    let before: Vec<_> = chain.iter().map(|l| stamp(&dir.join(&l.name))).collect();

    let mut vmdk = Vmdk::open(&dir.join(&chain[0].name)).expect("newest delta opens");
    let capacity = vmdk.disk_size();
    for index in 0..256u64 {
        let _ = read_at(&mut vmdk, index * (capacity / 256));
    }
    drop(vmdk);

    let after: Vec<_> = chain.iter().map(|l| stamp(&dir.join(&l.name))).collect();
    for (index, (a, b)) in before.iter().zip(&after).enumerate() {
        assert_eq!(a, b, "{} changed while it was being read: {a:?} then {b:?}", chain[index].name);
    }
}

#[test]
fn a_split_sparse_disk_opens_through_its_text_descriptor() {
    let dir: PathBuf =
        std::env::var("MM_SPLIT_VM_DIR").unwrap_or_else(|_| vmware_dir("SPLITDISK")).into();
    let descriptor = dir.join("SPLITDISK.vmdk");
    if !descriptor.is_file() {
        eprintln!(
            "SKIPPED: no split disk at {}. Set MM_SPLIT_VM_DIR to a directory holding one.",
            descriptor.display()
        );
        return;
    }

    let mut vmdk = Vmdk::open(&descriptor).expect("a split sparse disk must open");
    let info = vmdk.info().clone();
    assert_eq!(info.create_type, "twoGbMaxExtentSparse");
    assert_eq!(info.extents, 16, "the descriptor lists sixteen extents");
    assert_eq!(info.chain.len(), 1, "this disk is a base with no snapshots");
    assert_eq!(info.capacity_bytes, 125_829_120 * 512);

    let far = info.capacity_bytes - 1024 * 1024;
    let _ = read_at(&mut vmdk, far);
    assert!(matches!(
        vmdk.provenance(far).expect("provenance must be answerable"),
        Provenance::Stored { .. } | Provenance::NeverWritten | Provenance::ExplicitlyZeroed { .. }
    ));
}

#[test]
fn a_delta_without_its_parent_is_refused() {
    let Some(dir) = vm_dir() else { return };

    let chain = chain_of(&newest_link(&dir));
    let delta = chain[chain.len() - 2].name.clone();

    let scratch = std::env::temp_dir().join(format!("malmathic-orphan-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&scratch);
    let orphan = scratch.join(&delta);

    let head = {
        use std::io::Read;
        let mut f = std::fs::File::open(dir.join(&delta)).expect("delta opens");
        let mut buf = vec![0u8; 64 * 1024];
        let mut filled = 0;
        while filled < buf.len() {
            match f.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => break,
            }
        }
        buf.truncate(filled);
        buf
    };
    std::fs::write(&orphan, &head).expect("the orphan copy must be writable");

    let err = Vmdk::open(&orphan).expect_err("a delta with no parent beside it must be refused");
    let text = err.to_string();
    assert!(
        text.contains(&delta) || text.contains(CHAIN_BASE),
        "the refusal must name the link that broke, got: {text}"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

fn read_at(vmdk: &mut Vmdk, at: u64) -> [u8; 512] {
    use std::io::{Read, Seek, SeekFrom};
    vmdk.seek(SeekFrom::Start(at)).expect("seeking inside the declared disk must work");
    let mut buf = [0u8; 512];
    let mut filled = 0;
    while filled < buf.len() {
        match vmdk.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => panic!("reading at {at} failed: {e}"),
        }
    }
    buf
}

fn stamp(path: &Path) -> (u64, Option<std::time::SystemTime>) {
    let meta = std::fs::metadata(path).expect("the chain's files must be readable");
    (meta.len(), meta.modified().ok())
}

const HEAD: usize = 20 * 1024 * 1024;

fn scratch_chain(label: &str) -> Option<(PathBuf, PathBuf, Vec<Link>)> {
    let dir = vm_dir()?;
    let chain = chain_of(&newest_link(&dir));
    let scratch =
        std::env::temp_dir().join(format!("malmathic-chain-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("a scratch directory must be creatable");
    for link in &chain {
        let head = head_of(&dir.join(&link.name));
        std::fs::write(scratch.join(&link.name), &head).expect("the head copy must be writable");
    }
    Some((dir, scratch, chain))
}

fn head_of(path: &Path) -> Vec<u8> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).expect("the link must be readable");
    let mut buf = vec![0u8; HEAD];
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => panic!("reading {}: {e}", path.display()),
        }
    }
    buf.truncate(filled);
    buf
}

fn edit_descriptor(path: &Path, edit: impl Fn(&str) -> String) {
    let mut bytes = std::fs::read(path).expect("the copy must be readable");
    let run = &bytes[512..512 + 10_240];
    let end = run.iter().position(|b| *b == 0).unwrap_or(run.len());
    let text = std::str::from_utf8(&run[..end]).expect("these descriptors are ASCII");
    let edited = edit(text);
    let edited = edited.as_bytes();
    assert!(edited.len() <= 10_240, "the edited descriptor must still fit its run");
    bytes[512..512 + 10_240].fill(0);
    bytes[512..512 + edited.len()].copy_from_slice(edited);
    std::fs::write(path, &bytes).expect("the copy must be writable");
}

#[test]
fn a_delta_with_no_hint_is_still_resolved_by_cid() {
    let Some((_, scratch, chain)) = scratch_chain("nohint") else { return };
    let leaf = scratch.join(&chain[0].name);
    edit_descriptor(&leaf, |text| {
        text.lines().filter(|l| !l.starts_with("parentFileNameHint")).collect::<Vec<_>>().join("\n")
    });

    let vmdk = Vmdk::open(&leaf).expect("the chain must still resolve without any hint");
    let names: Vec<&str> = vmdk.info().chain.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(
        names,
        chain.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
        "with the hint gone, the CIDs alone must rebuild the whole chain"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn a_stale_hint_pointing_at_the_wrong_file_is_overruled_by_the_cid() {
    let Some((_, scratch, chain)) = scratch_chain("stale") else { return };
    let leaf = scratch.join(&chain[0].name);
    let true_parent = chain[1].name.clone();
    let decoy = chain[2].name.clone();
    edit_descriptor(&leaf, |text| {
        text.replace(
            &format!("parentFileNameHint=\"{true_parent}\""),
            &format!("parentFileNameHint=\"D:\\Somebody Else\\{decoy}\""),
        )
    });

    let vmdk = Vmdk::open(&leaf).expect("the chain must resolve past a stale hint");
    let names: Vec<&str> = vmdk.info().chain.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(
        names[1], true_parent,
        "the CID must pick {true_parent} even though the hint names {decoy}: {names:?}"
    );
    assert_eq!(names.len(), chain.len());

    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn an_unsatisfiable_parent_cid_is_refused_by_name() {
    let Some((_, scratch, chain)) = scratch_chain("broken") else { return };
    let leaf = scratch.join(&chain[0].name);
    let wanted = chain[0].parent_cid.clone();
    let hint = format!("parentFileNameHint=\"{}\"", chain[1].name);
    edit_descriptor(&leaf, |text| {
        text.replace(&format!("parentCID={wanted}"), "parentCID=deadbeef").replace(&hint, "")
    });

    let err = Vmdk::open(&leaf).expect_err("a chain with no satisfiable parent must be refused");
    let text = err.to_string();
    assert!(text.contains(&chain[0].name), "the refusal must name the broken link: {text}");
    assert!(text.contains("deadbeef"), "and the CID it wanted: {text}");

    let _ = std::fs::remove_dir_all(&scratch);
}
