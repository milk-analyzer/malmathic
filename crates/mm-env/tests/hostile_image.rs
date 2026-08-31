mod forge;

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use forge::*;
use mm_env::{ImageFile, Vmdk};

fn must_finish<T: Send + 'static>(
    secs: u64,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(_) => panic!("{what} did not finish within {secs}s — it hung"),
    }
}

fn open_image(path: &Path) -> std::result::Result<(), String> {
    let owned = path.to_path_buf();
    must_finish(20, "opening the image", move || {
        mm_env::find_ntfs_partitions(&owned).map(|_| ()).map_err(|e| e.to_string())
    })
}

fn open_vmdk(path: &Path) -> std::result::Result<Vmdk, String> {
    let owned = path.to_path_buf();
    must_finish(20, "opening the VMDK", move || Vmdk::open(&owned).map_err(|e| e.to_string()))
}

#[test]
fn the_control_image_is_read_correctly() {
    let s = Scratch::new("control");
    let bytes = Forge::new(base_descriptor("base.vmdk"))
        .grain_bytes(0, &ntfs_boot_sector())
        .grain(3, 0xC3)
        .build();
    let path = s.put("base.vmdk", &bytes);

    assert!(Vmdk::looks_like_one(&path), "KDMV must be recognised");

    let mut disk = open_vmdk(&path).expect("the control image must open");
    assert_eq!(disk.disk_size(), CAPACITY_SECTORS * SECTOR as u64);
    assert_eq!(disk.info().extents, 1);
    assert_eq!(disk.info().chain.len(), 1, "a base disk is one link");

    let mut first = vec![0u8; SECTOR];
    disk.read_exact(&mut first).expect("reading the boot sector");
    assert_eq!(&first[3..11], b"NTFS    ");

    open_image(&path).expect("find_ntfs_partitions must accept the control image");
}

#[test]
fn every_truncation_of_a_valid_image_is_refused_or_degrades() {
    let s = Scratch::new("truncate");
    let full = Forge::new(base_descriptor("base.vmdk"))
        .grain_bytes(0, &ntfs_boot_sector())
        .grain(1, 0x11)
        .grain(4, 0x44)
        .build();

    let mut cuts: Vec<usize> = vec![0, 1, 3, 4, 63, 64, 100, 511, 512, 513];
    for sector in 1..=(full.len() / SECTOR) {
        cuts.push(sector * SECTOR);
        cuts.push(sector * SECTOR - 1);
    }
    cuts.push(full.len() - 1);
    cuts.sort_unstable();
    cuts.dedup();

    let dir = s.dir().to_path_buf();
    must_finish(120, "the truncation sweep", move || {
        for cut in cuts {
            if cut >= full.len() {
                continue;
            }
            let path = dir.join(format!("cut-{cut}.vmdk"));
            std::fs::write(&path, &full[..cut]).expect("a fixture");
            if let Ok(mut disk) = Vmdk::open(&path) {
                read_all_of(&mut disk);
            }
            let _ = std::fs::remove_file(&path);
        }
    });
}

fn read_all_of(disk: &mut Vmdk) {
    use std::io::Seek;
    let size = disk.disk_size().min(1 << 20);
    let mut buf = vec![0u8; 4096];
    let mut at = 0u64;
    while at < size {
        if disk.seek(std::io::SeekFrom::Start(at)).is_err() || disk.read(&mut buf).is_err() {
            break;
        }
        at += 4096;
    }
}

#[test]
fn an_empty_file_and_a_bare_magic_are_refused() {
    let s = Scratch::new("empty");
    for (name, bytes) in
        [("empty.vmdk", &b""[..]), ("magic.vmdk", &b"KDMV"[..]), ("half.vmdk", &vec![0u8; 256][..])]
    {
        let path = s.put(name, bytes);
        assert!(open_vmdk(&path).is_err(), "{name} must be refused");
    }
}

#[test]
fn a_header_claiming_an_enormous_disk_is_refused_rather_than_allocated() {
    let s = Scratch::new("bigcap");
    for capacity in [u64::MAX, u64::MAX / 2, 1u64 << 60, 1u64 << 45] {
        let mut bytes = Forge::new(base_descriptor("big.vmdk")).grain(0, 0x01).build();
        put64(&mut bytes, at::CAPACITY, capacity);
        let path = s.put("big.vmdk", &bytes);
        let err = open_vmdk(&path)
            .err()
            .unwrap_or_else(|| panic!("a {capacity}-sector disk must be refused"));
        assert!(
            err.contains("not credible")
                || err.contains("will not allocate")
                || err.contains("overflow")
                || err.contains("past the end"),
            "the refusal should say why: {err}"
        );
    }
}

#[test]
fn an_implausible_grain_geometry_is_refused() {
    let s = Scratch::new("geometry");

    for grain in [0u64, 1, 3, 7, 12, 100, 1 << 40, u64::MAX] {
        let mut bytes = Forge::new(base_descriptor("g.vmdk")).grain(0, 1).build();
        put64(&mut bytes, at::GRAIN_SIZE, grain);
        let path = s.put("g.vmdk", &bytes);
        assert!(open_vmdk(&path).is_err(), "a {grain}-sector grain must be refused");
    }

    for gte in [0u32, u32::MAX, 1 << 20] {
        let mut bytes = Forge::new(base_descriptor("t.vmdk")).grain(0, 1).build();
        put32(&mut bytes, at::GTE_PER_GT, gte);
        let path = s.put("t.vmdk", &bytes);
        assert!(open_vmdk(&path).is_err(), "{gte} entries per grain table must be refused");
    }
}

#[test]
fn a_descriptor_claiming_a_gigabyte_is_refused_rather_than_read() {
    let s = Scratch::new("bigdesc");
    for sectors in [2_097_152u64, u64::MAX, u64::MAX / SECTOR as u64, 1 << 30] {
        let mut bytes = Forge::new(base_descriptor("d.vmdk")).grain(0, 1).build();
        put64(&mut bytes, at::DESCRIPTOR_SIZE, sectors);
        let path = s.put("d.vmdk", &bytes);
        let err = open_vmdk(&path)
            .err()
            .unwrap_or_else(|| panic!("a {sectors}-sector descriptor must be refused"));
        assert!(
            err.contains("cap is") || err.contains("overflow") || err.contains("not credible"),
            "the refusal should name the cap: {err}"
        );
    }
}

#[test]
fn an_enormous_text_descriptor_file_is_refused_rather_than_read() {
    let s = Scratch::new("bigtext");
    let mut text = Vec::from(&b"# Disk DescriptorFile\nversion=1\n"[..]);
    while text.len() < 2 * 1024 * 1024 {
        text.extend_from_slice(b"RW 64 SPARSE \"nowhere.vmdk\"\n");
    }
    let path = s.put("huge.vmdk", &text);
    let err = open_vmdk(&path).expect_err("a 2 MB descriptor must be refused");
    assert!(err.contains("too large") || err.contains("cap"), "got {err}");
}

#[test]
fn compressed_and_stream_optimized_images_are_refused_by_name() {
    let s = Scratch::new("compressed");

    let mut bytes = Forge::new(base_descriptor("c.vmdk")).grain(0, 1).build();
    bytes[at::COMPRESS] = 1;
    let path = s.put("c.vmdk", &bytes);
    let err = open_vmdk(&path).expect_err("compressAlgorithm 1 must be refused");
    assert!(err.contains("compress"), "the refusal must name compression: {err}");

    let mut bytes = Forge::new(base_descriptor("m.vmdk")).grain(0, 1).build();
    put32(&mut bytes, at::FLAGS, 1 | (1 << 16) | (1 << 17));
    let path = s.put("m.vmdk", &bytes);
    let err = open_vmdk(&path).expect_err("the compressed/marker flags must be refused");
    assert!(err.contains("compress") || err.contains("marker"), "got {err}");
}

#[test]
fn a_mangled_end_of_line_canary_is_refused() {
    let s = Scratch::new("canary");
    let mut bytes = Forge::new(base_descriptor("n.vmdk")).grain(0, 1).build();
    bytes[at::NEWLINE_CANARY + 2] = b'\n';
    let path = s.put("n.vmdk", &bytes);
    let err = open_vmdk(&path).expect_err("a mangled canary must be refused");
    assert!(err.contains("canary") || err.contains("text mode"), "got {err}");
}

#[test]
fn a_grain_directory_outside_the_file_is_refused() {
    let s = Scratch::new("gd");
    for gd in [u64::MAX, u64::MAX / SECTOR as u64, 1u64 << 40, 1_000_000] {
        let mut bytes = Forge::new(base_descriptor("gd.vmdk")).grain(0, 1).build();
        put64(&mut bytes, at::GD_OFFSET, gd);
        let path = s.put("gd.vmdk", &bytes);
        assert!(
            open_vmdk(&path).is_err(),
            "a grain directory at sector {gd} of a {}-byte file must be refused",
            bytes.len()
        );
    }
}

#[test]
fn a_grain_table_outside_the_file_is_refused_when_it_is_read() {
    let s = Scratch::new("gt");
    let mut bytes = Forge::new(base_descriptor("gt.vmdk"))
        .grain_bytes(0, &ntfs_boot_sector())
        .grain(5, 0x55)
        .build();
    put32(&mut bytes, grain_directory_entry(1), 2_000_000);
    let path = s.put("gt.vmdk", &bytes);

    let mut disk = open_vmdk(&path).expect("the first table is still fine, so the open succeeds");
    let mut first = vec![0u8; SECTOR];
    disk.read_exact(&mut first).expect("grain 0 still reads");
    assert_eq!(&first[3..11], b"NTFS    ");

    use std::io::Seek;
    disk.seek(std::io::SeekFrom::Start(5 * GRAIN_SECTORS * SECTOR as u64)).unwrap();
    let mut buf = vec![0u8; SECTOR];
    let err = disk.read(&mut buf).expect_err("a table past the end of the file must error");
    assert!(err.to_string().contains("past the end"), "the error should say what was wrong: {err}");
}

#[test]
fn a_grain_outside_the_file_is_refused_rather_than_read() {
    let s = Scratch::new("grain");
    for sector in [u32::MAX, 1_000_000, 100_000] {
        let mut bytes = Forge::new(base_descriptor("gr.vmdk"))
            .grain_bytes(0, &ntfs_boot_sector())
            .grain(1, 0x11)
            .build();
        put32(&mut bytes, grain_table_entry(1), sector);
        let path = s.put("gr.vmdk", &bytes);

        let mut disk = open_vmdk(&path).expect("the header and tables are intact");
        use std::io::Seek;
        disk.seek(std::io::SeekFrom::Start(GRAIN_SECTORS * SECTOR as u64)).unwrap();
        let mut buf = vec![0u8; SECTOR];
        assert!(
            disk.read(&mut buf).is_err(),
            "a grain at sector {sector} of a {}-byte file must not be read",
            bytes.len()
        );
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn a_parent_chain_that_loops_is_refused_rather_than_followed_forever() {
    let s = Scratch::new("loop");
    s.put(
        "a.vmdk",
        &Forge::new(delta_descriptor("a.vmdk", "b.vmdk", "aaaaaaaa", "bbbbbbbb"))
            .grain(0, 0xA0)
            .build(),
    );
    let a = s.dir().join("a.vmdk");
    s.put(
        "b.vmdk",
        &Forge::new(delta_descriptor("b.vmdk", "a.vmdk", "bbbbbbbb", "aaaaaaaa"))
            .grain(0, 0xB0)
            .build(),
    );

    let err = open_vmdk(&a).expect_err("a two-link cycle must be refused");
    assert!(err.contains("loop"), "the refusal should say it is a loop: {err}");
}

#[test]
fn a_disk_that_is_its_own_parent_is_refused() {
    let s = Scratch::new("selfparent");
    let path = s.put(
        "self.vmdk",
        &Forge::new(delta_descriptor("self.vmdk", "self.vmdk", "cccccccc", "cccccccc"))
            .grain(0, 0xC0)
            .build(),
    );
    let err = open_vmdk(&path).expect_err("a self-parenting disk must be refused");
    assert!(err.contains("loop"), "got {err}");
}

#[test]
fn a_chain_deeper_than_the_limit_is_refused() {
    let s = Scratch::new("deep");
    const LINKS: usize = 200;
    for i in 0..LINKS {
        let name = format!("l{i}.vmdk");
        let parent = format!("l{}.vmdk", i + 1);
        let bytes = Forge::new(delta_descriptor(
            &name,
            &parent,
            &format!("{i:08x}"),
            &format!("{:08x}", i + 1),
        ))
        .grain(0, i as u8)
        .build();
        s.put(&name, &bytes);
    }
    let head = s.dir().join("l0.vmdk");
    let err = open_vmdk(&head).expect_err("a 200-link chain must be refused");
    assert!(
        err.contains("deep") || err.contains("not next to it"),
        "the refusal should say the chain is too deep or broken: {err}"
    );
}

#[test]
fn a_chain_whose_content_ids_do_not_match_is_refused() {
    let s = Scratch::new("cid");
    s.put("base.vmdk", &Forge::new(base_descriptor("base.vmdk")).grain(0, 0x11).build());
    let delta = s.put(
        "delta.vmdk",
        &Forge::new(delta_descriptor("delta.vmdk", "base.vmdk", "bbbbbbbb", "deadbeef"))
            .grain(1, 0x22)
            .build(),
    );
    let err = open_vmdk(&delta).expect_err("a mismatched chain must be refused");
    assert!(err.contains("CID"), "the refusal should name the content ids: {err}");
}

#[test]
fn a_parent_hint_cannot_escape_the_images_own_directory() {
    let s = Scratch::new("traversal");
    let outside = s.dir().join("secret.vmdk");
    std::fs::write(&outside, Forge::new(base_descriptor("secret.vmdk")).grain(0, 0x77).build())
        .unwrap();

    let inner = s.dir().join("disk");
    std::fs::create_dir_all(&inner).unwrap();

    for hint in [
        r"..\secret.vmdk",
        "../secret.vmdk",
        r"..\..\..\Windows\System32\config\SAM",
        r"C:\Windows\System32\config\SAM",
        "/etc/passwd",
        r"subdir\..\..\secret.vmdk",
    ] {
        let bytes = Forge::new(delta_descriptor("d.vmdk", hint, "bbbbbbbb", "aaaaaaaa"))
            .grain(0, 0xDD)
            .build();
        let path = inner.join("d.vmdk");
        std::fs::write(&path, &bytes).unwrap();

        match open_vmdk(&path) {
            Err(_) => {}
            Ok(disk) => {
                for link in &disk.info().chain {
                    assert!(
                        !link.name.contains(".."),
                        "a parent hint of {hint:?} produced link {:?}",
                        link.name
                    );
                    assert!(
                        inner.join(&link.name).exists(),
                        "link {:?} from hint {hint:?} was resolved outside {}",
                        link.name,
                        inner.display()
                    );
                }
            }
        }
    }
}

#[test]
fn a_descriptor_listing_a_ludicrous_number_of_extents_is_refused() {
    let s = Scratch::new("manyextents");
    let mut text = String::from(
        "# Disk DescriptorFile\nversion=1\nCID=aaaaaaaa\n\
                                 parentCID=ffffffff\ncreateType=\"twoGbMaxExtentSparse\"\n",
    );
    for i in 0..50_000 {
        text.push_str(&format!("RW 64 SPARSE \"e{i:06}.vmdk\"\n"));
    }
    let path = s.put("many.vmdk", text.as_bytes());
    assert!(open_vmdk(&path).is_err(), "50,000 extents must be refused");
}

#[test]
fn extent_lengths_that_overflow_when_summed_are_refused() {
    let s = Scratch::new("overflow");
    let text = format!(
        "# Disk DescriptorFile\nversion=1\nCID=aaaaaaaa\nparentCID=ffffffff\n\
         createType=\"twoGbMaxExtentSparse\"\nRW {m} SPARSE \"x.vmdk\"\n\
         RW {m} SPARSE \"y.vmdk\"\nRW {m} SPARSE \"z.vmdk\"\n",
        m = u64::MAX
    );
    let path = s.put("of.vmdk", text.as_bytes());
    assert!(open_vmdk(&path).is_err(), "summed extents that overflow must be refused");
}

#[test]
fn a_descriptor_naming_a_missing_extent_says_so() {
    let s = Scratch::new("missing");
    let text = "# Disk DescriptorFile\nversion=1\nCID=aaaaaaaa\nparentCID=ffffffff\n\
                createType=\"twoGbMaxExtentSparse\"\nRW 64 SPARSE \"absent.vmdk\"\n";
    let path = s.put("m.vmdk", text.as_bytes());
    let err = open_vmdk(&path).expect_err("a missing extent must be reported");
    assert!(err.contains("absent.vmdk"), "the error should name the file: {err}");
}

#[test]
fn a_delta_with_no_parent_beside_it_is_refused_rather_than_read_as_holes() {
    let s = Scratch::new("orphan");
    let path = s.put(
        "orphan.vmdk",
        &Forge::new(delta_descriptor("orphan.vmdk", "gone.vmdk", "bbbbbbbb", "aaaaaaaa"))
            .grain(0, 0x0F)
            .build(),
    );
    let err = open_vmdk(&path).expect_err("an orphaned delta must be refused");
    assert!(err.contains("not next to it"), "got {err}");
}

#[test]
fn a_descriptor_of_arbitrary_bytes_does_not_panic() {
    let s = Scratch::new("fuzzdesc");
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let path = s.dir().join("fuzz.vmdk");
    must_finish(120, "the descriptor fuzz sweep", move || {
        for _ in 0..200 {
            let mut junk = vec![0u8; (DESCRIPTOR_SECTORS as usize) * SECTOR];
            for chunk in junk.chunks_mut(8) {
                let v = next().to_le_bytes();
                let n = chunk.len();
                chunk.copy_from_slice(&v[..n]);
            }
            let text = String::from_utf8_lossy(&junk).into_owned();
            std::fs::write(&path, Forge::new(text).grain(0, 1).build()).expect("a fixture");
            let _ = Vmdk::open(&path);
        }
    });
}

#[test]
fn arbitrary_files_pointed_at_image_are_refused_clearly() {
    let s = Scratch::new("notadisk");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("text.txt", b"hello, this is not a disk\n".to_vec()),
        ("zeros.bin", vec![0u8; 4096]),
        ("ff.bin", vec![0xFFu8; 4096]),
        ("mz.exe", {
            let mut v = b"MZ".to_vec();
            v.resize(65536, 0x90);
            v
        }),
        ("descriptor-only.vmdk", b"# Disk DescriptorFile\nversion=1\n".to_vec()),
        ("kdmv-then-junk.vmdk", {
            let mut v = b"KDMV".to_vec();
            v.resize(8192, 0xAB);
            v
        }),
    ];
    for (name, bytes) in cases {
        let path = s.put(name, &bytes);
        let owned = path.clone();
        let result = must_finish(20, "opening a non-disk", move || {
            ImageFile::open(&owned).map(|_| ()).map_err(|e| e.to_string())
        });
        if result.is_ok() {
            assert!(
                open_image(&path).is_err(),
                "{name} must not be accepted as a disk with partitions"
            );
        }
    }
}

#[test]
fn a_directory_and_a_missing_path_are_errors_rather_than_faults() {
    let s = Scratch::new("weirdpaths");
    assert!(open_vmdk(s.dir()).is_err(), "a directory is not a disk");
    assert!(open_image(s.dir()).is_err(), "a directory is not an image");
    assert!(open_vmdk(Path::new("no-such-image-anywhere.vmdk")).is_err());
    assert!(open_image(Path::new("no-such-image-anywhere.vmdk")).is_err());
}

#[test]
fn no_single_byte_change_to_a_header_can_fault_the_reader() {
    let s = Scratch::new("bitflip");
    let good = Forge::new(base_descriptor("f.vmdk"))
        .grain_bytes(0, &ntfs_boot_sector())
        .grain(2, 0x22)
        .build();

    let path = s.dir().join("f.vmdk");
    must_finish(120, "the header mutation sweep", move || {
        let fields = 0..0x50usize;
        let pad = [0x50usize, 0x60, 0x80, 0x100, 0x180, 0x1FE, 0x1FF];
        for offset in fields.chain(pad) {
            for value in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                if good[offset] == value {
                    continue;
                }
                let mut bytes = good.clone();
                bytes[offset] = value;
                std::fs::write(&path, &bytes).expect("a fixture");
                if let Ok(mut disk) = Vmdk::open(&path) {
                    read_all_of(&mut disk);
                }
            }
        }
    });
}
