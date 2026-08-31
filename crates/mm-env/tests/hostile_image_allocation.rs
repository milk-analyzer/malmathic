use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

mod forge;
use forge::*;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            note(LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) }
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(p, layout, new_size) };
        if !out.is_null() {
            let live = LIVE
                .fetch_add(new_size.wrapping_sub(layout.size()), Ordering::Relaxed)
                .wrapping_add(new_size.wrapping_sub(layout.size()));
            note(live);
        }
        out
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            note(LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size());
        }
        p
    }
}

fn note(live: usize) {
    PEAK.fetch_max(live, Ordering::Relaxed);
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn peak_growth_of(f: impl FnOnce()) -> usize {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    f();
    PEAK.load(Ordering::Relaxed).saturating_sub(before)
}

const CEILING: usize = 8 * 1024 * 1024;

fn describe(bytes: usize) -> String {
    format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
}

#[test]
fn a_hostile_header_costs_a_refusal_and_not_a_gigabyte() {
    let s = Scratch::new("alloc");

    let good = s.put(
        "good.vmdk",
        &Forge::new(base_descriptor("good.vmdk")).grain_bytes(0, &ntfs_boot_sector()).build(),
    );
    let mut opened = false;
    let control = peak_growth_of(|| {
        opened = mm_env::Vmdk::open(&good).is_ok();
    });
    assert!(opened, "the control image must open");
    assert!(
        control < CEILING,
        "even a valid image should be cheap to open; it took {}",
        describe(control)
    );

    let mut cases: Vec<(&str, PathBuf)> = Vec::new();

    for (label, capacity) in [
        ("capacity = u64::MAX", u64::MAX),
        ("capacity = 2^63 sectors", 1u64 << 63),
        ("capacity = 2^45 sectors (16 PiB)", 1u64 << 45),
        ("capacity = 2^34 sectors (8 TiB)", 1u64 << 34),
    ] {
        let mut bytes = Forge::new(base_descriptor("c.vmdk")).grain(0, 1).build();
        put64(&mut bytes, at::CAPACITY, capacity);
        cases.push((label, s.put(&format!("cap-{capacity}.vmdk"), &bytes)));
    }

    for (label, sectors) in [
        ("descriptorSize = 2 M sectors (1 GB)", 2_097_152u64),
        ("descriptorSize = u32::MAX sectors", u64::from(u32::MAX)),
    ] {
        let mut bytes = Forge::new(base_descriptor("d.vmdk")).grain(0, 1).build();
        put64(&mut bytes, at::DESCRIPTOR_SIZE, sectors);
        cases.push((label, s.put(&format!("desc-{sectors}.vmdk"), &bytes)));
    }

    for (label, gte) in [("numGTEsPerGT = u32::MAX", u32::MAX), ("numGTEsPerGT = 2^24", 1u32 << 24)]
    {
        let mut bytes = Forge::new(base_descriptor("t.vmdk")).grain(0, 1).build();
        put32(&mut bytes, at::GTE_PER_GT, gte);
        cases.push((label, s.put(&format!("gte-{gte}.vmdk"), &bytes)));
    }

    {
        let mut bytes =
            Forge::new(base_descriptor("g.vmdk")).grain_bytes(0, &ntfs_boot_sector()).build();
        put32(&mut bytes, grain_directory_entry(0), u32::MAX);
        put32(&mut bytes, grain_directory_entry(1), u32::MAX);
        cases.push(("grain directory pointing past the file", s.put("gd.vmdk", &bytes)));
    }

    {
        s.put(
            "cyc-a.vmdk",
            &Forge::new(delta_descriptor("cyc-a.vmdk", "cyc-b.vmdk", "aaaaaaaa", "bbbbbbbb"))
                .grain(0, 0xA0)
                .build(),
        );
        s.put(
            "cyc-b.vmdk",
            &Forge::new(delta_descriptor("cyc-b.vmdk", "cyc-a.vmdk", "bbbbbbbb", "aaaaaaaa"))
                .grain(0, 0xB0)
                .build(),
        );
        cases.push(("a chain that loops", s.dir().join("cyc-a.vmdk")));
    }

    for (label, path) in &cases {
        let mut refused = false;
        let cost = peak_growth_of(|| {
            refused = mm_env::Vmdk::open(path).is_err();
        });
        assert!(refused, "{label} must be refused");
        assert!(
            cost < CEILING,
            "{label} was refused, but refusing it cost {} of heap — the bound is being \
             checked after the allocation rather than before it",
            describe(cost)
        );
    }
}
