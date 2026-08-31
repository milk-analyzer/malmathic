use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering::Relaxed};
use std::sync::{Mutex, MutexGuard};

use mm_sign::catalog::CatalogIndex;
use mm_sign::TrustStore;

struct Accounting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Accounting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size() as isize, Relaxed) + layout.size() as isize;
        PEAK.fetch_max(live, Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let delta = new_size as isize - layout.size() as isize;
        let live = LIVE.fetch_add(delta, Relaxed) + delta;
        PEAK.fetch_max(live, Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Accounting = Accounting;

static MEASURING: Mutex<()> = Mutex::new(());

fn serially() -> MutexGuard<'static, ()> {
    MEASURING.lock().unwrap_or_else(|e| e.into_inner())
}

fn peak_bytes<T>(body: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let value = body();
    let peak = PEAK.load(Relaxed);
    (value, usize::try_from(peak.saturating_sub(before)).unwrap_or(0))
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n < 0x1_0000 {
        out.push(0x82);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0x84);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn oid(text: &str) -> Vec<u8> {
    tlv(0x06, const_oid::ObjectIdentifier::new(text).unwrap().as_bytes())
}

fn oversized_catalog(members: usize) -> Vec<u8> {
    let usage = tlv(0x30, &oid("1.3.6.1.4.1.311.12.1.1"));
    let list_id = tlv(0x04, &[0x01; 16]);
    let this_update = tlv(0x17, b"240101000000Z");
    let algorithm = tlv(0x30, &[oid("2.16.840.1.101.3.4.2.1"), vec![0x05, 0x00]].concat());
    let mut items = Vec::with_capacity(members * 4);
    for _ in 0..members {
        items.extend_from_slice(&[0x30, 0x02, 0x04, 0x00]);
    }
    let ctl = tlv(0x30, &[usage, list_id, this_update, algorithm, tlv(0x30, &items)].concat());

    let signer = tlv(
        0x30,
        &[
            tlv(0x02, &[0x01]),
            tlv(
                0x30,
                &[
                    tlv(0x30, &tlv(0x31, &tlv(0x30, &[oid("2.5.4.3"), tlv(0x0c, b"x")].concat()))),
                    tlv(0x02, &[0x01]),
                ]
                .concat(),
            ),
            tlv(0x30, &[oid("2.16.840.1.101.3.4.2.1"), vec![0x05, 0x00]].concat()),
            tlv(0x30, &oid("1.2.840.10045.4.3.2")),
            tlv(0x04, &[0x42; 8]),
        ]
        .concat(),
    );

    let signed_data = tlv(
        0x30,
        &[
            tlv(0x02, &[0x01]),
            tlv(0x31, &tlv(0x30, &[oid("2.16.840.1.101.3.4.2.1"), vec![0x05, 0x00]].concat())),
            tlv(0x30, &[oid("1.3.6.1.4.1.311.10.1"), tlv(0xa0, &ctl)].concat()),
            tlv(0x31, &signer),
        ]
        .concat(),
    );
    tlv(0x30, &[oid("1.2.840.113549.1.7.2"), tlv(0xa0, &signed_data)].concat())
}

#[test]
fn a_catalog_claiming_a_million_members_does_not_allocate_per_member() {
    let _serial = serially();
    let catalog = oversized_catalog(1_000_000);
    let input = catalog.len();
    let trust = TrustStore::empty();
    let now = mm_sign::now();

    let mut index = CatalogIndex::new();
    let (_, peak) = peak_bytes(|| {
        let _ = index.add("hostile.cat", &catalog, &trust, now);
    });

    assert!(
        peak < input / 4,
        "indexing a {input}-byte catalog peaked at {peak} bytes of live allocation — \
         the member walk allocates per member, so a 64 MB catalog would cost gigabytes"
    );
    assert_eq!(index.stats().members_seen, 1_000_000);
}

#[test]
fn a_certificate_bag_of_a_million_entries_does_not_allocate_per_entry() {
    let _serial = serially();
    let mut bag = Vec::with_capacity(4_000_000);
    for _ in 0..1_000_000 {
        bag.extend_from_slice(&[0x30, 0x02, 0x04, 0x00]);
    }
    let signer = tlv(
        0x30,
        &[
            tlv(0x02, &[0x01]),
            tlv(
                0x30,
                &[
                    tlv(0x30, &tlv(0x31, &tlv(0x30, &[oid("2.5.4.3"), tlv(0x0c, b"x")].concat()))),
                    tlv(0x02, &[0x01]),
                ]
                .concat(),
            ),
            tlv(0x30, &[oid("2.16.840.1.101.3.4.2.1"), vec![0x05, 0x00]].concat()),
            tlv(0x30, &oid("1.2.840.10045.4.3.2")),
            tlv(0x04, &[0x42; 8]),
        ]
        .concat(),
    );
    let signed_data = tlv(
        0x30,
        &[
            tlv(0x02, &[0x01]),
            tlv(0x31, &[]),
            tlv(0x30, &[oid("1.3.6.1.4.1.311.2.1.4"), tlv(0xa0, &[0x05, 0x00])].concat()),
            tlv(0xa0, &bag),
            tlv(0x31, &signer),
        ]
        .concat(),
    );
    let pkcs7 = tlv(0x30, &[oid("1.2.840.113549.1.7.2"), tlv(0xa0, &signed_data)].concat());

    let input = pkcs7.len();
    let (result, peak) = peak_bytes(|| mm_sign::pkcs7::parse(&pkcs7).is_ok());
    assert!(result);
    assert!(
        peak < input / 4,
        "parsing a {input}-byte PKCS#7 peaked at {peak} bytes: the certificate bag is \
         materialised as one descriptor per entry before anything is decoded"
    );
}
