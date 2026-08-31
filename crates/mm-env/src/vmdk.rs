use crate::readonly::ReadOnlyFile;
use std::collections::{HashMap, VecDeque};
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const SECTOR: u64 = 512;

const SPARSE_MAGIC: [u8; 4] = *b"KDMV";

const TEXT_MAGIC: &[u8] = b"# Disk DescriptorFile";

const HEADER_LEN: usize = 512;

const FLAG_VALID_NEWLINE: u32 = 1 << 0;
const FLAG_REDUNDANT_GD: u32 = 1 << 1;
const FLAG_COMPRESSED: u32 = 1 << 16;
const FLAG_MARKERS: u32 = 1 << 17;

const GTE_UNALLOCATED: u32 = 0;
const GTE_ZEROED: u32 = 1;

const MAX_DESCRIPTOR: u64 = 1 << 20;

const MAX_EXTENTS: usize = 4096;

const MAX_GD_ENTRIES: usize = 1 << 20;

const MAX_GTE_PER_GT: u32 = 1 << 16;

const MAX_GRAIN_SECTORS: u64 = 1 << 17;

const MIN_GRAIN_SECTORS: u64 = 8;

const MAX_CHAIN: usize = 64;

const GT_CACHE_TABLES: usize = 512;

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap_or_default())
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or_default())
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default())
}

fn bad(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, msg.into())
}

#[derive(Clone, Copy, Debug)]
struct SparseHeader {
    version: u32,
    flags: u32,
    capacity_sectors: u64,
    grain_sectors: u64,
    descriptor_offset: u64,
    descriptor_sectors: u64,
    gte_per_gt: u32,
    rgd_offset: u64,
    gd_offset: u64,
    compress: u16,
}

impl SparseHeader {
    fn parse(h: &[u8; HEADER_LEN]) -> Result<Self> {
        if h[0..4] != SPARSE_MAGIC {
            return Err(bad("not a VMDK sparse extent: no KDMV magic"));
        }
        let out = SparseHeader {
            version: le32(h, 0x04),
            flags: le32(h, 0x08),
            capacity_sectors: le64(h, 0x0C),
            grain_sectors: le64(h, 0x14),
            descriptor_offset: le64(h, 0x1C),
            descriptor_sectors: le64(h, 0x24),
            gte_per_gt: le32(h, 0x2C),
            rgd_offset: le64(h, 0x30),
            gd_offset: le64(h, 0x38),
            compress: le16(h, 0x4D),
        };

        if out.compress != 0 {
            return Err(bad(format!(
                "this VMDK declares compressAlgorithm {} (compressed / streamOptimized grains); \
                 this build reads uncompressed sparse extents only and will not guess at the bytes",
                out.compress
            )));
        }
        if out.flags & (FLAG_COMPRESSED | FLAG_MARKERS) != 0 {
            return Err(bad(format!(
                "this VMDK sets flags {:#x} (compressed grains and/or stream markers); \
                 this build reads uncompressed sparse extents only",
                out.flags
            )));
        }
        if out.version == 0 || out.version > 3 {
            return Err(bad(format!(
                "VMDK sparse extent version {} is not recognised",
                out.version
            )));
        }

        if out.flags & FLAG_VALID_NEWLINE != 0
            && (h[0x49], h[0x4A], h[0x4B], h[0x4C]) != (b'\n', b' ', b'\r', b'\n')
        {
            return Err(bad(
                "the VMDK end-of-line canary is mangled; the file was probably transferred in \
                 text mode and its grain offsets can no longer be trusted",
            ));
        }

        if out.grain_sectors < MIN_GRAIN_SECTORS
            || out.grain_sectors > MAX_GRAIN_SECTORS
            || !out.grain_sectors.is_power_of_two()
        {
            return Err(bad(format!(
                "the VMDK header declares a {}-sector grain, which is not a credible power of two",
                out.grain_sectors
            )));
        }
        if out.gte_per_gt == 0 || out.gte_per_gt > MAX_GTE_PER_GT {
            return Err(bad(format!(
                "the VMDK header declares {} entries per grain table, which is not credible",
                out.gte_per_gt
            )));
        }
        if out.gd_offset == 0 && out.rgd_offset == 0 {
            return Err(bad("the VMDK header names no grain directory"));
        }
        Ok(out)
    }

    fn gd_entries(&self) -> Result<usize> {
        let grains = self.capacity_sectors.div_ceil(self.grain_sectors);
        let entries = grains.div_ceil(u64::from(self.gte_per_gt));
        let entries =
            usize::try_from(entries).map_err(|_| bad("the VMDK grain directory overflows"))?;
        if entries > MAX_GD_ENTRIES {
            return Err(bad(format!(
                "the VMDK header implies a {entries}-entry grain directory (a {:.1} TiB disk), \
                 which this build will not allocate",
                (self.capacity_sectors as f64 * SECTOR as f64) / (1u64 << 40) as f64
            )));
        }
        Ok(entries)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExtentSpec {
    sectors: u64,
    kind: SpecKind,
    file: Option<String>,
    offset_sectors: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpecKind {
    Sparse,
    Flat,
    Zero,
}

#[derive(Clone, Debug, Default)]
struct Descriptor {
    create_type: String,
    cid: String,
    parent_cid: String,
    parent_hint: Option<String>,
    extents: Vec<ExtentSpec>,
}

fn parse_descriptor(text: &str) -> Descriptor {
    let mut out = Descriptor::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(spec) = parse_extent_line(line) {
            if out.extents.len() < MAX_EXTENTS {
                out.extents.push(spec);
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let value = v.trim().trim_matches('"').trim().to_string();
        match k.trim().to_ascii_lowercase().as_str() {
            "createtype" => out.create_type = value,
            "cid" => out.cid = value,
            "parentcid" => out.parent_cid = value,
            "parentfilenamehint" => out.parent_hint = Some(value),
            _ => {}
        }
    }
    out
}

fn parse_extent_line(line: &str) -> Option<ExtentSpec> {
    let (head, rest) = match line.find('"') {
        Some(q) => (&line[..q], Some(&line[q + 1..])),
        None => (line, None),
    };
    let mut fields = head.split_whitespace();
    let access = fields.next()?;
    if !matches!(access.to_ascii_uppercase().as_str(), "RW" | "RDONLY" | "NOACCESS") {
        return None;
    }
    let sectors: u64 = fields.next()?.parse().ok()?;
    let kind = match fields.next()?.to_ascii_uppercase().as_str() {
        "SPARSE" | "VMFSSPARSE" => SpecKind::Sparse,
        "FLAT" | "VMFS" | "VMFSRAW" => SpecKind::Flat,
        "ZERO" => SpecKind::Zero,
        _ => return None,
    };
    let (file, tail) = match rest {
        Some(r) => {
            let end = r.find('"')?;
            (Some(r[..end].to_string()), &r[end + 1..])
        }
        None => (None, ""),
    };
    let offset_sectors = tail.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some(ExtentSpec { sectors, kind, file, offset_sectors })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Located {
    At(u64),
    Unallocated,
    Zeroed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheCost {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Debug, Default)]
struct GrainTables {
    map: HashMap<u32, Box<[u32]>>,
    order: VecDeque<u32>,
    cost: CacheCost,
}

#[derive(Debug)]
struct Sparse {
    file: ReadOnlyFile,
    file_len: u64,
    grain_sectors: u64,
    gte_per_gt: u32,
    gd: Vec<u32>,
    tables: GrainTables,
}

impl Sparse {
    fn read_u32s(
        file: &mut ReadOnlyFile,
        file_len: u64,
        at_sector: u64,
        count: usize,
    ) -> Result<Vec<u32>> {
        let bytes = (count as u64).checked_mul(4).ok_or_else(|| bad("a VMDK table overflows"))?;
        let at =
            at_sector.checked_mul(SECTOR).ok_or_else(|| bad("a VMDK table offset overflows"))?;
        if at.checked_add(bytes).is_none_or(|end| end > file_len) {
            return Err(bad(format!(
                "a VMDK table at sector {at_sector} runs {bytes} bytes past the end of a \
                 {file_len}-byte file"
            )));
        }
        let mut raw = vec![0u8; count * 4];
        file.seek(SeekFrom::Start(at))?;
        file.read_exact(&mut raw)?;
        Ok((0..count).map(|i| le32(&raw, i * 4)).collect())
    }

    fn open(mut file: ReadOnlyFile, header: &SparseHeader) -> Result<Self> {
        let file_len = file.len()?;
        let entries = header.gd_entries()?;

        let primary = if header.gd_offset != 0 { header.gd_offset } else { header.rgd_offset };
        let gd = match Self::read_u32s(&mut file, file_len, primary, entries) {
            Ok(gd) => gd,
            Err(first) => {
                if header.flags & FLAG_REDUNDANT_GD != 0
                    && header.rgd_offset != 0
                    && header.rgd_offset != primary
                {
                    Self::read_u32s(&mut file, file_len, header.rgd_offset, entries)?
                } else {
                    return Err(first);
                }
            }
        };

        Ok(Sparse {
            file,
            file_len,
            grain_sectors: header.grain_sectors,
            gte_per_gt: header.gte_per_gt,
            gd,
            tables: GrainTables::default(),
        })
    }

    fn to_grain_end(&self, local_sector: u64) -> u64 {
        (self.grain_sectors - (local_sector % self.grain_sectors)) * SECTOR
    }

    fn locate(&mut self, local_sector: u64) -> Result<Located> {
        let grain = local_sector / self.grain_sectors;
        let gd_index = grain / u64::from(self.gte_per_gt);
        let gt_index = (grain % u64::from(self.gte_per_gt)) as usize;

        let Ok(gd_index) = u32::try_from(gd_index) else { return Ok(Located::Unallocated) };
        let Some(&gt_sector) = self.gd.get(gd_index as usize) else {
            return Ok(Located::Unallocated);
        };
        if gt_sector == GTE_UNALLOCATED {
            return Ok(Located::Unallocated);
        }
        if gt_sector == GTE_ZEROED {
            return Ok(Located::Zeroed);
        }

        if !self.tables.map.contains_key(&gd_index) {
            self.tables.cost.misses += 1;
            let entries = Self::read_u32s(
                &mut self.file,
                self.file_len,
                u64::from(gt_sector),
                self.gte_per_gt as usize,
            )?;
            if self.tables.order.len() >= GT_CACHE_TABLES {
                if let Some(old) = self.tables.order.pop_front() {
                    self.tables.map.remove(&old);
                    self.tables.cost.evictions += 1;
                }
            }
            self.tables.order.push_back(gd_index);
            self.tables.map.insert(gd_index, entries.into_boxed_slice());
        } else {
            self.tables.cost.hits += 1;
        }

        let entry = self
            .tables
            .map
            .get(&gd_index)
            .and_then(|t| t.get(gt_index).copied())
            .unwrap_or(GTE_UNALLOCATED);

        match entry {
            GTE_UNALLOCATED => Ok(Located::Unallocated),
            GTE_ZEROED => Ok(Located::Zeroed),
            grain_sector => {
                let grain_start = u64::from(grain_sector)
                    .checked_mul(SECTOR)
                    .ok_or_else(|| bad("a VMDK grain offset overflows"))?;
                let grain_end = grain_start
                    .checked_add(self.grain_sectors * SECTOR)
                    .ok_or_else(|| bad("a VMDK grain extent overflows"))?;
                if grain_end > self.file_len {
                    return Err(bad(format!(
                        "a VMDK grain table points at sector {grain_sector}, whose grain ends at \
                         {grain_end}, past the end of its own {}-byte file",
                        self.file_len
                    )));
                }
                let within = (local_sector % self.grain_sectors) * SECTOR;
                Ok(Located::At(grain_start + within))
            }
        }
    }
}

#[derive(Debug)]
enum Body {
    Sparse(Sparse),
    Flat { file: ReadOnlyFile, file_len: u64, base: u64 },
    Zero,
}

#[derive(Debug)]
struct Extent {
    start: u64,
    sectors: u64,
    body: Body,
}

#[derive(Debug)]
struct Link {
    name: String,
    cid: String,
    parent_cid: String,
    extents: Vec<Extent>,
}

impl Link {
    fn extent_of(&self, sector: u64) -> Option<usize> {
        self.extents.iter().position(|e| sector >= e.start && sector < e.start + e.sectors)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainLink {
    pub name: String,
    pub cid: String,
    pub parent_cid: String,
    pub extents: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmdkInfo {
    pub create_type: String,
    pub capacity_bytes: u64,
    pub grain_bytes: u64,
    pub extents: usize,
    pub chain: Vec<ChainLink>,
}

impl VmdkInfo {
    pub fn summary(&self) -> String {
        let depth = self.chain.len();
        format!(
            "VMDK {} — {:.1} GiB, {} KiB grains, {} extent{}, {} link{} in the snapshot chain",
            self.create_type,
            self.capacity_bytes as f64 / (1u64 << 30) as f64,
            self.grain_bytes / 1024,
            self.extents,
            if self.extents == 1 { "" } else { "s" },
            depth,
            if depth == 1 { "" } else { "s" },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Provenance {
    Stored { link: usize, name: String },
    NeverWritten,
    ExplicitlyZeroed { link: usize, name: String },
    PastEnd,
}

#[derive(Debug)]
pub struct Vmdk {
    chain: Vec<Link>,
    capacity: u64,
    pos: u64,
    info: VmdkInfo,
}

impl Vmdk {
    pub fn looks_like_one(path: &Path) -> bool {
        let mut file = match ReadOnlyFile::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut head = [0u8; 64];
        let got = match read_up_to(&mut file, &mut head) {
            Ok(n) => n,
            Err(_) => return false,
        };
        let head = &head[..got];
        head.starts_with(&SPARSE_MAGIC) || head.starts_with(TEXT_MAGIC)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let mut chain: Vec<Link> = Vec::new();
        let mut seen: Vec<PathBuf> = Vec::new();
        let mut next = Some(path.to_path_buf());
        let mut geometry: Option<(u64, u64)> = None;
        let mut create_type = String::new();

        while let Some(current) = next.take() {
            if chain.len() >= MAX_CHAIN {
                return Err(bad(format!(
                    "this VMDK's parent chain is more than {MAX_CHAIN} links deep, which is not \
                     a disk anybody made on purpose"
                )));
            }
            let canonical = current.canonicalize().unwrap_or_else(|_| current.clone());
            if seen.contains(&canonical) {
                return Err(bad(format!(
                    "this VMDK's parent chain loops back to {}",
                    canonical.display()
                )));
            }
            seen.push(canonical);

            let (descriptor, dir) = read_descriptor(&current)?;
            if create_type.is_empty() {
                create_type = descriptor.create_type.clone();
            }

            let extents = build_extents(&descriptor, &dir, &current)?;
            let capacity_sectors: u64 = extents.iter().map(|e| e.sectors).sum();
            let grain = extents
                .iter()
                .find_map(|e| match &e.body {
                    Body::Sparse(s) => Some(s.grain_sectors * SECTOR),
                    _ => None,
                })
                .unwrap_or(SECTOR);
            if geometry.is_none() {
                geometry = Some((capacity_sectors * SECTOR, grain));
            }

            let name = current
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| current.display().to_string());

            let parent_cid = descriptor.parent_cid.clone();
            let is_base = parent_cid.is_empty() || parent_cid.eq_ignore_ascii_case("ffffffff");

            chain.push(Link {
                name,
                cid: descriptor.cid.clone(),
                parent_cid: parent_cid.clone(),
                extents,
            });

            if !is_base {
                next = Some(find_parent(
                    &dir,
                    &current,
                    &parent_cid,
                    descriptor.parent_hint.as_deref(),
                )?);
            }
        }

        for pair in chain.windows(2) {
            let (child, parent) = (&pair[0], &pair[1]);
            if !child.parent_cid.is_empty()
                && !parent.cid.is_empty()
                && !child.parent_cid.eq_ignore_ascii_case(&parent.cid)
            {
                return Err(bad(format!(
                    "{} expects a parent with CID {} but {} has CID {}; the chain does not link, \
                     and the bytes it would produce are not any state this disk was ever in",
                    child.name, child.parent_cid, parent.name, parent.cid
                )));
            }
        }

        let (capacity, grain_bytes) = geometry.ok_or_else(|| bad("this VMDK has no extents"))?;
        if capacity == 0 {
            return Err(bad("this VMDK declares a zero-length disk"));
        }

        let info = VmdkInfo {
            create_type,
            capacity_bytes: capacity,
            grain_bytes,
            extents: chain.first().map(|l| l.extents.len()).unwrap_or(0),
            chain: chain
                .iter()
                .map(|l| ChainLink {
                    name: l.name.clone(),
                    cid: l.cid.clone(),
                    parent_cid: l.parent_cid.clone(),
                    extents: l.extents.len(),
                })
                .collect(),
        };

        Ok(Vmdk { chain, capacity, pos: 0, info })
    }

    pub fn disk_size(&self) -> u64 {
        self.capacity
    }

    pub fn info(&self) -> &VmdkInfo {
        &self.info
    }

    pub fn cache_cost(&self) -> CacheCost {
        let mut out = CacheCost::default();
        for link in &self.chain {
            for extent in &link.extents {
                if let Body::Sparse(s) = &extent.body {
                    out.hits += s.tables.cost.hits;
                    out.misses += s.tables.cost.misses;
                    out.evictions += s.tables.cost.evictions;
                }
            }
        }
        out
    }

    pub fn provenance(&mut self, offset: u64) -> Result<Provenance> {
        if offset >= self.capacity {
            return Ok(Provenance::PastEnd);
        }
        let sector = offset / SECTOR;
        for index in 0..self.chain.len() {
            match self.locate_in(index, sector)? {
                Some((Located::At(_), _)) => {
                    return Ok(Provenance::Stored {
                        link: index,
                        name: self.chain[index].name.clone(),
                    })
                }
                Some((Located::Zeroed, _)) => {
                    return Ok(Provenance::ExplicitlyZeroed {
                        link: index,
                        name: self.chain[index].name.clone(),
                    })
                }
                Some((Located::Unallocated, _)) | None => continue,
            }
        }
        Ok(Provenance::NeverWritten)
    }

    fn locate_in(&mut self, link: usize, sector: u64) -> Result<Option<(Located, u64)>> {
        let Some(index) = self.chain[link].extent_of(sector) else { return Ok(None) };
        let extent = &mut self.chain[link].extents[index];
        let local = sector - extent.start;
        let to_extent_end = (extent.sectors - local) * SECTOR;

        match &mut extent.body {
            Body::Zero => Ok(Some((Located::Zeroed, to_extent_end))),
            Body::Flat { file_len, base, .. } => {
                let at = base
                    .checked_add(local * SECTOR)
                    .ok_or_else(|| bad("a VMDK flat offset overflows"))?;
                if at >= *file_len {
                    return Ok(Some((Located::Unallocated, to_extent_end)));
                }
                Ok(Some((Located::At(at), to_extent_end.min(*file_len - at))))
            }
            Body::Sparse(sparse) => {
                let found = sparse.locate(local)?;
                let run = sparse.to_grain_end(local).min(to_extent_end);
                Ok(Some((found, run)))
            }
        }
    }
}

fn read_descriptor(path: &Path) -> Result<(Descriptor, PathBuf)> {
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let mut file = ReadOnlyFile::open(path)?;
    let mut head = [0u8; HEADER_LEN];
    let got = read_up_to(&mut file, &mut head)?;

    if got >= HEADER_LEN && head[0..4] == SPARSE_MAGIC {
        let header = SparseHeader::parse(&head)?;
        if header.descriptor_offset == 0 || header.descriptor_sectors == 0 {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            return Ok((
                Descriptor {
                    create_type: "sparseExtent".into(),
                    cid: String::new(),
                    parent_cid: "ffffffff".into(),
                    parent_hint: None,
                    extents: vec![ExtentSpec {
                        sectors: header.capacity_sectors,
                        kind: SpecKind::Sparse,
                        file: name,
                        offset_sectors: 0,
                    }],
                },
                dir,
            ));
        }
        let bytes = header
            .descriptor_sectors
            .checked_mul(SECTOR)
            .ok_or_else(|| bad("the VMDK descriptor size overflows"))?;
        if bytes > MAX_DESCRIPTOR {
            return Err(bad(format!(
                "this VMDK declares a {bytes}-byte descriptor; the cap is {MAX_DESCRIPTOR}"
            )));
        }
        let at = header
            .descriptor_offset
            .checked_mul(SECTOR)
            .ok_or_else(|| bad("the VMDK descriptor offset overflows"))?;
        let mut raw = vec![0u8; bytes as usize];
        file.seek(SeekFrom::Start(at))?;
        let got = read_up_to(&mut file, &mut raw)?;
        raw.truncate(got);
        return Ok((parse_descriptor(&decode(&raw)), dir));
    }

    let len = file.len()?;
    if len > MAX_DESCRIPTOR {
        return Err(bad(format!(
            "{} is {len} bytes, too large for a VMDK text descriptor",
            path.display()
        )));
    }
    let mut raw = vec![0u8; len as usize];
    file.seek(SeekFrom::Start(0))?;
    let got = read_up_to(&mut file, &mut raw)?;
    raw.truncate(got);
    if !raw.starts_with(TEXT_MAGIC) {
        return Err(bad(format!(
            "{} is neither a sparse extent nor a VMDK descriptor",
            path.display()
        )));
    }
    Ok((parse_descriptor(&decode(&raw)), dir))
}

fn decode(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn read_up_to(file: &mut ReadOnlyFile, buf: &mut [u8]) -> Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match file.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

fn resolve_sibling(dir: &Path, name: &str) -> PathBuf {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or(name);
    dir.join(leaf)
}

const MAX_PARENT_SCAN: usize = 4096;

fn find_parent(dir: &Path, child: &Path, want: &str, hint: Option<&str>) -> Result<PathBuf> {
    let hint_note = match hint {
        Some(raw) => {
            let candidate = resolve_sibling(dir, raw);
            if candidate.exists() {
                match read_descriptor(&candidate) {
                    Ok((parent, _)) if parent.cid.eq_ignore_ascii_case(want) => {
                        return Ok(candidate)
                    }
                    Ok((parent, _)) => format!(
                        "its parentFileNameHint names {raw:?}, but that file's CID is {}",
                        parent.cid
                    ),
                    Err(why) => format!(
                        "its parentFileNameHint names {raw:?}, which could not be read ({why})"
                    ),
                }
            } else {
                format!("its parentFileNameHint names {raw:?}, which is not next to it")
            }
        }
        None => "it carries no parentFileNameHint at all".to_string(),
    };

    let mut matches: Vec<PathBuf> = Vec::new();
    let mut scanned = 0usize;
    let listing = std::fs::read_dir(dir)?;
    for entry in listing.flatten() {
        if scanned >= MAX_PARENT_SCAN {
            break;
        }
        let path = entry.path();
        if !path.extension().is_some_and(|e| e.eq_ignore_ascii_case("vmdk")) {
            continue;
        }
        if same_file(&path, child) {
            continue;
        }
        scanned += 1;
        if read_descriptor(&path).is_ok_and(|(d, _)| d.cid.eq_ignore_ascii_case(want)) {
            matches.push(path);
        }
    }

    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(bad(format!(
            "the snapshot chain is broken at {}: it needs the disk whose CID is {want}, and no \
             .vmdk in {} has that CID ({hint_note}). Without the parent this link is mostly \
             holes, and reading it alone would be a false picture of the disk rather than a \
             partial one",
            child.display(),
            dir.display()
        ))),
        n => Err(bad(format!(
            "the snapshot chain is broken at {}: {n} files in {} claim CID {want} ({}), so which \
             one is its parent is UNKNOWN and guessing would mix two points in time into one disk",
            child.display(),
            dir.display(),
            matches.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    canon(a) == canon(b)
}

fn build_extents(descriptor: &Descriptor, dir: &Path, path: &Path) -> Result<Vec<Extent>> {
    if descriptor.extents.is_empty() {
        return Err(bad(format!("{} lists no extents", path.display())));
    }
    if descriptor.extents.len() > MAX_EXTENTS {
        return Err(bad(format!(
            "{} lists {} extents; the cap is {MAX_EXTENTS}",
            path.display(),
            descriptor.extents.len()
        )));
    }

    let mut out = Vec::with_capacity(descriptor.extents.len());
    let mut start = 0u64;
    for spec in &descriptor.extents {
        let body = match spec.kind {
            SpecKind::Zero => Body::Zero,
            SpecKind::Sparse => {
                let name = spec.file.clone().ok_or_else(|| bad("a SPARSE extent names no file"))?;
                let target = resolve_sibling(dir, &name);
                let mut file = ReadOnlyFile::open(&target).map_err(|e| {
                    Error::new(e.kind(), format!("opening VMDK extent {}: {e}", target.display()))
                })?;
                let mut head = [0u8; HEADER_LEN];
                if read_up_to(&mut file, &mut head)? < HEADER_LEN {
                    return Err(bad(format!(
                        "{} is too short to be a sparse extent",
                        target.display()
                    )));
                }
                let header = SparseHeader::parse(&head)?;
                Body::Sparse(Sparse::open(file, &header)?)
            }
            SpecKind::Flat => {
                let name = spec.file.clone().ok_or_else(|| bad("a FLAT extent names no file"))?;
                let target = resolve_sibling(dir, &name);
                let file = ReadOnlyFile::open(&target).map_err(|e| {
                    Error::new(e.kind(), format!("opening VMDK extent {}: {e}", target.display()))
                })?;
                let file_len = file.len()?;
                let base = spec
                    .offset_sectors
                    .checked_mul(SECTOR)
                    .ok_or_else(|| bad("a FLAT extent offset overflows"))?;
                Body::Flat { file, file_len, base }
            }
        };
        out.push(Extent { start, sectors: spec.sectors, body });
        start = start
            .checked_add(spec.sectors)
            .ok_or_else(|| bad("VMDK extent offsets overflow the guest address space"))?;
    }
    Ok(out)
}

impl Read for Vmdk {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.pos >= self.capacity || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min((self.capacity - self.pos) as usize) as u64;
        let sector = self.pos / SECTOR;
        let within = self.pos % SECTOR;

        let mut run = want;
        let mut source: Option<(usize, u64)> = None;

        for index in 0..self.chain.len() {
            let Some((found, available)) = self.locate_in(index, sector)? else { continue };
            let available = available.saturating_sub(within);
            if available == 0 {
                continue;
            }
            run = run.min(available);
            match found {
                Located::At(at) => {
                    source = Some((index, at + within));
                    break;
                }
                Located::Zeroed => break,
                Located::Unallocated => continue,
            }
        }

        let n = run.clamp(1, want) as usize;
        match source {
            None => buf[..n].fill(0),
            Some((link, at)) => {
                let Some(index) = self.chain[link].extent_of(sector) else {
                    buf[..n].fill(0);
                    self.pos += n as u64;
                    return Ok(n);
                };
                match &mut self.chain[link].extents[index].body {
                    Body::Sparse(s) => {
                        s.file.seek(SeekFrom::Start(at))?;
                        s.file.read_exact(&mut buf[..n])?;
                    }
                    Body::Flat { file, .. } => {
                        file.seek(SeekFrom::Start(at))?;
                        file.read_exact(&mut buf[..n])?;
                    }
                    Body::Zero => buf[..n].fill(0),
                }
            }
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Vmdk {
    fn seek(&mut self, to: SeekFrom) -> Result<u64> {
        let next = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.capacity.checked_add_signed(n),
            SeekFrom::Current(n) => self.pos.checked_add_signed(n),
        };
        match next {
            Some(n) => {
                self.pos = n;
                Ok(n)
            }
            None => Err(Error::new(ErrorKind::InvalidInput, "seek before the start of the disk")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    const T_GRAIN: u64 = 8;
    const T_GTE: u32 = 512;
    const T_CAPACITY: u64 = T_GRAIN * 4;

    fn scratch(name: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "mm-env-vmdk-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir.join(name)
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn sparse_fixture(path: &Path, descriptor: &str, gt: [u32; 4], fill: [u8; 4]) {
        const GD_SECTOR: u64 = 3;
        const GT_SECTOR: u64 = 4;
        let total_sectors = 8 + T_GRAIN * 4;
        let mut file = vec![0u8; (total_sectors * SECTOR) as usize];

        file[0..4].copy_from_slice(&SPARSE_MAGIC);
        put32(&mut file, 0x04, 1);
        put32(&mut file, 0x08, FLAG_VALID_NEWLINE | FLAG_REDUNDANT_GD);
        put64(&mut file, 0x0C, T_CAPACITY);
        put64(&mut file, 0x14, T_GRAIN);
        put64(&mut file, 0x1C, if descriptor.is_empty() { 0 } else { 1 });
        put64(&mut file, 0x24, if descriptor.is_empty() { 0 } else { 2 });
        put32(&mut file, 0x2C, T_GTE);
        put64(&mut file, 0x30, GD_SECTOR);
        put64(&mut file, 0x38, GD_SECTOR);
        put64(&mut file, 0x40, 8);
        file[0x49] = b'\n';
        file[0x4A] = b' ';
        file[0x4B] = b'\r';
        file[0x4C] = b'\n';

        let at = SECTOR as usize;
        file[at..at + descriptor.len()].copy_from_slice(descriptor.as_bytes());

        put32(&mut file, (GD_SECTOR * SECTOR) as usize, GT_SECTOR as u32);
        for (i, entry) in gt.iter().enumerate() {
            put32(&mut file, (GT_SECTOR * SECTOR) as usize + i * 4, *entry);
        }
        for (i, entry) in gt.iter().enumerate() {
            if *entry > GTE_ZEROED {
                let start = (u64::from(*entry) * SECTOR) as usize;
                let end = start + (T_GRAIN * SECTOR) as usize;
                if end <= file.len() {
                    file[start..end].fill(fill[i]);
                }
            }
        }
        std::fs::write(path, &file).expect("writing a fixture");
    }

    fn base_descriptor(name: &str) -> String {
        format!(
            "# Disk DescriptorFile\nversion=1\nencoding=\"windows-1251\"\nCID=aaaa0001\n\
             parentCID=ffffffff\ncreateType=\"monolithicSparse\"\n\n\
             # Extent description\nRW {T_CAPACITY} SPARSE \"{name}\"\n"
        )
    }

    fn delta_descriptor(name: &str, parent: &str, cid: &str, parent_cid: &str) -> String {
        format!(
            "# Disk DescriptorFile\nversion=1\nCID={cid}\nparentCID={parent_cid}\n\
             createType=\"monolithicSparse\"\nparentFileNameHint=\"{parent}\"\n\n\
             RW {T_CAPACITY} SPARSE \"{name}\"\n"
        )
    }

    fn read_at(v: &mut Vmdk, offset: u64, len: usize) -> Vec<u8> {
        v.seek(SeekFrom::Start(offset)).expect("seeking");
        let mut out = vec![0u8; len];
        v.read_exact(&mut out).expect("reading");
        out
    }

    #[test]
    fn the_header_offsets_match_the_bytes_measured_off_the_real_disk() {
        let mut h = [0u8; HEADER_LEN];
        let real: &[u8] = &[
            0x4b, 0x44, 0x4d, 0x56, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x33, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x78, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0a, 0x20, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00,
        ];
        h[..real.len()].copy_from_slice(real);

        let parsed = SparseHeader::parse(&h).expect("the real header parses");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.flags, FLAG_VALID_NEWLINE | FLAG_REDUNDANT_GD);
        assert_eq!(parsed.capacity_sectors, 251_658_240, "120 GiB");
        assert_eq!(parsed.capacity_sectors * SECTOR, 128_849_018_880);
        assert_eq!(parsed.grain_sectors, 128, "64 KiB grains");
        assert_eq!(parsed.descriptor_offset, 1);
        assert_eq!(parsed.descriptor_sectors, 20);
        assert_eq!(parsed.gte_per_gt, 512);
        assert_eq!(parsed.rgd_offset, 21);
        assert_eq!(parsed.gd_offset, 15_411);
        assert_eq!(parsed.compress, 0, "no compression on any measured file");
        assert_eq!(parsed.gd_entries().expect("bounded"), 3_840);
    }

    #[test]
    fn a_split_extent_header_declares_no_descriptor_of_its_own() {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(&SPARSE_MAGIC);
        put32(&mut h, 0x04, 1);
        put32(&mut h, 0x08, 3);
        put64(&mut h, 0x0C, 8_323_072);
        put64(&mut h, 0x14, 128);
        put64(&mut h, 0x1C, 0);
        put64(&mut h, 0x24, 0);
        put32(&mut h, 0x2C, 512);
        put64(&mut h, 0x30, 1);
        put64(&mut h, 0x38, 510);
        h[0x49] = b'\n';
        h[0x4A] = b' ';
        h[0x4B] = b'\r';
        h[0x4C] = b'\n';
        let parsed = SparseHeader::parse(&h).expect("a split extent header parses");
        assert_eq!(parsed.descriptor_offset, 0);
        assert_eq!(parsed.gd_entries().expect("bounded"), 127);
    }

    #[test]
    fn the_real_monolithic_descriptor_parses_to_its_chain_fields() {
        let d = parse_descriptor(
            "# Disk DescriptorFile\nversion=1\nencoding=\"windows-1251\"\nCID=8be0d27b\n\
             parentCID=f48e54aa\ncreateType=\"monolithicSparse\"\n\
             parentFileNameHint=\"WIN11-LAB-000004.vmdk\"\n\
             # Extent description\nRW 251658240 SPARSE \"WIN11-LAB-000005.vmdk\"\n\
             ddb.longContentID = \"bfff32fe28eae0b5a23d2b958be0d27b\"\n",
        );
        assert_eq!(d.create_type, "monolithicSparse");
        assert_eq!(d.cid, "8be0d27b");
        assert_eq!(d.parent_cid, "f48e54aa");
        assert_eq!(d.parent_hint.as_deref(), Some("WIN11-LAB-000004.vmdk"));
        assert_eq!(d.extents.len(), 1);
        assert_eq!(d.extents[0].sectors, 251_658_240);
        assert_eq!(d.extents[0].kind, SpecKind::Sparse);
        assert_eq!(d.extents[0].file.as_deref(), Some("WIN11-LAB-000005.vmdk"));
    }

    #[test]
    fn the_real_split_descriptor_parses_all_sixteen_extents() {
        let mut text = String::from(
            "# Disk DescriptorFile\nversion=1\nencoding=\"windows-1251\"\nCID=9c11f696\n\
             parentCID=ffffffff\ncreateType=\"twoGbMaxExtentSparse\"\n\n# Extent description\n",
        );
        for i in 1..=15 {
            text.push_str(&format!("RW 8323072 SPARSE \"SPLITDISK-s{i:03}.vmdk\"\n"));
        }
        text.push_str("RW 983040 SPARSE \"SPLITDISK-s016.vmdk\"\n");
        text.push_str("ddb.adapterType = \"lsilogic\"\nddb.geometry.cylinders = \"7832\"\n");

        let d = parse_descriptor(&text);
        assert_eq!(d.create_type, "twoGbMaxExtentSparse");
        assert_eq!(d.extents.len(), 16);
        assert_eq!(d.extents[15].sectors, 983_040);
        assert_eq!(d.extents[15].file.as_deref(), Some("SPLITDISK-s016.vmdk"));
        let total: u64 = d.extents.iter().map(|e| e.sectors).sum();
        assert_eq!(total * SECTOR, 64_424_509_440, "60 GiB across sixteen extents");
        assert!(d.extents.iter().all(|e| e.file.is_some()));
    }

    #[test]
    fn an_extent_filename_containing_spaces_survives_parsing() {
        let spec = parse_extent_line("RW 8323072 SPARSE \"Static Analyzer-000001-s001.vmdk\"")
            .expect("a quoted name with spaces");
        assert_eq!(spec.file.as_deref(), Some("Static Analyzer-000001-s001.vmdk"));
        assert_eq!(spec.sectors, 8_323_072);
    }

    #[test]
    fn a_flat_extent_line_keeps_its_offset_and_zero_and_rdonly_are_understood() {
        let flat = parse_extent_line("RW 20971520 FLAT \"disk-flat.vmdk\" 0").expect("flat");
        assert_eq!(flat.kind, SpecKind::Flat);
        assert_eq!(flat.offset_sectors, 0);
        let offset = parse_extent_line("RDONLY 100 FLAT \"d.vmdk\" 2048").expect("flat at offset");
        assert_eq!(offset.offset_sectors, 2048);
        assert_eq!(parse_extent_line("RW 4096 ZERO").expect("zero").kind, SpecKind::Zero);
        assert!(parse_extent_line("ddb.geometry.heads = \"255\"").is_none());
        assert!(parse_extent_line("createType=\"monolithicSparse\"").is_none());
        assert!(parse_extent_line("RW 100 SESPARSE \"d.vmdk\"").is_none());
    }

    #[test]
    fn an_allocated_grain_reads_back_byte_for_byte() {
        let path = scratch("mono.vmdk");
        sparse_fixture(&path, &base_descriptor("mono.vmdk"), [8, 0, 0, 0], [0xAB, 0, 0, 0]);
        let mut v = Vmdk::open(&path).expect("opening the fixture");
        assert_eq!(v.disk_size(), T_CAPACITY * SECTOR);
        assert_eq!(v.info().create_type, "monolithicSparse");
        assert!(read_at(&mut v, 0, (T_GRAIN * SECTOR) as usize).iter().all(|b| *b == 0xAB));
    }

    #[test]
    fn an_unallocated_grain_on_a_base_disk_reads_as_zeroes() {
        let path = scratch("mono.vmdk");
        sparse_fixture(&path, &base_descriptor("mono.vmdk"), [8, 0, 0, 0], [0xAB, 0, 0, 0]);
        let mut v = Vmdk::open(&path).expect("opening");
        let hole = read_at(&mut v, T_GRAIN * SECTOR, (T_GRAIN * SECTOR) as usize);
        assert!(hole.iter().all(|b| *b == 0));
        assert_eq!(v.provenance(T_GRAIN * SECTOR).expect("provenance"), Provenance::NeverWritten);
    }

    #[test]
    fn a_read_across_a_grain_boundary_is_split_and_reassembles() {
        let path = scratch("mono.vmdk");
        sparse_fixture(&path, &base_descriptor("mono.vmdk"), [8, 16, 0, 0], [0xAB, 0xCD, 0, 0]);
        let mut v = Vmdk::open(&path).expect("opening");
        let got = read_at(&mut v, T_GRAIN * SECTOR - 16, 32);
        assert!(got[..16].iter().all(|b| *b == 0xAB), "the tail of grain 0");
        assert!(got[16..].iter().all(|b| *b == 0xCD), "the head of grain 1");
    }

    #[test]
    fn a_short_read_is_legal_and_read_exact_loops_over_it() {
        let path = scratch("mono.vmdk");
        sparse_fixture(&path, &base_descriptor("mono.vmdk"), [8, 16, 0, 0], [1, 2, 0, 0]);
        let mut v = Vmdk::open(&path).expect("opening");
        v.seek(SeekFrom::Start(0)).expect("seeking");
        let n = v.read(&mut vec![0u8; (T_GRAIN * SECTOR * 2) as usize]).expect("a read");
        assert_eq!(n as u64, T_GRAIN * SECTOR, "reads stop at the grain boundary");
    }

    #[test]
    fn reading_past_the_end_of_the_disk_returns_nothing_and_seeking_back_is_an_error() {
        let path = scratch("mono.vmdk");
        sparse_fixture(&path, &base_descriptor("mono.vmdk"), [8, 0, 0, 0], [1, 0, 0, 0]);
        let mut v = Vmdk::open(&path).expect("opening");
        v.seek(SeekFrom::Start(T_CAPACITY * SECTOR)).expect("seeking to the end");
        assert_eq!(v.read(&mut [0u8; 16]).expect("past the end"), 0);
        assert_eq!(v.provenance(T_CAPACITY * SECTOR).expect("provenance"), Provenance::PastEnd);
        v.seek(SeekFrom::Start(0)).expect("seeking");
        assert!(v.seek(SeekFrom::Current(-1)).is_err(), "before the start is an error");
    }

    fn chain_fixture(delta_gt: [u32; 4], delta_fill: [u8; 4]) -> PathBuf {
        let base = scratch("base.vmdk");
        let dir = base.parent().expect("a directory").to_path_buf();
        sparse_fixture(&base, &base_descriptor("base.vmdk"), [8, 16, 24, 0], [0x11, 0x22, 0x33, 0]);
        let delta = dir.join("delta.vmdk");
        sparse_fixture(
            &delta,
            &delta_descriptor("delta.vmdk", "base.vmdk", "aaaa0002", "aaaa0001"),
            delta_gt,
            delta_fill,
        );
        delta
    }

    #[test]
    fn a_grain_missing_from_the_delta_comes_from_the_parent_rather_than_reading_as_zeroes() {
        let delta = chain_fixture([8, GTE_UNALLOCATED, GTE_UNALLOCATED, 0], [0x99, 0, 0, 0]);
        let mut v = Vmdk::open(&delta).expect("opening the chain");
        assert_eq!(v.info().chain.len(), 2);
        assert_eq!(v.info().chain[0].name, "delta.vmdk");
        assert_eq!(v.info().chain[1].name, "base.vmdk");

        let g = (T_GRAIN * SECTOR) as usize;
        assert!(read_at(&mut v, 0, g).iter().all(|b| *b == 0x99), "the delta's own grain wins");
        assert!(read_at(&mut v, g as u64, g).iter().all(|b| *b == 0x22), "grain 1 from the base");
        assert!(
            read_at(&mut v, 2 * g as u64, g).iter().all(|b| *b == 0x33),
            "grain 2 from the base"
        );

        assert_eq!(
            v.provenance(0).expect("provenance"),
            Provenance::Stored { link: 0, name: "delta.vmdk".into() }
        );
        assert_eq!(
            v.provenance(g as u64).expect("provenance"),
            Provenance::Stored { link: 1, name: "base.vmdk".into() }
        );
    }

    #[test]
    fn a_grain_explicitly_zeroed_in_the_delta_hides_the_parents_bytes() {
        let delta = chain_fixture([8, GTE_ZEROED, GTE_UNALLOCATED, 0], [0x99, 0, 0, 0]);
        let mut v = Vmdk::open(&delta).expect("opening the chain");
        let g = (T_GRAIN * SECTOR) as usize;
        assert!(
            read_at(&mut v, g as u64, g).iter().all(|b| *b == 0),
            "zeroed in the delta, not the base's 0x22"
        );
        assert_eq!(
            v.provenance(g as u64).expect("provenance"),
            Provenance::ExplicitlyZeroed { link: 0, name: "delta.vmdk".into() },
            "and the caller is told it was zeroed rather than never written"
        );
    }

    #[test]
    fn a_delta_whose_parent_is_missing_is_refused_rather_than_read_as_holes() {
        let dir = scratch("x").parent().expect("a directory").to_path_buf();
        let delta = dir.join("orphan.vmdk");
        sparse_fixture(
            &delta,
            &delta_descriptor("orphan.vmdk", "absent.vmdk", "aaaa0002", "aaaa0001"),
            [8, 0, 0, 0],
            [0x99, 0, 0, 0],
        );
        let err = Vmdk::open(&delta).expect_err("an orphan delta must be refused");
        assert!(err.to_string().contains("not next to it"), "{err}");
    }

    #[test]
    fn a_chain_whose_content_ids_do_not_link_is_refused() {
        let base = scratch("base.vmdk");
        let dir = base.parent().expect("a directory").to_path_buf();
        sparse_fixture(&base, &base_descriptor("base.vmdk"), [8, 0, 0, 0], [0x11, 0, 0, 0]);
        let delta = dir.join("delta.vmdk");
        sparse_fixture(
            &delta,
            &delta_descriptor("delta.vmdk", "base.vmdk", "aaaa0002", "deadbeef"),
            [8, 0, 0, 0],
            [0x99, 0, 0, 0],
        );
        let err = Vmdk::open(&delta).expect_err("a broken chain must be refused");
        let text = err.to_string();
        assert!(text.contains("chain is broken at"), "{text}");
        assert!(text.contains("deadbeef"), "the refusal must name the CID it needed: {text}");
        assert!(text.contains("delta.vmdk"), "and the link that broke: {text}");
    }

    #[test]
    fn a_parent_chain_that_loops_is_refused_rather_than_followed_forever() {
        let a = scratch("a.vmdk");
        let dir = a.parent().expect("a directory").to_path_buf();
        let b = dir.join("b.vmdk");
        sparse_fixture(
            &a,
            &delta_descriptor("a.vmdk", "b.vmdk", "c1", "c2"),
            [8, 0, 0, 0],
            [1, 0, 0, 0],
        );
        sparse_fixture(
            &b,
            &delta_descriptor("b.vmdk", "a.vmdk", "c2", "c1"),
            [8, 0, 0, 0],
            [2, 0, 0, 0],
        );
        let err = Vmdk::open(&a).expect_err("a loop must be refused");
        assert!(err.to_string().contains("loops back"), "{err}");
    }

    #[test]
    fn a_read_crossing_a_split_extent_boundary_is_served_from_both_files() {
        let s1 = scratch("split-s001.vmdk");
        let dir = s1.parent().expect("a directory").to_path_buf();
        let s2 = dir.join("split-s002.vmdk");
        sparse_fixture(&s1, "", [8, 16, 24, 32], [0xE1; 4]);
        sparse_fixture(&s2, "", [8, 16, 24, 32], [0xE2; 4]);
        let desc = dir.join("split.vmdk");
        std::fs::write(
            &desc,
            format!(
                "# Disk DescriptorFile\nversion=1\nCID=9c11f696\nparentCID=ffffffff\n\
                 createType=\"twoGbMaxExtentSparse\"\n\n\
                 RW {T_CAPACITY} SPARSE \"split-s001.vmdk\"\n\
                 RW {T_CAPACITY} SPARSE \"split-s002.vmdk\"\n"
            ),
        )
        .expect("writing the descriptor");

        let mut v = Vmdk::open(&desc).expect("opening a split disk");
        assert_eq!(v.info().create_type, "twoGbMaxExtentSparse");
        assert_eq!(v.info().extents, 2);
        assert_eq!(v.disk_size(), T_CAPACITY * SECTOR * 2);

        let seam = T_CAPACITY * SECTOR;
        let got = read_at(&mut v, seam - 16, 32);
        assert!(got[..16].iter().all(|b| *b == 0xE1), "the tail of extent 1");
        assert!(got[16..].iter().all(|b| *b == 0xE2), "the head of extent 2");
    }

    #[test]
    fn a_bare_split_extent_opens_as_a_single_extent_disk() {
        let s1 = scratch("bare-s001.vmdk");
        sparse_fixture(&s1, "", [8, 0, 0, 0], [0x77, 0, 0, 0]);
        let mut v = Vmdk::open(&s1).expect("opening a bare extent");
        assert_eq!(v.info().chain.len(), 1);
        assert!(read_at(&mut v, 0, 512).iter().all(|b| *b == 0x77));
    }

    fn header_with(mutate: impl FnOnce(&mut [u8; HEADER_LEN])) -> Result<SparseHeader> {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(&SPARSE_MAGIC);
        put32(&mut h, 0x04, 1);
        put32(&mut h, 0x08, FLAG_VALID_NEWLINE);
        put64(&mut h, 0x0C, T_CAPACITY);
        put64(&mut h, 0x14, T_GRAIN);
        put32(&mut h, 0x2C, T_GTE);
        put64(&mut h, 0x38, 3);
        h[0x49] = b'\n';
        h[0x4A] = b' ';
        h[0x4B] = b'\r';
        h[0x4C] = b'\n';
        mutate(&mut h);
        SparseHeader::parse(&h)
    }

    #[test]
    fn compressed_grains_are_refused_explicitly_rather_than_read_as_garbage() {
        let err = header_with(|h| h[0x4D] = 1).expect_err("compressAlgorithm 1 is deflate");
        assert!(err.to_string().contains("compressAlgorithm"), "{err}");

        let err = header_with(|h| put32(h, 0x08, FLAG_VALID_NEWLINE | FLAG_COMPRESSED))
            .expect_err("the compressed flag is refused");
        assert!(err.to_string().contains("compressed"), "{err}");

        let err = header_with(|h| put32(h, 0x08, FLAG_VALID_NEWLINE | FLAG_MARKERS))
            .expect_err("streamOptimized markers are refused");
        assert!(err.to_string().contains("markers"), "{err}");
    }

    #[test]
    fn a_mangled_end_of_line_canary_is_refused() {
        let err = header_with(|h| h[0x4B] = b'X').expect_err("a text-mode transfer is detectable");
        assert!(err.to_string().contains("end-of-line canary"), "{err}");
    }

    #[test]
    fn an_implausible_grain_size_is_refused() {
        assert!(header_with(|h| put64(h, 0x14, 0)).is_err(), "zero");
        assert!(header_with(|h| put64(h, 0x14, 3)).is_err(), "not a power of two");
        assert!(header_with(|h| put64(h, 0x14, 1 << 40)).is_err(), "absurd");
        assert!(header_with(|h| put32(h, 0x2C, 0)).is_err(), "zero entries per table");
        assert!(header_with(|h| put32(h, 0x2C, u32::MAX)).is_err(), "absurd table");
    }

    #[test]
    fn a_grain_directory_claiming_a_terabyte_is_refused_rather_than_allocated() {
        let header =
            header_with(|h| put64(h, 0x0C, u64::MAX / 2)).expect("the header itself parses");
        let err = header.gd_entries().expect_err("the directory must be refused");
        assert!(err.to_string().contains("will not allocate"), "{err}");
    }

    #[test]
    fn a_grain_pointing_past_the_end_of_the_file_is_refused_rather_than_seeked_to() {
        let path = scratch("evil.vmdk");
        sparse_fixture(&path, &base_descriptor("evil.vmdk"), [0xFFFF, 0, 0, 0], [0, 0, 0, 0]);
        let mut v = Vmdk::open(&path).expect("the header and directory are fine");
        v.seek(SeekFrom::Start(0)).expect("seeking");
        let err = v.read(&mut [0u8; 512]).expect_err("the grain is outside the file");
        assert!(err.to_string().contains("past the end"), "{err}");
    }

    #[test]
    fn a_grain_directory_outside_the_file_is_refused_at_open() {
        let path = scratch("evil2.vmdk");
        sparse_fixture(&path, &base_descriptor("evil2.vmdk"), [8, 0, 0, 0], [1, 0, 0, 0]);
        let mut raw = std::fs::read(&path).expect("reading the fixture");
        put64(&mut raw, 0x38, 1 << 40);
        put64(&mut raw, 0x30, 1 << 40);
        std::fs::write(&path, &raw).expect("rewriting");
        let err = Vmdk::open(&path).expect_err("must be refused");
        assert!(err.to_string().contains("past the end of a"), "{err}");
    }

    #[test]
    fn a_descriptor_naming_a_path_is_reduced_to_a_sibling() {
        let dir = Path::new("C:\\vms\\case");
        assert_eq!(resolve_sibling(dir, "base.vmdk"), dir.join("base.vmdk"));
        assert_eq!(resolve_sibling(dir, "..\\..\\Windows\\System32\\config\\SAM"), dir.join("SAM"));
        assert_eq!(resolve_sibling(dir, "/etc/shadow"), dir.join("shadow"));
    }

    #[test]
    fn a_file_that_is_not_a_vmdk_is_refused_and_not_claimed() {
        let path = scratch("nope.bin");
        std::fs::write(&path, vec![0u8; 2048]).expect("a fixture");
        assert!(!Vmdk::looks_like_one(&path));
        assert!(Vmdk::open(&path).is_err());

        let empty = scratch("empty.bin");
        std::fs::write(&empty, b"").expect("a fixture");
        assert!(!Vmdk::looks_like_one(&empty));
        assert!(Vmdk::open(&empty).is_err());
    }

    #[test]
    fn a_descriptor_that_is_not_utf8_still_parses_its_ascii_fields() {
        let mut raw = b"# Disk DescriptorFile\nversion=1\n# \xC0\xE1\xE2\nCID=abcd1234\n".to_vec();
        raw.extend_from_slice(b"parentCID=ffffffff\nRW 64 SPARSE \"x.vmdk\"\n");
        let d = parse_descriptor(&decode(&raw));
        assert_eq!(d.cid, "abcd1234");
        assert_eq!(d.extents.len(), 1);
    }

    #[test]
    fn the_handle_refuses_writes_rather_than_being_trusted_not_to() {
        let path = scratch("readonly.vmdk");
        sparse_fixture(&path, &base_descriptor("readonly.vmdk"), [8, 16, 0, 0], [0xAB, 0xCD, 0, 0]);
        let before = std::fs::read(&path).expect("reading the fixture");

        let mut handle = File::open(&path).expect("opening read-only");
        assert!(handle.write_all(b"x").is_err(), "a File::open handle must carry no write access");
        drop(handle);

        let _ = ReadOnlyFile::open(&path).expect("the reader's own handle opens");

        let mut v = Vmdk::open(&path).expect("opening");
        let mut sink = vec![0u8; (T_CAPACITY * SECTOR) as usize];
        let mut done = 0;
        while done < sink.len() {
            match v.read(&mut sink[done..]) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) => panic!("reading: {e}"),
            }
        }
        drop(v);

        let after = std::fs::read(&path).expect("re-reading the fixture");
        assert_eq!(before, after, "reading an image must not change a single byte of it");
    }

    #[test]
    fn repeated_reads_in_one_grain_table_cost_one_table_read_not_one_per_hop() {
        let path = scratch("cache.vmdk");
        sparse_fixture(&path, &base_descriptor("cache.vmdk"), [8, 16, 24, 32], [1, 2, 3, 4]);
        let mut v = Vmdk::open(&path).expect("opening");
        for i in 0..1000u64 {
            let at = (i * 97) % (T_CAPACITY * SECTOR - 512);
            read_at(&mut v, at, 512);
        }
        let cost = v.cache_cost();
        assert_eq!(cost.misses, 1, "one grain table covers this whole disk");
        assert!(cost.hits >= 999, "the rest were cached: {cost:?}");
        assert_eq!(cost.evictions, 0);
    }

    fn real_vm(name: &str) -> Option<PathBuf> {
        let dir = std::env::var("MM_VM_DIR").ok().map(PathBuf::from).unwrap_or_else(|| {
            PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default())
                .join("Documents")
                .join("Virtual Machines")
        });
        let path = dir.join(name);
        path.exists().then_some(path)
    }

    #[test]
    fn the_real_njrat_base_disk_reads_its_partition_table() {
        let Some(path) = real_vm("WIN11-LAB/WIN11-LAB.vmdk") else { return };
        let mut v = Vmdk::open(&path).expect("opening the real base disk");
        let info = v.info().clone();
        assert_eq!(info.create_type, "monolithicSparse");
        assert_eq!(info.capacity_bytes, 128_849_018_880, "120 GiB");
        assert_eq!(info.grain_bytes, 65_536);
        assert_eq!(info.extents, 1);
        assert_eq!(info.chain.len(), 1, "the base has no parent");
        assert_eq!(info.chain[0].cid, "62e01ed9");
        assert_eq!(info.chain[0].parent_cid, "ffffffff");

        let mbr = read_at(&mut v, 0, 512);
        assert_eq!(&mbr[510..512], &[0x55, 0xAA], "a real MBR");
        let boot = read_at(&mut v, 104_448 * SECTOR, 512);
        assert_eq!(&boot[3..11], b"NTFS    ", "a real NTFS boot sector");
    }

    #[test]
    fn the_real_snapshot_chain_links_and_serves_grains_from_the_right_link() {
        let Some(path) = real_vm("WIN11-LAB/WIN11-LAB-000005.vmdk") else { return };
        let mut v = Vmdk::open(&path).expect("opening the real chain");
        let chain = v.info().chain.clone();
        let link_of = |name: &str| {
            chain
                .iter()
                .position(|l| l.name == name)
                .unwrap_or_else(|| panic!("no {name} in the chain"))
        };

        assert!(chain.len() >= 6, "a chain of snapshots, not a lone disk: {}", chain.len());
        assert_eq!(chain[0].name, "WIN11-LAB-000005.vmdk", "the leaf is what was opened");
        let base = chain.len() - 1;
        assert_eq!(chain[base].name, "WIN11-LAB.vmdk");
        assert_eq!(chain[base].parent_cid, "ffffffff", "the chain terminates");
        for pair in chain.windows(2) {
            assert_eq!(pair[0].parent_cid, pair[1].cid, "every link must join");
        }

        let boot = read_at(&mut v, 104_448 * SECTOR, 512);
        assert_eq!(&boot[3..11], b"NTFS    ");
        assert_eq!(
            v.provenance(104_448 * SECTOR).expect("provenance"),
            Provenance::Stored {
                link: link_of("WIN11-LAB-000002.vmdk"),
                name: "WIN11-LAB-000002.vmdk".into(),
            }
        );
        assert_eq!(
            v.provenance(0).expect("provenance"),
            Provenance::Stored { link: base, name: "WIN11-LAB.vmdk".into() }
        );
        assert_ne!(link_of("WIN11-LAB-000002.vmdk"), 0, "not served from the leaf");
    }

    #[test]
    fn the_real_split_disk_reads_across_sixteen_extents() {
        let Some(path) = real_vm("SPLITDISK/SPLITDISK.vmdk") else { return };
        let mut v = Vmdk::open(&path).expect("opening the real split disk");
        let info = v.info().clone();
        assert_eq!(info.create_type, "twoGbMaxExtentSparse");
        assert_eq!(info.extents, 16);
        assert_eq!(info.capacity_bytes, 64_424_509_440, "60 GiB");
        let mbr = read_at(&mut v, 0, 512);
        assert_eq!(&mbr[510..512], &[0x55, 0xAA]);

        let seam = 8_323_072u64 * SECTOR;
        let straddle = read_at(&mut v, seam - 4096, 8192);
        assert_eq!(straddle.len(), 8192);
    }

    #[test]
    fn the_real_split_disk_with_a_snapshot_chain_opens() {
        let Some(path) = real_vm("Static Analyzer/Static Analyzer-000007.vmdk") else { return };
        let mut v = Vmdk::open(&path).expect("opening a split disk with a chain");
        let info = v.info().clone();
        assert_eq!(info.create_type, "twoGbMaxExtentSparse");
        assert_eq!(info.chain.len(), 2);
        assert_eq!(info.extents, 31, "and every extent name contains a space");
        let boot = read_at(&mut v, 104_448 * SECTOR, 512);
        assert_eq!(&boot[3..11], b"NTFS    ");
    }

    #[test]
    fn every_real_vmdk_on_this_machine_opens_or_is_refused_with_a_reason() {
        let Some(root) = real_vm(".") else { return };
        let mut opened = 0;
        for vm in std::fs::read_dir(&root).expect("listing VMs").flatten() {
            if !vm.path().is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(vm.path()).expect("listing a VM").flatten() {
                let path = entry.path();
                if path.extension().is_none_or(|e| e != "vmdk") {
                    continue;
                }
                if !Vmdk::looks_like_one(&path) {
                    continue;
                }
                match Vmdk::open(&path) {
                    Ok(mut v) => {
                        opened += 1;
                        assert!(v.disk_size() > 0);
                        let mut head = [0u8; 512];
                        let mut done = 0;
                        while done < head.len() {
                            match v.read(&mut head[done..]) {
                                Ok(0) => break,
                                Ok(n) => done += n,
                                Err(e) => panic!("reading {}: {e}", path.display()),
                            }
                        }
                    }
                    Err(e) => assert!(!e.to_string().is_empty(), "{}", path.display()),
                }
            }
        }
        assert!(opened > 100, "expected the machine's whole VMDK corpus, opened {opened}");
    }
}
