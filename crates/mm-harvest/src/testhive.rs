#![allow(dead_code)]

use std::collections::HashMap;

pub const NIL: u32 = u32::MAX;
pub const REG_SZ_T: u32 = 1;
pub const REG_EXPAND_SZ_T: u32 = 2;
pub const REG_BINARY_T: u32 = 3;
pub const REG_MULTI_SZ_T: u32 = 7;
pub const COMP: u16 = 0x0020;
pub const ROOT_FLAG: u16 = 0x0004;

pub struct Builder {
    pub bins: Vec<u8>,
    minor: u32,
    names: HashMap<u32, String>,
    children: Vec<(u32, Vec<u32>)>,
    bin_starts: Vec<usize>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    pub fn new() -> Self {
        let mut bins = vec![0u8; 32];
        bins[0..4].copy_from_slice(b"hbin");
        Builder { bins, minor: 5, names: HashMap::new(), children: Vec::new(), bin_starts: vec![0] }
    }

    pub fn bin_break(&mut self) {
        while !self.bins.len().is_multiple_of(4096) {
            self.bins.push(0);
        }
        let start = self.bins.len();
        self.bins.extend_from_slice(b"hbin");
        self.bins.extend_from_slice(&(start as u32).to_le_bytes());
        self.bins.extend_from_slice(&0u32.to_le_bytes());
        self.bins.extend_from_slice(&[0u8; 20]);
        self.bin_starts.push(start);
    }

    pub fn minor(mut self, minor: u32) -> Self {
        self.minor = minor;
        self
    }

    pub fn add(&mut self, content: &[u8], allocated: bool) -> u32 {
        let offset = self.bins.len() as u32;
        let size = (4 + content.len() + 7) & !7;
        let raw: i32 = if allocated { -(size as i32) } else { size as i32 };
        self.bins.extend_from_slice(&raw.to_le_bytes());
        self.bins.extend_from_slice(content);
        while !self.bins.len().is_multiple_of(8) {
            self.bins.push(0);
        }
        offset
    }

    pub fn key_bytes(&mut self, name: &[u8], flags: u16, allocated: bool) -> u32 {
        let mut c = Vec::new();
        c.extend_from_slice(b"nk");
        c.extend_from_slice(&flags.to_le_bytes());
        c.extend_from_slice(&0u64.to_le_bytes());
        c.extend_from_slice(&0u32.to_le_bytes());
        c.extend_from_slice(&NIL.to_le_bytes());
        c.extend_from_slice(&0u32.to_le_bytes());
        c.extend_from_slice(&0u32.to_le_bytes());
        c.extend_from_slice(&NIL.to_le_bytes());
        c.extend_from_slice(&NIL.to_le_bytes());
        c.extend_from_slice(&0u32.to_le_bytes());
        c.extend_from_slice(&NIL.to_le_bytes());
        c.extend_from_slice(&NIL.to_le_bytes());
        c.extend_from_slice(&NIL.to_le_bytes());
        c.extend_from_slice(&[0u8; 20]);
        c.extend_from_slice(&(name.len() as u16).to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(name);
        self.add(&c, allocated)
    }

    pub fn key(&mut self, name: &str, flags: u16, allocated: bool) -> u32 {
        let off = self.key_bytes(name.as_bytes(), flags | COMP, allocated);
        self.names.insert(off, name.to_string());
        off
    }

    pub fn set_last_written(&mut self, key: u32, filetime: u64) {
        let at = key as usize + 8;
        self.bins[at..at + 8].copy_from_slice(&filetime.to_le_bytes());
    }

    pub fn key_wide(&mut self, name: &str) -> u32 {
        let wide: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let off = self.key_bytes(&wide, 0, true);
        self.names.insert(off, name.to_string());
        off
    }

    pub fn link(&mut self, parent: u32, child: u32) {
        match self.children.iter_mut().find(|(p, _)| *p == parent) {
            Some((_, kids)) => kids.push(child),
            None => self.children.push((parent, vec![child])),
        }
    }

    pub fn child(&mut self, parent: u32, name: &str) -> u32 {
        if let Some((_, kids)) = self.children.iter().find(|(p, _)| *p == parent) {
            for k in kids {
                if self.names.get(k).is_some_and(|n| n.eq_ignore_ascii_case(name)) {
                    return *k;
                }
            }
        }
        let k = self.key(name, 0, true);
        self.link(parent, k);
        k
    }

    pub fn path(&mut self, parent: u32, names: &[&str]) -> u32 {
        let mut cur = parent;
        for name in names {
            cur = self.child(cur, name);
        }
        cur
    }

    pub fn value(&mut self, name: &str, kind: u32, data: &[u8], allocated: bool) -> u32 {
        self.value_inner(name, kind, data, allocated, allocated)
    }

    pub fn value_over_reused_data(&mut self, name: &str, kind: u32, data: &[u8]) -> u32 {
        self.value_inner(name, kind, data, false, true)
    }

    fn value_inner(
        &mut self,
        name: &str,
        kind: u32,
        data: &[u8],
        allocated: bool,
        data_allocated: bool,
    ) -> u32 {
        let (size_field, offset_field) = if data.is_empty() {
            (0u32, NIL)
        } else if data.len() <= 4 {
            let mut b = [0u8; 4];
            b[..data.len()].copy_from_slice(data);
            (0x8000_0000u32 | data.len() as u32, u32::from_le_bytes(b))
        } else {
            (data.len() as u32, self.add(data, data_allocated))
        };
        let mut c = Vec::new();
        c.extend_from_slice(b"vk");
        c.extend_from_slice(&(name.len() as u16).to_le_bytes());
        c.extend_from_slice(&size_field.to_le_bytes());
        c.extend_from_slice(&offset_field.to_le_bytes());
        c.extend_from_slice(&kind.to_le_bytes());
        c.extend_from_slice(&1u16.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(name.as_bytes());
        self.add(&c, allocated)
    }

    pub fn big_value(&mut self, name: &str, kind: u32, data: &[u8]) -> u32 {
        let mut segments = Vec::new();
        for chunk in data.chunks(16344) {
            segments.push(self.add(chunk, true));
        }
        let mut list = Vec::new();
        for o in &segments {
            list.extend_from_slice(&o.to_le_bytes());
        }
        let list_off = self.add(&list, true);
        let mut db = Vec::new();
        db.extend_from_slice(b"db");
        db.extend_from_slice(&(segments.len() as u16).to_le_bytes());
        db.extend_from_slice(&list_off.to_le_bytes());
        let db_off = self.add(&db, true);

        let mut c = Vec::new();
        c.extend_from_slice(b"vk");
        c.extend_from_slice(&(name.len() as u16).to_le_bytes());
        c.extend_from_slice(&(data.len() as u32).to_le_bytes());
        c.extend_from_slice(&db_off.to_le_bytes());
        c.extend_from_slice(&kind.to_le_bytes());
        c.extend_from_slice(&1u16.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(name.as_bytes());
        self.add(&c, true)
    }

    pub fn value_list(&mut self, values: &[u32], allocated: bool) -> u32 {
        let mut c = Vec::new();
        for v in values {
            c.extend_from_slice(&v.to_le_bytes());
        }
        self.add(&c, allocated)
    }

    pub fn hash_leaf(&mut self, keys: &[u32], allocated: bool) -> u32 {
        let mut c = Vec::new();
        c.extend_from_slice(b"lh");
        c.extend_from_slice(&(keys.len() as u16).to_le_bytes());
        for k in keys {
            c.extend_from_slice(&k.to_le_bytes());
            c.extend_from_slice(&0u32.to_le_bytes());
        }
        self.add(&c, allocated)
    }

    pub fn index_leaf(&mut self, keys: &[u32], allocated: bool) -> u32 {
        let mut c = Vec::new();
        c.extend_from_slice(b"li");
        c.extend_from_slice(&(keys.len() as u16).to_le_bytes());
        for k in keys {
            c.extend_from_slice(&k.to_le_bytes());
        }
        self.add(&c, allocated)
    }

    pub fn index_root(&mut self, lists: &[u32], allocated: bool) -> u32 {
        let mut c = Vec::new();
        c.extend_from_slice(b"ri");
        c.extend_from_slice(&(lists.len() as u16).to_le_bytes());
        for l in lists {
            c.extend_from_slice(&l.to_le_bytes());
        }
        self.add(&c, allocated)
    }

    pub fn set_u32(&mut self, key: u32, field: usize, value: u32) {
        let at = key as usize + 4 + field;
        self.bins[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn set_parent(&mut self, key: u32, parent: u32) {
        self.set_u32(key, 16, parent);
    }

    pub fn set_subkeys(&mut self, key: u32, list: u32, count: u32) {
        self.set_u32(key, 20, count);
        self.set_u32(key, 28, list);
    }

    pub fn set_values(&mut self, key: u32, list: u32, count: u32) {
        self.set_u32(key, 36, count);
        self.set_u32(key, 40, list);
    }

    pub fn finish(mut self, root: u32) -> Vec<u8> {
        let links = std::mem::take(&mut self.children);
        for (parent, kids) in links {
            let list = self.hash_leaf(&kids, true);
            self.set_subkeys(parent, list, kids.len() as u32);
            for k in &kids {
                self.set_parent(*k, parent);
            }
        }
        while !self.bins.len().is_multiple_of(4096) {
            self.bins.push(0);
        }
        let bins_len = self.bins.len() as u32;
        for (i, start) in self.bin_starts.clone().iter().enumerate() {
            let end = self.bin_starts.get(i + 1).copied().unwrap_or(self.bins.len());
            self.bins[start + 4..start + 8].copy_from_slice(&(*start as u32).to_le_bytes());
            self.bins[start + 8..start + 12].copy_from_slice(&((end - start) as u32).to_le_bytes());
        }

        let mut out = vec![0u8; 4096];
        out[0..4].copy_from_slice(b"regf");
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[24..28].copy_from_slice(&self.minor.to_le_bytes());
        out[36..40].copy_from_slice(&root.to_le_bytes());
        out[40..44].copy_from_slice(&bins_len.to_le_bytes());
        out.extend_from_slice(&self.bins);
        out
    }
}

pub fn utf16(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

pub fn utf16_multi(parts: &[&str]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend(p.encode_utf16().flat_map(|u| u.to_le_bytes()));
        v.extend_from_slice(&[0, 0]);
    }
    v.extend_from_slice(&[0, 0]);
    v
}
