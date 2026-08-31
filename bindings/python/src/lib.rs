use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyNone};

use mm_core::NormalizedPath;
use mm_env::{find_ntfs_partitions, open_partition, ImageVolume, Partition};
use mm_harvest::{
    amcache, defender_log, pe, persistence, prefetch, recycle_bin, shimcache, tasks, HiveSource,
};

fn to_python<'py>(py: Python<'py>, value: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        serde_json::Value::Null => PyNone::get(py).to_owned().into_any(),
        serde_json::Value::Bool(b) => (*b).into_pyobject(py)?.to_owned().into_any(),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py)?.into_any()
            } else if let Some(u) = n.as_u64() {
                u.into_pyobject(py)?.into_any()
            } else {
                n.as_f64().unwrap_or(f64::NAN).into_pyobject(py)?.into_any()
            }
        }
        serde_json::Value::String(s) => s.into_pyobject(py)?.into_any(),
        serde_json::Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(to_python(py, item)?)?;
            }
            list.into_any()
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, item) in map {
                dict.set_item(key, to_python(py, item)?)?;
            }
            dict.into_any()
        }
    })
}

fn observations<'py, T: serde::Serialize>(
    py: Python<'py>,
    value: &T,
) -> PyResult<Bound<'py, PyAny>> {
    let json = serde_json::to_value(value)
        .map_err(|e| PyValueError::new_err(format!("serialising observations: {e}")))?;
    to_python(py, &json)
}

fn hive_source(source: &str) -> PyResult<HiveSource> {
    let (kind, user) = match source.split_once(':') {
        Some((kind, user)) => (kind, Some(user)),
        None => (source, None),
    };
    match (kind.to_ascii_lowercase().as_str(), user) {
        ("software", None) => Ok(HiveSource::Software),
        ("system", None) => Ok(HiveSource::System),
        ("ntuser", Some(user)) if !user.is_empty() => {
            Ok(HiveSource::NtUser { user: user.to_string() })
        }
        ("usrclass", Some(user)) if !user.is_empty() => {
            Ok(HiveSource::UsrClass { user: user.to_string() })
        }
        _ => Err(PyValueError::new_err(
            "source must be one of: software, system, ntuser:<user>, usrclass:<user>",
        )),
    }
}

fn normalized(path: &str) -> PyResult<NormalizedPath> {
    NormalizedPath::parse(path)
        .ok_or_else(|| PyValueError::new_err(format!("not a usable Windows path: {path}")))
}

fn to_py(e: mm_core::Error) -> PyErr {
    PyOSError::new_err(e.to_string())
}

/// Parse an Amcache.hve hive into a list of observation dicts (the shape report.json uses).
#[pyfunction]
fn parse_amcache<'py>(py: Python<'py>, hive: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let found = py.detach(|| amcache::harvest(hive));
    observations(py, &found)
}

/// Parse the ShimCache (AppCompatCache) out of a SYSTEM hive.
#[pyfunction]
fn parse_shimcache<'py>(py: Python<'py>, system_hive: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let found = py.detach(|| shimcache::harvest(system_hive));
    observations(py, &found)
}

/// Parse one Prefetch file; file_name is its name on disk, e.g. "CALC.EXE-3FBEF7FD.pf".
#[pyfunction]
fn parse_prefetch<'py>(
    py: Python<'py>,
    bytes: &[u8],
    file_name: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let found = py.detach(|| prefetch::harvest(bytes, file_name));
    observations(py, &found)
}

/// Parse one scheduled-task XML definition; task_path is its path under \Windows\System32\Tasks.
#[pyfunction]
fn parse_tasks<'py>(py: Python<'py>, xml: &[u8], task_path: &str) -> PyResult<Bound<'py, PyAny>> {
    let found = py.detach(|| tasks::harvest(xml, task_path));
    observations(py, &found)
}

/// Parse the Microsoft-Windows-Windows Defender/Operational event log (.evtx).
#[pyfunction]
fn parse_defender_log<'py>(py: Python<'py>, bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let found = py.detach(|| defender_log::harvest(bytes));
    observations(py, &found)
}

/// Parse persistence locations out of a registry hive; source is "software", "system", "ntuser:<user>" or "usrclass:<user>".
#[pyfunction]
fn parse_persistence<'py>(
    py: Python<'py>,
    hive: &[u8],
    source: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let source = hive_source(source)?;
    let found = py.detach(|| persistence::harvest(hive, &source));
    observations(py, &found)
}

/// Parse one $Recycle.Bin $I record; info_name is the $I file's own name.
#[pyfunction]
fn parse_recycle_bin<'py>(
    py: Python<'py>,
    info_name: &str,
    bytes: &[u8],
) -> PyResult<Bound<'py, PyAny>> {
    let found = py.detach(|| recycle_bin::harvest(info_name, bytes));
    observations(py, &found)
}

/// Analyze a PE image as the triage does: packing, structural anomalies, Rich header, version resource.
#[pyfunction]
fn analyze_pe<'py>(py: Python<'py>, bytes: &[u8], path: &str) -> PyResult<Bound<'py, PyAny>> {
    let path = normalized(path)?;
    let found = py.detach(|| pe::harvest(bytes, &path));
    observations(py, &found)
}

/// pefile-compatible imphash (frozen ws2_32/oleaut32 ordinal tables), or None when pefile would report none.
#[pyfunction]
fn imphash(py: Python<'_>, bytes: &[u8]) -> Option<String> {
    py.detach(|| mm_harvest::imphash::imphash(bytes))
}

/// The "dll.function" strings the imphash is taken over, in order, or None when there is no import directory.
#[pyfunction]
fn imports(py: Python<'_>, bytes: &[u8]) -> Option<Vec<String>> {
    py.detach(|| mm_harvest::imphash::import_strings(bytes))
}

/// The Rich header: {"hash", "checksum_valid", "dans_decoded", "entries": [{"product_id", "build", "count"}]}, or None.
#[pyfunction]
fn rich_header<'py>(py: Python<'py>, bytes: &[u8]) -> PyResult<Option<Bound<'py, PyDict>>> {
    let Some(rich) = py.detach(|| mm_harvest::imphash::rich_header(bytes)) else { return Ok(None) };
    let dict = PyDict::new(py);
    dict.set_item("hash", rich.hash)?;
    dict.set_item("checksum_valid", rich.checksum_valid)?;
    dict.set_item("dans_decoded", rich.dans_decoded)?;
    let entries = PyList::empty(py);
    for entry in &rich.entries {
        let row = PyDict::new(py);
        row.set_item("product_id", entry.product_id)?;
        row.set_item("build", entry.build)?;
        row.set_item("count", entry.count)?;
        entries.append(row)?;
    }
    dict.set_item("entries", entries)?;
    Ok(Some(dict))
}

/// An NTFS volume inside a disk image (dd, VDI, VMDK with snapshots), read by malmathic's own parser; nothing is mounted.
#[pyclass(unsendable)]
struct Image {
    volume: ImageVolume,
    #[pyo3(get)]
    offset: u64,
    #[pyo3(get)]
    partitions: Vec<u64>,
}

#[pymethods]
impl Image {
    /// Open the image and choose its Windows partition, or the first NTFS partition that opens.
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        let disk = std::path::Path::new(path);
        let found = find_ntfs_partitions(disk).map_err(to_py)?;
        if found.is_empty() {
            return Err(PyOSError::new_err(format!("no NTFS partition in {path}")));
        }
        let partitions = found.iter().map(|p| p.offset).collect();
        let mut chosen: Option<(Partition, ImageVolume)> = None;
        for partition in &found {
            if let Ok(volume) = open_partition(disk, *partition) {
                let windows = volume.is_windows_install();
                if chosen.is_none() || windows {
                    chosen = Some((*partition, volume));
                    if windows {
                        break;
                    }
                }
            }
        }
        let (partition, volume) = chosen.ok_or_else(|| {
            PyOSError::new_err(format!("no NTFS partition in {path} could be opened"))
        })?;
        Ok(Image { volume, offset: partition.offset, partitions })
    }

    /// Whether the chosen partition holds a Windows installation.
    fn is_windows(&self) -> bool {
        self.volume.is_windows_install()
    }

    /// The NTFS volume serial number as 16 hex digits.
    fn serial(&self) -> String {
        format!("{:016x}", self.volume.serial())
    }

    /// Whether a volume-relative path such as "\Windows\System32" resolves.
    fn exists(&self, path: &str) -> bool {
        self.volume.exists(path)
    }

    /// Read a file's bytes; max_bytes caps the read so a hostile record cannot demand the whole image.
    #[pyo3(signature = (path, max_bytes=None))]
    fn read_file<'py>(
        &self,
        py: Python<'py>,
        path: &str,
        max_bytes: Option<usize>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = match max_bytes {
            Some(cap) => self.volume.read_capped(path, cap),
            None => self.volume.read(path),
        }
        .map_err(to_py)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// List a directory as [{"name": str, "record": int}].
    fn list_dir<'py>(&self, py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for entry in self.volume.list_directory_entries_checked(path).map_err(to_py)? {
            let dict = PyDict::new(py);
            dict.set_item("name", entry.name)?;
            dict.set_item("record", entry.record)?;
            list.append(dict)?;
        }
        Ok(list)
    }

    fn __repr__(&self) -> String {
        format!("Image(offset={}, windows={})", self.offset, self.volume.is_windows_install())
    }
}

#[pymodule]
fn pymalmathic(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(parse_amcache, m)?)?;
    m.add_function(wrap_pyfunction!(parse_shimcache, m)?)?;
    m.add_function(wrap_pyfunction!(parse_prefetch, m)?)?;
    m.add_function(wrap_pyfunction!(parse_tasks, m)?)?;
    m.add_function(wrap_pyfunction!(parse_defender_log, m)?)?;
    m.add_function(wrap_pyfunction!(parse_persistence, m)?)?;
    m.add_function(wrap_pyfunction!(parse_recycle_bin, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_pe, m)?)?;
    m.add_function(wrap_pyfunction!(imphash, m)?)?;
    m.add_function(wrap_pyfunction!(imports, m)?)?;
    m.add_function(wrap_pyfunction!(rich_header, m)?)?;
    m.add_class::<Image>()?;
    Ok(())
}
