//! Offline IP → region lookup against an `ip2region` xdb file, used by the
//! listener's optional region allowlist (checked at accept time).
//!
//! The xdb v2/v3 layout (little-endian throughout):
//!
//! ```text
//! [0..256)                     header
//!   u16 version | u16 index_policy | u32 created_at
//!   u32 start_index_ptr | u32 end_index_ptr
//!   u16 ip_version | u16 runtime_ptr_bytes
//! [256..256+256*256*8)         vector index: (start_ptr, end_ptr) per /16 block
//! ...                          region data (referenced by absolute offsets)
//! [start_index_ptr..)          segment index, 14 bytes per entry:
//!   u32 start_ip | u32 end_ip | u16 data_len | u32 data_ptr
//! ```
//!
//! Lookups use positioned reads, so the 11 MB database is never held in
//! memory — only the 512 KiB vector index is cached, keeping the resident
//! footprint small on a process that must not grow.

use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;

const HEADER_LEN: usize = 256;
const VECTOR_COLS: usize = 256;
const VECTOR_SIZE: usize = 8;
const VECTOR_INDEX_LEN: usize = 256 * 256 * 8;
const SEGMENT_SIZE: usize = 14;

/// Positioned read that does not move the file cursor (lock-free, so parallel
/// lookups do not serialize on the handle).
#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        done += n;
    }
    Ok(())
}

/// An opened ip2region xdb (IPv4).
pub(crate) struct GeoDb {
    file: File,
    vector_index: Vec<u8>,
}

impl GeoDb {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("cannot open geo database {}", path.display()))?;

        let mut header = [0u8; HEADER_LEN];
        read_exact_at(&file, &mut header, 0)
            .with_context(|| format!("cannot read geo database header {}", path.display()))?;

        let version = u16::from_le_bytes([header[0], header[1]]);
        let index_policy = u16::from_le_bytes([header[2], header[3]]);
        let ip_version = u16::from_le_bytes([header[16], header[17]]);

        if version < 2 {
            bail!(
                "geo database {} has unsupported version {version} (need the xdb v2/v3 format)",
                path.display()
            );
        }
        if index_policy != 1 {
            bail!(
                "geo database {} uses index policy {index_policy}; only the vector-index \
                 database (1) is supported",
                path.display()
            );
        }
        if ip_version != 4 {
            bail!(
                "geo database {} holds IPv{ip_version} data; use the IPv4 database \
                 (ip2region_v4.xdb)",
                path.display()
            );
        }

        let mut vector_index = vec![0u8; VECTOR_INDEX_LEN];
        read_exact_at(&file, &mut vector_index, HEADER_LEN as u64)
            .with_context(|| format!("cannot read geo database index {}", path.display()))?;

        Ok(Self { file, vector_index })
    }

    /// Region string for `ip`, e.g. `中国|浙江省|杭州市|阿里|CN`, or `None` when
    /// the database has no segment covering the address.
    pub(crate) fn lookup(&self, ip: Ipv4Addr) -> Result<Option<String>> {
        let octets = ip.octets();
        let idx = (octets[0] as usize * VECTOR_COLS + octets[1] as usize) * VECTOR_SIZE;
        let start = u32::from_le_bytes(self.vector_index[idx..idx + 4].try_into().unwrap()) as u64;
        let end =
            u32::from_le_bytes(self.vector_index[idx + 4..idx + 8].try_into().unwrap()) as u64;
        // Zero pointers mean the source data has no segment for this block.
        if start == 0 || end == 0 {
            return Ok(None);
        }

        // Addresses in the index are little-endian u32; compare as such.
        let key = u32::from_be_bytes(octets);
        let mut lo: i64 = 0;
        let mut hi: i64 = ((end - start) / SEGMENT_SIZE as u64) as i64;
        let mut buf = [0u8; SEGMENT_SIZE];
        while lo <= hi {
            let mid = (lo + hi) / 2;
            read_exact_at(
                &self.file,
                &mut buf,
                start + mid as u64 * SEGMENT_SIZE as u64,
            )?;
            let seg_start = u32::from_le_bytes(buf[0..4].try_into().unwrap());
            let seg_end = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            if key < seg_start {
                hi = mid - 1;
            } else if key > seg_end {
                lo = mid + 1;
            } else {
                let data_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
                let data_ptr = u32::from_le_bytes(buf[10..14].try_into().unwrap()) as u64;
                if data_len == 0 {
                    return Ok(None);
                }
                let mut data = vec![0u8; data_len];
                read_exact_at(&self.file, &mut data, data_ptr)?;
                return Ok(Some(
                    String::from_utf8(data)
                        .context("geo database returned non-UTF-8 region data")?,
                ));
            }
        }
        Ok(None)
    }
}

/// One allowlist rule. Fields are `|`-separated and trailing ones may be
/// omitted: `country[|province[|city[|isp]]]`. An empty field or `*` matches
/// anything; the country field matches either the ISO code (`CN`) or the
/// country name, and province/city/isp match as case-insensitive substrings so
/// `浙江` matches `浙江省`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegionRule {
    country: String,
    province: String,
    city: String,
    isp: String,
}

impl RegionRule {
    fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty region rule");
        }
        let mut parts = spec.split('|').map(|s| s.trim().to_string());
        let rule = Self {
            country: parts.next().unwrap_or_default(),
            province: parts.next().unwrap_or_default(),
            city: parts.next().unwrap_or_default(),
            isp: parts.next().unwrap_or_default(),
        };
        if parts.next().is_some() {
            bail!("region rule {spec:?} has too many fields (expected country|province|city|isp)");
        }
        Ok(rule)
    }

    fn matches(&self, record: &str) -> bool {
        let fields: Vec<&str> = record.split('|').collect();
        let country_name = fields.first().copied().unwrap_or("");
        let province = fields.get(1).copied().unwrap_or("");
        let city = fields.get(2).copied().unwrap_or("");
        let isp = fields.get(3).copied().unwrap_or("");
        let iso = fields.get(4).copied().unwrap_or("");

        (field_matches(&self.country, country_name) || field_matches(&self.country, iso))
            && field_matches(&self.province, province)
            && field_matches(&self.city, city)
            && field_matches(&self.isp, isp)
    }
}

/// An empty or `*` field matches anything; otherwise a case-insensitive
/// substring match (`浙江` matches `浙江省`).
fn field_matches(spec: &str, value: &str) -> bool {
    if spec.is_empty() || spec == "*" {
        return true;
    }
    value.to_lowercase().contains(&spec.to_lowercase())
}

/// The parsed `--allow-region` list.
#[derive(Debug, Clone)]
pub(crate) struct RegionFilter {
    rules: Vec<RegionRule>,
}

impl RegionFilter {
    pub(crate) fn parse(specs: &[String]) -> Result<Self> {
        let mut rules = Vec::new();
        for spec in specs {
            for part in spec.split(',') {
                if part.trim().is_empty() {
                    continue;
                }
                rules.push(RegionRule::parse(part)?);
            }
        }
        if rules.is_empty() {
            bail!("--allow-region was given but contains no usable rules");
        }
        Ok(Self { rules })
    }

    pub(crate) fn matches(&self, record: &str) -> bool {
        self.rules.iter().any(|r| r.matches(record))
    }
}

/// Region-based admission control for the listener: decided at `accept()`
/// time from the TCP peer address alone. No request data is consulted —
/// forwarding headers like `CF-Connecting-IP` are deliberately ignored, so a
/// client cannot smuggle its region in through headers.
pub(crate) struct GeoCheck {
    db: GeoDb,
    filter: RegionFilter,
}

impl GeoCheck {
    pub(crate) fn new(db_path: &Path, rules: &[String]) -> Result<Self> {
        Ok(Self {
            db: GeoDb::open(db_path)?,
            filter: RegionFilter::parse(rules)?,
        })
    }

    /// `Ok(true)` admits the connection; `Ok(false)` denies it. Lookup
    /// failures are returned to the caller, which fails closed.
    pub(crate) fn allows(&self, ip: IpAddr) -> Result<bool> {
        // The database is IPv4-only: an IPv6 client cannot be judged, and an
        // allowlist denies what it cannot verify.
        let IpAddr::V4(ip) = ip else {
            return Ok(false);
        };
        match self.db.lookup(ip)? {
            Some(record) => Ok(self.filter.matches(&record)),
            None => Ok(false),
        }
    }
}

/// Convenience wrapper stored by the remote proxy.
pub(crate) type SharedGeoCheck = Arc<GeoCheck>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn filter(specs: &[&str]) -> RegionFilter {
        let specs: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
        RegionFilter::parse(&specs).expect("filter should parse")
    }

    #[test]
    fn matches_hangzhou_rule() {
        let f = filter(&["中国|浙江省|杭州市"]);
        assert!(f.matches("中国|浙江省|杭州市|阿里|CN"));
        assert!(!f.matches("中国|北京市|北京市|电信|CN"));
        assert!(!f.matches("United States|California|0|Google LLC|US"));
    }

    #[test]
    fn province_substring_tolerates_missing_suffix() {
        // `浙江` must match the database's `浙江省`.
        let f = filter(&["中国|浙江|杭州"]);
        assert!(f.matches("中国|浙江省|杭州市|阿里|CN"));
    }

    #[test]
    fn country_rule_accepts_iso_code() {
        let f = filter(&["CN"]);
        assert!(f.matches("中国|北京市|北京市|电信|CN"));
        assert!(f.matches("中国|浙江省|杭州市|阿里|CN"));
        assert!(!f.matches("United States|California|0|Google LLC|US"));
    }

    #[test]
    fn country_rule_accepts_country_name() {
        let f = filter(&["United States"]);
        assert!(f.matches("United States|California|0|Google LLC|US"));
        assert!(!f.matches("中国|浙江省|杭州市|阿里|CN"));
    }

    #[test]
    fn wildcard_fields_match_anything() {
        let f = filter(&["CN|*|杭州市"]);
        assert!(f.matches("中国|浙江省|杭州市|阿里|CN"));
        assert!(!f.matches("中国|浙江省|宁波市|阿里|CN"));
    }

    #[test]
    fn multiple_rules_are_ored() {
        let f = filter(&["中国|浙江省|杭州市,CN|北京市"]);
        assert!(f.matches("中国|浙江省|杭州市|阿里|CN"));
        assert!(f.matches("中国|北京市|北京市|电信|CN"));
        assert!(!f.matches("中国|江苏省|南京市|0|CN"));
    }

    #[test]
    fn unknown_city_zero_does_not_match_city_rule() {
        // The database writes `0` for an unknown city; a city rule must not
        // silently admit it.
        let f = filter(&["CN|浙江省|杭州市"]);
        assert!(!f.matches("中国|浙江省|0|电信|CN"));
    }

    #[test]
    fn empty_rule_list_is_rejected() {
        let specs = vec!["".to_string(), " , ".to_string()];
        assert!(RegionFilter::parse(&specs).is_err());
    }

    #[test]
    fn too_many_fields_is_rejected() {
        let specs = vec!["CN|浙江省|杭州市|阿里|extra".to_string()];
        assert!(RegionFilter::parse(&specs).is_err());
    }

    /// Builds a minimal valid xdb v3 database containing two segments and
    /// returns its path. Layout mirrors the module docs: 256-byte header,
    /// 512 KiB vector index, region data, then 14-byte segment index entries.
    fn write_synthetic_xdb(dir: &Path) -> PathBuf {
        use std::io::Write;

        let path = dir.join("synthetic.xdb");
        let mut f = std::fs::File::create(&path).unwrap();

        // Segments: 10.0.0.0-10.0.0.255 -> Hangzhou, 10.1.0.0-10.1.0.255 -> US.
        // All little-endian u32 addresses, like the real database.
        let segments: [(u32, u32, &str); 2] = [
            (
                u32::from_be_bytes([10, 0, 0, 0]),
                u32::from_be_bytes([10, 0, 0, 255]),
                "中国|浙江省|杭州市|电信|CN",
            ),
            (
                u32::from_be_bytes([10, 1, 0, 0]),
                u32::from_be_bytes([10, 1, 0, 255]),
                "United States|California|0|Google LLC|US",
            ),
        ];

        let header_len = 256usize;
        let vector_len = 256 * 256 * 8usize;
        // Data follows the header + vector index; each record is length-prefixed.
        let mut data: Vec<u8> = Vec::new();
        let mut records: Vec<(usize, usize)> = Vec::new(); // (offset, len) per segment
        for (_, _, region) in &segments {
            let offset = data.len();
            data.extend_from_slice(region.as_bytes());
            records.push((offset, region.len()));
        }
        let data_base = header_len + vector_len;

        let index_start: usize = data_base + data.len();
        let mut index: Vec<u8> = Vec::new();
        for ((start, end, _), (off, len)) in segments.iter().zip(&records) {
            index.extend_from_slice(&start.to_le_bytes());
            index.extend_from_slice(&end.to_le_bytes());
            index.extend_from_slice(&(*len as u16).to_le_bytes());
            index.extend_from_slice(&(data_base as u32 + *off as u32).to_le_bytes());
        }

        // Header: version 3, policy 1 (vector index), created_at 0,
        // start/end index pointers, ip_version 4.
        let mut header = vec![0u8; header_len];
        header[0..2].copy_from_slice(&3u16.to_le_bytes());
        header[2..4].copy_from_slice(&1u16.to_le_bytes());
        header[8..12].copy_from_slice(&(index_start as u32).to_le_bytes());
        header[12..16].copy_from_slice(&((index_start + index.len()) as u32).to_le_bytes());
        header[16..18].copy_from_slice(&4u16.to_le_bytes());

        f.write_all(&header).unwrap();
        // Vector index: point the /16 block of 10.0.x.x (first byte 10, second
        // byte 0) at the first segment, 10.1.x.x at the second; everything
        // else stays zero (no data for that block).
        let mut vector = vec![0u8; vector_len];
        let idx = |first: u8, second: u8| (first as usize * 256 + second as usize) * 8;
        vector[idx(10, 0)..idx(10, 0) + 4].copy_from_slice(&(index_start as u32).to_le_bytes());
        vector[idx(10, 0) + 4..idx(10, 0) + 8]
            .copy_from_slice(&(index_start as u32 + 14).to_le_bytes());
        vector[idx(10, 1)..idx(10, 1) + 4]
            .copy_from_slice(&(index_start as u32 + 14).to_le_bytes());
        vector[idx(10, 1) + 4..idx(10, 1) + 8]
            .copy_from_slice(&(index_start as u32 + 2 * 14).to_le_bytes());
        f.write_all(&vector).unwrap();
        f.write_all(&data).unwrap();
        f.write_all(&index).unwrap();
        f.flush().unwrap();
        path
    }

    #[test]
    fn geocheck_admits_matching_and_deny_blocks_others() {
        let dir = std::env::temp_dir().join(format!("rrproxy2-geo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = write_synthetic_xdb(&dir);
        let check = GeoCheck::new(&db, &["CN|浙江省|杭州市".to_string()]).unwrap();

        // Hangzhou segment -> admitted.
        assert!(check.allows("10.0.0.5".parse().unwrap()).unwrap());
        // US segment -> dropped.
        assert!(!check.allows("10.1.0.9".parse().unwrap()).unwrap());
        // Address outside any segment (vector index zero block) -> dropped.
        assert!(!check.allows("10.2.0.1".parse().unwrap()).unwrap());
        // IPv6 cannot be judged by an IPv4 database -> dropped (fail closed).
        assert!(!check.allows("2001:db8::1".parse().unwrap()).unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reads_and_rejects_a_missing_database() {
        let err = match GeoDb::open(Path::new("/nonexistent/ip2region_v4.xdb")) {
            Ok(_) => panic!("opening a missing database should fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("cannot open geo database"));
    }

    #[test]
    fn lookup_reads_real_database_when_provided() {
        // Opt-in: point IP2REGION_XDB at a real ip2region_v4.xdb to exercise
        // the reader against real data.
        let Ok(path) = std::env::var("IP2REGION_XDB") else {
            return;
        };
        let db = GeoDb::open(Path::new(&path)).expect("database should open");
        let record = db
            .lookup("47.96.1.1".parse().unwrap())
            .expect("lookup should succeed")
            .expect("Aliyun Hangzhou address should be present");
        assert!(record.contains("杭州"), "unexpected record: {record}");
        // A Cloudflare edge address resolves to the PoP, not the visitor.
        let cf = db.lookup("172.71.98.207".parse().unwrap()).unwrap();
        assert!(cf.is_none_or(|r| !r.contains("杭州")));
    }
}
