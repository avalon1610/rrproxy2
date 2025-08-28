//! use fake name here, decrease request fingerprint
//!
pub const CHUNK_INDEX_HEADER: &str = "X-Fetch-Id";
pub const TRANSACTION_ID_HEADER: &str = "X-Request-Id";
/// this header should be encrypted, process is
/// 1. combine: <original method>+<original_version>+<original url> (use plus(+) sign to separate)
/// 2. encrypt the combined string
/// 3. encoded using base64
pub const ORIGINAL_URL_HEADER: &str = "X-Referer";
pub const TOTAL_CHUNKS_HEADER: &str = "X-Robots-Tag";
