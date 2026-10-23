//! Google Health API v4beta client (read-only, Fitbit's successor): data-type catalog,
//! filter and request builders and output slimmers, all pure and unit-tested.

use http::StatusCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::http::{
    InvalidPathSegment, MAX_API_RESPONSE_BYTES, MAX_DOWNLOAD_BYTES, ReadBodyError,
    read_body_capped, seg,
};

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Health returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("could not parse Health response: {0}")]
    Parse(serde_json::Error),
    #[error("invalid id: {0}")]
    InvalidId(String),
    #[error("{0}")]
    Invalid(String),
    #[error("response body exceeds the {cap}-byte cap (at least {actual} bytes)")]
    TooLarge { cap: usize, actual: usize },
}

impl From<InvalidPathSegment> for HealthError {
    fn from(e: InvalidPathSegment) -> Self {
        HealthError::InvalidId(e.0)
    }
}

impl From<ReadBodyError> for HealthError {
    fn from(e: ReadBodyError) -> Self {
        match e {
            ReadBodyError::Http(e) => HealthError::Http(e),
            ReadBodyError::TooLarge { cap, actual } => HealthError::TooLarge { cap, actual },
        }
    }
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, HealthError> {
    Err(HealthError::Invalid(msg.into()))
}

const BASE: &str = "https://health.googleapis.com/v4beta";
/// Default `pageSize` for `health_list_data_points`.
pub const DEFAULT_PAGE_SIZE: u32 = 200;

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Interval,
    Sample,
    Daily,
    Session,
    Sleep,
    Ecg,
    Food,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Interval => "interval",
            Kind::Sample => "sample",
            Kind::Daily => "daily",
            Kind::Session => "session",
            Kind::Sleep => "sleep",
            Kind::Ecg => "ecg",
            Kind::Food => "food",
        }
    }

    fn filter_hint(self) -> &'static str {
        match self {
            Kind::Interval => {
                "start/end filter on the interval start time; local bounds (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS) or absolute RFC3339 with Z or an offset"
            }
            Kind::Sample => {
                "start/end filter on the sample time; local bounds (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS) or absolute RFC3339 with Z or an offset"
            }
            Kind::Daily => {
                "start/end filter on the date; any date or datetime is cut to YYYY-MM-DD"
            }
            Kind::Session => {
                "start/end filter on the local start time only: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS without a zone"
            }
            Kind::Sleep => {
                "start/end filter on when the sleep ENDS; local bounds or absolute RFC3339 with Z or an offset"
            }
            Kind::Ecg => "start only, absolute RFC3339 with Z or an offset; no end bound",
            Kind::Food => "no time filter; page through everything or pass a raw `filter`",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    List,
    Get,
    Reconcile,
    Rollup,
    DailyRollup,
}

impl Op {
    const ALL: [Op; 5] = [
        Op::List,
        Op::Get,
        Op::Reconcile,
        Op::Rollup,
        Op::DailyRollup,
    ];

    fn bit(self) -> u8 {
        match self {
            Op::List => 1,
            Op::Get => 2,
            Op::Reconcile => 4,
            Op::Rollup => 8,
            Op::DailyRollup => 16,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Op::List => "list",
            Op::Get => "get",
            Op::Reconcile => "reconcile",
            Op::Rollup => "rollup",
            Op::DailyRollup => "dailyRollup",
        }
    }
}

const LIST: u8 = 1;
const GET: u8 = 2;
const RECONCILE: u8 = 4;
const ROLLUP: u8 = 8;
const DAILY_ROLLUP: u8 = 16;

const LIST_RECONCILE_ROLLUPS: u8 = LIST | RECONCILE | ROLLUP | DAILY_ROLLUP;
const LIST_RECONCILE: u8 = LIST | RECONCILE;
const RECONCILE_ROLLUPS: u8 = RECONCILE | ROLLUP | DAILY_ROLLUP;
const ROLLUPS: u8 = ROLLUP | DAILY_ROLLUP;
const EVERYTHING: u8 = LIST | GET | RECONCILE | ROLLUP | DAILY_ROLLUP;
const LIST_GET_RECONCILE: u8 = LIST | GET | RECONCILE;
const LIST_GET: u8 = LIST | GET;

#[derive(Debug, PartialEq, Eq)]
pub struct DataType {
    /// Hyphenated name used in URLs.
    pub name: &'static str,
    pub kind: Kind,
    ops: u8,
}

impl DataType {
    pub fn supports(&self, op: Op) -> bool {
        self.ops & op.bit() != 0
    }

    pub fn operations(&self) -> Vec<&'static str> {
        Op::ALL
            .into_iter()
            .filter(|o| self.supports(*o))
            .map(Op::label)
            .collect()
    }

    /// Field name used in filter expressions (`-` becomes `_`).
    pub fn filter_field(&self) -> String {
        self.name.replace('-', "_")
    }

    /// camelCase key under which the payload sits in a data point.
    pub fn payload_key(&self) -> String {
        let mut out = String::with_capacity(self.name.len());
        for (i, part) in self.name.split('-').enumerate() {
            if i == 0 {
                out.push_str(part);
            } else {
                let mut cs = part.chars();
                if let Some(c) = cs.next() {
                    out.extend(c.to_uppercase());
                    out.push_str(cs.as_str());
                }
            }
        }
        out
    }
}

const fn dt(name: &'static str, kind: Kind, ops: u8) -> DataType {
    DataType { name, kind, ops }
}

pub static CATALOG: &[DataType] = &[
    dt(
        "active-energy-burned",
        Kind::Interval,
        LIST_RECONCILE_ROLLUPS,
    ),
    dt("active-minutes", Kind::Interval, LIST_RECONCILE_ROLLUPS),
    dt(
        "active-zone-minutes",
        Kind::Interval,
        LIST_RECONCILE_ROLLUPS,
    ),
    dt("altitude", Kind::Interval, LIST_RECONCILE_ROLLUPS),
    dt("distance", Kind::Interval, LIST_RECONCILE_ROLLUPS),
    dt("sedentary-period", Kind::Interval, LIST_RECONCILE_ROLLUPS),
    dt("steps", Kind::Interval, LIST_RECONCILE_ROLLUPS),
    dt("swim-lengths-data", Kind::Interval, LIST_RECONCILE_ROLLUPS),
    dt(
        "time-in-heart-rate-zone",
        Kind::Interval,
        LIST_RECONCILE_ROLLUPS,
    ),
    dt("activity-level", Kind::Interval, LIST_RECONCILE),
    dt("basal-energy-burned", Kind::Interval, LIST_RECONCILE),
    dt("floors", Kind::Interval, RECONCILE_ROLLUPS),
    dt("calories-in-heart-rate-zone", Kind::Interval, ROLLUPS),
    dt("total-calories", Kind::Interval, ROLLUPS),
    dt("blood-glucose", Kind::Sample, EVERYTHING),
    dt("body-fat", Kind::Sample, EVERYTHING),
    dt("core-body-temperature", Kind::Sample, EVERYTHING),
    dt("weight", Kind::Sample, EVERYTHING),
    dt("heart-rate", Kind::Sample, LIST_RECONCILE_ROLLUPS),
    dt("run-vo2-max", Kind::Sample, LIST_RECONCILE_ROLLUPS),
    dt("height", Kind::Sample, LIST_GET_RECONCILE),
    dt("heart-rate-variability", Kind::Sample, LIST_RECONCILE),
    dt("oxygen-saturation", Kind::Sample, LIST_RECONCILE),
    dt(
        "respiratory-rate-sleep-summary",
        Kind::Sample,
        LIST_RECONCILE,
    ),
    dt("vo2-max", Kind::Sample, LIST_RECONCILE),
    dt("skin-temperature-sensors", Kind::Sample, LIST),
    dt("daily-heart-rate-variability", Kind::Daily, LIST_RECONCILE),
    dt("daily-heart-rate-zones", Kind::Daily, LIST_RECONCILE),
    dt("daily-oxygen-saturation", Kind::Daily, LIST_RECONCILE),
    dt("daily-respiratory-rate", Kind::Daily, LIST_RECONCILE),
    dt("daily-resting-heart-rate", Kind::Daily, LIST_RECONCILE),
    dt(
        "daily-sleep-temperature-derivations",
        Kind::Daily,
        LIST_RECONCILE,
    ),
    dt("daily-vo2-max", Kind::Daily, LIST_RECONCILE),
    dt("exercise", Kind::Session, LIST_GET_RECONCILE),
    dt("hydration-log", Kind::Session, EVERYTHING),
    dt("nutrition-log", Kind::Session, EVERYTHING),
    dt("irregular-rhythm-notification", Kind::Session, LIST),
    dt("sleep", Kind::Sleep, LIST_GET_RECONCILE),
    dt("electrocardiogram", Kind::Ecg, LIST),
    dt("food", Kind::Food, LIST_GET),
    dt("food-measurement-unit", Kind::Food, LIST_GET),
];

/// Look up a data type by name (case-insensitive, `_` accepted for `-`).
pub fn lookup(name: &str) -> Result<&'static DataType, HealthError> {
    let norm = name.trim().to_ascii_lowercase().replace('_', "-");
    CATALOG.iter().find(|d| d.name == norm).ok_or_else(|| {
        let valid: Vec<&str> = CATALOG.iter().map(|d| d.name).collect();
        HealthError::Invalid(format!(
            "unknown data type '{}'; valid types: {}",
            name.trim(),
            valid.join(", ")
        ))
    })
}

/// Reject an operation the data type does not support, naming what it does.
pub fn require(dt: &DataType, op: Op) -> Result<(), HealthError> {
    if dt.supports(op) {
        return Ok(());
    }
    invalid(format!(
        "operation `{}` is not supported for data type {}; supported operations: {}",
        op.label(),
        dt.name,
        dt.operations().join(", ")
    ))
}

/// Body of `health_list_data_types`: the catalog plus a filter hint per kind.
pub fn catalog_json() -> Value {
    let types: Vec<Value> = CATALOG
        .iter()
        .map(|d| {
            json!({
                "dataType": d.name,
                "kind": d.kind.as_str(),
                "payloadKey": d.payload_key(),
                "operations": d.operations(),
            })
        })
        .collect();
    let mut hints = Map::new();
    for k in [
        Kind::Interval,
        Kind::Sample,
        Kind::Daily,
        Kind::Session,
        Kind::Sleep,
        Kind::Ecg,
        Kind::Food,
    ] {
        hints.insert(k.as_str().into(), Value::String(k.filter_hint().into()));
    }
    json!({ "dataTypes": types, "filterHints": hints })
}

// ---------------------------------------------------------------------------
// Filters, windows, ids
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flavour {
    Physical,
    Civil,
}

fn all_digits(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(u8::is_ascii_digit)
}

fn two(b: &[u8]) -> u32 {
    u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0')
}

/// Classify a bound as absolute (RFC3339 with `Z` or an offset) or local.
fn classify_bound(v: &str) -> Result<Flavour, HealthError> {
    let v = v.trim();
    let bad = || {
        HealthError::Invalid(format!(
            "'{v}' is not a valid bound; use YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS (local, no zone) or RFC3339 with Z or an offset"
        ))
    };
    let b = v.as_bytes();
    if b.len() < 10
        || b[4] != b'-'
        || b[7] != b'-'
        || !all_digits(&b[0..4])
        || !all_digits(&b[5..7])
        || !all_digits(&b[8..10])
    {
        return Err(bad());
    }
    let (month, day) = (two(&b[5..7]), two(&b[8..10]));
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad());
    }
    if b.len() == 10 {
        return Ok(Flavour::Civil);
    }
    if b[10] != b'T' {
        return Err(bad());
    }
    let t = &b[11..];
    if t.len() < 5 || !all_digits(&t[0..2]) || t[2] != b':' || !all_digits(&t[3..5]) {
        return Err(bad());
    }
    if two(&t[0..2]) > 23 || two(&t[3..5]) > 59 {
        return Err(bad());
    }
    let mut i = 5;
    if t.get(i) == Some(&b':') {
        if t.len() < i + 3 || !all_digits(&t[i + 1..i + 3]) || two(&t[i + 1..i + 3]) > 60 {
            return Err(bad());
        }
        i += 3;
        if t.get(i) == Some(&b'.') {
            let start = i + 1;
            let mut end = start;
            while end < t.len() && t[end].is_ascii_digit() {
                end += 1;
            }
            if end == start {
                return Err(bad());
            }
            i = end;
        }
    }
    match &t[i..] {
        [] => Ok(Flavour::Civil),
        [b'Z' | b'z'] => Ok(Flavour::Physical),
        z if z.len() == 6
            && (z[0] == b'+' || z[0] == b'-')
            && all_digits(&z[1..3])
            && z[3] == b':'
            && all_digits(&z[4..6]) =>
        {
            Ok(Flavour::Physical)
        }
        _ => Err(bad()),
    }
}

/// Build a closed-open time filter (`start >= ...` AND `end < ...`) for a
/// data type from friendly bounds, or `None` when neither bound is given.
pub fn build_filter(
    dt: &DataType,
    start: Option<&str>,
    end: Option<&str>,
) -> Result<Option<String>, HealthError> {
    if start.is_none() && end.is_none() {
        return Ok(None);
    }
    let f = dt.filter_field();
    let start = start.map(str::trim);
    let end = end.map(str::trim);
    let sf = start.map(classify_bound).transpose()?;
    let ef = end.map(classify_bound).transpose()?;
    match dt.kind {
        Kind::Food => {
            return invalid(format!(
                "{} has no time filter; drop start and end",
                dt.name
            ));
        }
        Kind::Ecg => {
            let Some(s) = start else {
                return invalid("electrocardiogram supports a start bound only");
            };
            if end.is_some() {
                return invalid("electrocardiogram supports a start bound only, not end");
            }
            if sf != Some(Flavour::Physical) {
                return invalid(
                    "electrocardiogram start must be RFC3339 with Z or an offset (a physical time)",
                );
            }
            return Ok(Some(format!("{f}.interval.start_time >= \"{s}\"")));
        }
        _ => {}
    }
    if dt.kind != Kind::Daily
        && let (Some(a), Some(b)) = (sf, ef)
        && a != b
    {
        return invalid(
            "start and end must be the same kind: both local (no zone) or both RFC3339 with Z or an offset",
        );
    }
    let flavour = sf.or(ef).unwrap_or(Flavour::Civil);
    let (field, cut_to_date) = match (dt.kind, flavour) {
        (Kind::Interval, Flavour::Physical) => (format!("{f}.interval.start_time"), false),
        (Kind::Interval, Flavour::Civil) => (format!("{f}.interval.civil_start_time"), false),
        (Kind::Sample, Flavour::Physical) => (format!("{f}.sample_time.physical_time"), false),
        (Kind::Sample, Flavour::Civil) => (format!("{f}.sample_time.civil_time"), false),
        (Kind::Daily, _) => (format!("{f}.date"), true),
        (Kind::Session, Flavour::Physical) => {
            return invalid(
                "session data types filter on local time only: use a local date or YYYY-MM-DDTHH:MM:SS without a zone",
            );
        }
        (Kind::Session, Flavour::Civil) => (format!("{f}.interval.civil_start_time"), false),
        (Kind::Sleep, Flavour::Physical) => (format!("{f}.interval.end_time"), false),
        (Kind::Sleep, Flavour::Civil) => (format!("{f}.interval.civil_end_time"), false),
        (Kind::Ecg | Kind::Food, _) => unreachable!("handled above"),
    };
    let lit = |v: &str| {
        if cut_to_date {
            v[..10].to_string()
        } else {
            v.to_string()
        }
    };
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = start {
        parts.push(format!("{field} >= \"{}\"", lit(s)));
    }
    if let Some(e) = end {
        parts.push(format!("{field} < \"{}\"", lit(e)));
    }
    Ok(Some(parts.join(" AND ")))
}

/// Pick the filter to send: a raw `filter` verbatim (exclusive with the
/// bounds) or one built from `start`/`end`.
pub fn resolve_filter(
    dt: &DataType,
    filter: Option<&str>,
    start: Option<&str>,
    end: Option<&str>,
) -> Result<Option<String>, HealthError> {
    match filter {
        Some(raw) => {
            if start.is_some() || end.is_some() {
                return invalid("pass either `filter` or `start`/`end`, not both");
            }
            if raw.trim().is_empty() {
                return invalid("`filter` must not be empty");
            }
            Ok(Some(raw.to_string()))
        }
        None => build_filter(dt, start, end),
    }
}

/// Normalise `"90s"`, `"15m"`, `"1h"`, `"1d"` or bare seconds to `"<n>s"`.
pub fn parse_window(s: &str) -> Result<String, HealthError> {
    let t = s.trim();
    let bad = || {
        HealthError::Invalid(format!(
            "invalid window '{t}'; use a whole number with an optional s, m, h or d unit (for example 90s, 15m, 1h, 1d or 3600), at least 1 second"
        ))
    };
    let (digits, mult) = match t.as_bytes().last() {
        Some(b's') => (&t[..t.len() - 1], 1u64),
        Some(b'm') => (&t[..t.len() - 1], 60),
        Some(b'h') => (&t[..t.len() - 1], 3600),
        Some(b'd') => (&t[..t.len() - 1], 86_400),
        _ => (t, 1),
    };
    if !all_digits(digits.as_bytes()) {
        return Err(bad());
    }
    let n: u64 = digits.parse().map_err(|_| bad())?;
    let secs = n.checked_mul(mult).ok_or_else(bad)?;
    if secs == 0 {
        return Err(bad());
    }
    Ok(format!("{secs}s"))
}

const FAMILIES: [&str; 4] = [
    "all-sources",
    "google-wearables",
    "google-sources",
    "self-sources",
];

/// Expand a short data source family name to its resource name.
pub fn expand_family(s: &str) -> Result<String, HealthError> {
    let t = s.trim();
    if FAMILIES.contains(&t) {
        return Ok(format!("users/me/dataSourceFamilies/{t}"));
    }
    invalid(format!(
        "unknown data_source_family '{t}'; use one of {}",
        FAMILIES.join(", ")
    ))
}

/// Extract the numeric id from bare digits or a full data point name whose
/// type matches `data_type`.
pub fn parse_point_id(data_type: &str, s: &str) -> Result<String, HealthError> {
    let t = s.trim();
    if all_digits(t.as_bytes()) {
        return Ok(t.to_string());
    }
    let parts: Vec<&str> = t.split('/').collect();
    let ok = parts.len() == 6
        && parts[0] == "users"
        && (parts[1] == "me" || all_digits(parts[1].as_bytes()))
        && parts[2] == "dataTypes"
        && parts[3] == data_type
        && parts[4] == "dataPoints"
        && all_digits(parts[5].as_bytes());
    if ok {
        return Ok(parts[5].to_string());
    }
    invalid(format!(
        "invalid {data_type} id '{t}'; pass the digits or a full name like users/me/dataTypes/{data_type}/dataPoints/<digits>"
    ))
}

/// Parse a strict `YYYY-MM-DD` into year, month, day.
fn parse_ymd(s: &str) -> Result<(u32, u32, u32), HealthError> {
    let t = s.trim();
    if t.len() != 10 || classify_bound(t)? != Flavour::Civil {
        return invalid(format!("'{t}' is not a date; use YYYY-MM-DD"));
    }
    let b = t.as_bytes();
    let year = two(&b[0..2]) * 100 + two(&b[2..4]);
    Ok((year, two(&b[5..7]), two(&b[8..10])))
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

fn points_path(dt: &DataType, suffix: &str) -> Result<String, HealthError> {
    Ok(format!(
        "users/me/dataTypes/{}/dataPoints{suffix}",
        seg(dt.name)?
    ))
}

fn paging_query(
    q: &mut Vec<(String, String)>,
    family: Option<&str>,
    page_size: Option<u32>,
    page_token: Option<&str>,
) -> Result<(), HealthError> {
    if let Some(f) = family {
        q.push(("dataSourceFamily".into(), expand_family(f)?));
    }
    if let Some(n) = page_size {
        q.push(("pageSize".into(), n.to_string()));
    }
    if let Some(t) = page_token {
        q.push(("pageToken".into(), t.into()));
    }
    Ok(())
}

fn paging_body(
    body: &mut Value,
    family: Option<&str>,
    page_size: Option<u32>,
    page_token: Option<&str>,
) -> Result<(), HealthError> {
    if let Some(f) = family {
        body["dataSourceFamily"] = json!(expand_family(f)?);
    }
    if let Some(n) = page_size {
        body["pageSize"] = json!(n);
    }
    if let Some(t) = page_token {
        body["pageToken"] = json!(t);
    }
    Ok(())
}

/// Types whose rollup range the API caps at 14 days; every other type allows 90.
const SHORT_RANGE_TYPES: [&str; 4] = [
    "heart-rate",
    "active-minutes",
    "total-calories",
    "calories-in-heart-rate-zone",
];
const DAY_SECS: i128 = 86_400;
const NANOS: i128 = 1_000_000_000;

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Nanoseconds since the Unix epoch of a validated absolute RFC3339 instant.
fn instant_nanos(v: &str) -> Result<i128, HealthError> {
    let v = v.trim();
    if classify_bound(v)? != Flavour::Physical {
        return invalid(format!("'{v}' must be RFC3339 with Z or an offset"));
    }
    let b = v.as_bytes();
    let num = |r: std::ops::Range<usize>| i64::from(two(&b[r.start..r.start + 2]));
    let year = i64::from(two(&b[0..2])) * 100 + i64::from(two(&b[2..4]));
    let days = days_from_civil(year, num(5..7), num(8..10));
    let mut secs = i128::from(days) * DAY_SECS + i128::from(num(11..13) * 3600 + num(14..16) * 60);
    let mut i = 16;
    if b.get(i) == Some(&b':') {
        secs += i128::from(num(i + 1..i + 3));
        i += 3;
    }
    let mut nanos: i128 = 0;
    if b.get(i) == Some(&b'.') {
        let digits: Vec<u8> = b[i + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .copied()
            .collect();
        for k in 0..9 {
            nanos = nanos * 10 + i128::from(digits.get(k).map_or(0, |c| c - b'0'));
        }
        i += 1 + digits.len();
    }
    let zone = &b[i..];
    if zone.len() == 6 {
        let off = i128::from(two(&zone[1..3]) * 3600 + two(&zone[4..6]) * 60);
        secs -= if zone[0] == b'-' { -off } else { off };
    }
    Ok(secs * NANOS + nanos)
}

fn fmt_span(nanos: i128) -> String {
    let s = nanos / NANOS;
    format!(
        "{}d {}h {}m {}s",
        s / DAY_SECS,
        s % DAY_SECS / 3600,
        s % 3600 / 60,
        s % 60
    )
}

/// Reject a rollup range that is empty, reversed or over the API cap.
fn check_rollup_range(dt: &DataType, start: &str, end: &str) -> Result<(), HealthError> {
    let span = instant_nanos(end)? - instant_nanos(start)?;
    if span <= 0 {
        return invalid("`end` must be after `start`");
    }
    let cap_days: i128 = if SHORT_RANGE_TYPES.contains(&dt.name) {
        14
    } else {
        90
    };
    if span > cap_days * DAY_SECS * NANOS {
        return invalid(format!(
            "{} rollup range is {} but the API allows at most {cap_days} days; split the request into chunks of at most {cap_days} days",
            dt.name,
            fmt_span(span)
        ));
    }
    Ok(())
}

/// Reject a reversed daily range, or one over 14 days for the short-range types.
fn check_daily_range(
    dt: &DataType,
    start: (u32, u32, u32),
    end: (u32, u32, u32),
) -> Result<(), HealthError> {
    let days =
        |(y, m, d): (u32, u32, u32)| days_from_civil(i64::from(y), i64::from(m), i64::from(d));
    let span = days(end) - days(start);
    if span <= 0 {
        return invalid("`end_date` must be after `start_date`");
    }
    if SHORT_RANGE_TYPES.contains(&dt.name) && span > 14 {
        return invalid(format!(
            "{} daily rollup range is {span} days but the API allows at most 14 days; split the request into chunks of at most 14 days",
            dt.name
        ));
    }
    Ok(())
}

pub struct ListArgs<'a> {
    pub data_type: &'a str,
    pub start: Option<&'a str>,
    pub end: Option<&'a str>,
    pub filter: Option<&'a str>,
    pub data_source_family: Option<&'a str>,
    pub page_size: Option<u32>,
    pub page_token: Option<&'a str>,
    pub reconcile: bool,
}

#[derive(Debug)]
pub struct ListRequest {
    pub data_type: &'static DataType,
    pub path: String,
    pub query: Vec<(String, String)>,
}

impl ListArgs<'_> {
    pub fn build(&self) -> Result<ListRequest, HealthError> {
        let dt = lookup(self.data_type)?;
        require(
            dt,
            if self.reconcile {
                Op::Reconcile
            } else {
                Op::List
            },
        )?;
        let mut query = Vec::new();
        if let Some(f) = resolve_filter(dt, self.filter, self.start, self.end)? {
            query.push(("filter".into(), f));
        }
        paging_query(
            &mut query,
            self.data_source_family,
            Some(self.page_size.unwrap_or(DEFAULT_PAGE_SIZE)),
            self.page_token,
        )?;
        let path = points_path(dt, if self.reconcile { ":reconcile" } else { "" })?;
        Ok(ListRequest {
            data_type: dt,
            path,
            query,
        })
    }
}

pub struct RollupArgs<'a> {
    pub data_type: &'a str,
    pub start: &'a str,
    pub end: &'a str,
    pub window: &'a str,
    pub data_source_family: Option<&'a str>,
    pub page_size: Option<u32>,
    pub page_token: Option<&'a str>,
}

pub struct DailyRollupArgs<'a> {
    pub data_type: &'a str,
    pub start_date: &'a str,
    pub end_date: &'a str,
    pub window_days: Option<u32>,
    pub data_source_family: Option<&'a str>,
    pub page_size: Option<u32>,
    pub page_token: Option<&'a str>,
}

#[derive(Debug)]
pub struct RollupRequest {
    pub data_type: &'static DataType,
    pub path: String,
    pub body: Value,
}

impl RollupArgs<'_> {
    pub fn build(&self) -> Result<RollupRequest, HealthError> {
        let dt = lookup(self.data_type)?;
        require(dt, Op::Rollup)?;
        for (name, v) in [("start", self.start), ("end", self.end)] {
            if classify_bound(v)? != Flavour::Physical {
                return invalid(format!(
                    "`{name}` must be RFC3339 with Z or an offset, for example 2026-01-02T00:00:00Z"
                ));
            }
        }
        check_rollup_range(dt, self.start, self.end)?;
        let mut body = json!({
            "range": {"startTime": self.start.trim(), "endTime": self.end.trim()},
            "windowSize": parse_window(self.window)?,
        });
        paging_body(
            &mut body,
            self.data_source_family,
            self.page_size,
            self.page_token,
        )?;
        Ok(RollupRequest {
            data_type: dt,
            path: points_path(dt, ":rollUp")?,
            body,
        })
    }
}

impl DailyRollupArgs<'_> {
    pub fn build(&self) -> Result<RollupRequest, HealthError> {
        let dt = lookup(self.data_type)?;
        require(dt, Op::DailyRollup)?;
        let days = self.window_days.unwrap_or(1);
        if days == 0 {
            return invalid("`window_days` must be at least 1");
        }
        let date = |s: &str| -> Result<Value, HealthError> {
            let (y, m, d) = parse_ymd(s)?;
            Ok(json!({"date": {"year": y, "month": m, "day": d}}))
        };
        check_daily_range(dt, parse_ymd(self.start_date)?, parse_ymd(self.end_date)?)?;
        let mut body = json!({
            "range": {"start": date(self.start_date)?, "end": date(self.end_date)?},
            "windowSizeDays": days,
        });
        paging_body(
            &mut body,
            self.data_source_family,
            self.page_size,
            self.page_token,
        )?;
        Ok(RollupRequest {
            data_type: dt,
            path: points_path(dt, ":dailyRollUp")?,
            body,
        })
    }
}

// ---------------------------------------------------------------------------
// Output mappers
// ---------------------------------------------------------------------------

const STRIP_KEYS: [&str; 5] = [
    "civilStartTime",
    "civilEndTime",
    "civilTime",
    "createTime",
    "updateTime",
];

fn date_string(v: &Value) -> Option<String> {
    let o = v.as_object()?;
    let y = o.get("year")?.as_i64()?;
    let m = o.get("month")?.as_i64()?;
    let d = o.get("day")?.as_i64()?;
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// Flatten `{year,month,day}` under `date`/`membershipStartDate` keys to
/// `"YYYY-MM-DD"`; with `strip`, also drop civil and create/update times.
fn walk(v: &mut Value, strip: bool) {
    match v {
        Value::Object(m) => {
            if strip {
                for k in STRIP_KEYS {
                    m.remove(k);
                }
            }
            for (k, child) in m.iter_mut() {
                let flat = if k == "date" || k == "membershipStartDate" {
                    date_string(child)
                } else {
                    None
                };
                match flat {
                    Some(s) => *child = Value::String(s),
                    None => walk(child, strip),
                }
            }
        }
        Value::Array(a) => {
            for x in a.iter_mut() {
                walk(x, strip);
            }
        }
        _ => {}
    }
}

/// Slim one data point: civil and create/update times dropped, dates flat.
pub fn slim_point(v: &mut Value) {
    walk(v, true);
}

/// Flatten date objects only (profile and similar single resources).
pub fn flatten_dates(v: &mut Value) {
    walk(v, false);
}

/// When every point carries the identical `dataSource`, remove it from the
/// points and return it once.
fn hoist_data_source(points: &mut [Value]) -> Option<Value> {
    let first = points.first()?.get("dataSource")?.clone();
    if !points.iter().all(|p| p.get("dataSource") == Some(&first)) {
        return None;
    }
    for p in points.iter_mut() {
        if let Some(o) = p.as_object_mut() {
            o.remove("dataSource");
        }
    }
    Some(first)
}

fn take_array(body: &mut Value, key: &str) -> Vec<Value> {
    match body.get_mut(key).map(Value::take) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    }
}

fn next_token(body: &Value) -> Option<Value> {
    body.get("nextPageToken")
        .filter(|t| t.as_str().is_some_and(|s| !s.is_empty()))
        .cloned()
}

/// `{ dataType, dataPoints, nextPageToken?, dataSource? }` from a list or
/// reconcile response.
pub fn map_points(data_type: &str, mut body: Value) -> Value {
    let mut points = take_array(&mut body, "dataPoints");
    for p in &mut points {
        slim_point(p);
    }
    let ds = hoist_data_source(&mut points);
    let mut out = json!({"dataType": data_type, "dataPoints": points});
    if let Some(t) = next_token(&body) {
        out["nextPageToken"] = t;
    }
    if let Some(ds) = ds {
        out["dataSource"] = ds;
    }
    out
}

fn civil_string(v: &Value) -> Option<String> {
    let mut s = date_string(v.get("date")?)?;
    if let Some(t) = v.get("time").and_then(Value::as_object)
        && !t.is_empty()
    {
        let n = |k: &str| t.get(k).and_then(Value::as_i64).unwrap_or(0);
        s.push_str(&format!(
            "T{:02}:{:02}:{:02}",
            n("hours"),
            n("minutes"),
            n("seconds")
        ));
    }
    Some(s)
}

/// `{ dataType, rollupDataPoints, nextPageToken? }`; with `daily`, civil
/// start and end become `date` / `endDate` strings.
pub fn map_rollup(data_type: &str, mut body: Value, daily: bool) -> Value {
    let mut points = take_array(&mut body, "rollupDataPoints");
    if daily {
        for p in &mut points {
            let Some(o) = p.as_object_mut() else { continue };
            for (from, to) in [("civilStartTime", "date"), ("civilEndTime", "endDate")] {
                if let Some(c) = o.remove(from)
                    && let Some(s) = civil_string(&c)
                {
                    o.insert(to.into(), Value::String(s));
                }
            }
        }
    }
    let mut out = json!({"dataType": data_type, "rollupDataPoints": points});
    if let Some(t) = next_token(&body) {
        out["nextPageToken"] = t;
    }
    out
}

/// `{ pairedDevices, nextPageToken? }` with `macAddress` dropped.
pub fn map_devices(mut body: Value) -> Value {
    let mut devices = take_array(&mut body, "pairedDevices");
    for d in &mut devices {
        if let Some(o) = d.as_object_mut() {
            o.remove("macAddress");
        }
    }
    let mut out = json!({"pairedDevices": devices});
    if let Some(t) = next_token(&body) {
        out["nextPageToken"] = t;
    }
    out
}

/// Google's `error.message` when the body is a standard error, else the raw
/// text, capped at 800 characters.
fn api_message(bytes: &[u8]) -> String {
    if let Ok(v) = serde_json::from_slice::<Value>(bytes)
        && let Some(m) = v.pointer("/error/message").and_then(Value::as_str)
    {
        return m.chars().take(800).collect();
    }
    String::from_utf8_lossy(bytes).chars().take(800).collect()
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct HealthClient {
    http: reqwest::Client,
    access_token: String,
}

impl HealthClient {
    pub fn new(http: reqwest::Client, access_token: impl Into<String>) -> Self {
        Self {
            http,
            access_token: access_token.into(),
        }
    }

    pub async fn identity(&self) -> Result<Value, HealthError> {
        self.get_json("users/me/identity", &[]).await
    }

    pub async fn profile(&self) -> Result<Value, HealthError> {
        let mut v = self.get_json("users/me/profile", &[]).await?;
        flatten_dates(&mut v);
        Ok(v)
    }

    pub async fn settings(&self) -> Result<Value, HealthError> {
        self.get_json("users/me/settings", &[]).await
    }

    pub async fn irn_profile(&self) -> Result<Value, HealthError> {
        self.get_json("users/me/irnProfile", &[]).await
    }

    pub async fn paired_devices(
        &self,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<Value, HealthError> {
        let mut q = Vec::new();
        paging_query(&mut q, None, page_size, page_token)?;
        let v = self.get_json("users/me/pairedDevices", &q).await?;
        Ok(map_devices(v))
    }

    pub async fn list_data_points(&self, args: &ListArgs<'_>) -> Result<Value, HealthError> {
        let req = args.build()?;
        let v = self.get_json(&req.path, &req.query).await?;
        Ok(map_points(req.data_type.name, v))
    }

    pub async fn get_data_point(&self, data_type: &str, id: &str) -> Result<Value, HealthError> {
        let dt = lookup(data_type)?;
        require(dt, Op::Get)?;
        let id = parse_point_id(dt.name, id)?;
        let path = points_path(dt, &format!("/{}", seg(&id)?))?;
        let mut v = self.get_json(&path, &[]).await?;
        slim_point(&mut v);
        Ok(v)
    }

    pub async fn rollup(&self, args: &RollupArgs<'_>) -> Result<Value, HealthError> {
        let req = args.build()?;
        let v = self.post_json(&req.path, &req.body).await?;
        Ok(map_rollup(req.data_type.name, v, false))
    }

    pub async fn daily_rollup(&self, args: &DailyRollupArgs<'_>) -> Result<Value, HealthError> {
        let req = args.build()?;
        let v = self.post_json(&req.path, &req.body).await?;
        Ok(map_rollup(req.data_type.name, v, true))
    }

    /// Raw TCX XML bytes of one exercise.
    pub async fn export_exercise_tcx(
        &self,
        exercise_id: &str,
        partial_data: bool,
    ) -> Result<Vec<u8>, HealthError> {
        let id = parse_point_id("exercise", exercise_id)?;
        let mut q: Vec<(String, String)> = vec![("alt".into(), "media".into())];
        if partial_data {
            q.push(("partialData".into(), "true".into()));
        }
        let url = format!(
            "{BASE}/users/me/dataTypes/exercise/dataPoints/{}:exportExerciseTcx",
            seg(&id)?
        );
        self.send(Method::GET, url, None::<&()>, &q, MAX_DOWNLOAD_BYTES)
            .await
    }

    async fn get_json(&self, path: &str, query: &[(String, String)]) -> Result<Value, HealthError> {
        let bytes = self
            .send(
                Method::GET,
                format!("{BASE}/{path}"),
                None::<&()>,
                query,
                MAX_API_RESPONSE_BYTES,
            )
            .await?;
        parse_json(&bytes)
    }

    async fn post_json(&self, path: &str, body: &Value) -> Result<Value, HealthError> {
        let bytes = self
            .send(
                Method::POST,
                format!("{BASE}/{path}"),
                Some(body),
                &[],
                MAX_API_RESPONSE_BYTES,
            )
            .await?;
        parse_json(&bytes)
    }

    async fn send<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: String,
        body: Option<&B>,
        query: &[(String, String)],
        cap: usize,
    ) -> Result<Vec<u8>, HealthError> {
        let mut req = self
            .http
            .request(method, &url)
            .bearer_auth(&self.access_token);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let bytes = read_body_capped(resp, cap).await?;
        if status.is_success() {
            return Ok(bytes);
        }
        Err(HealthError::Api {
            status,
            message: api_message(&bytes),
        })
    }
}

fn parse_json(bytes: &[u8]) -> Result<Value, HealthError> {
    if bytes.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(bytes).map_err(HealthError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(name: &str) -> &'static DataType {
        lookup(name).unwrap()
    }

    fn err_text<T: std::fmt::Debug>(r: Result<T, HealthError>) -> String {
        r.unwrap_err().to_string()
    }

    // --- filters ---

    #[test]
    fn filter_interval_civil() {
        let f = build_filter(ty("steps"), Some("2026-01-02"), Some("2026-01-03")).unwrap();
        assert_eq!(
            f.unwrap(),
            "steps.interval.civil_start_time >= \"2026-01-02\" AND steps.interval.civil_start_time < \"2026-01-03\""
        );
    }

    #[test]
    fn filter_interval_physical() {
        let f = build_filter(
            ty("active-minutes"),
            Some("2026-01-02T00:00:00Z"),
            Some("2026-01-03T00:00:00-05:00"),
        )
        .unwrap();
        assert_eq!(
            f.unwrap(),
            "active_minutes.interval.start_time >= \"2026-01-02T00:00:00Z\" AND active_minutes.interval.start_time < \"2026-01-03T00:00:00-05:00\""
        );
    }

    #[test]
    fn filter_sample_physical_and_civil() {
        let p = build_filter(ty("heart-rate"), Some("2026-01-02T10:00:00Z"), None).unwrap();
        assert_eq!(
            p.unwrap(),
            "heart_rate.sample_time.physical_time >= \"2026-01-02T10:00:00Z\""
        );
        let c = build_filter(ty("weight"), None, Some("2026-01-02T10:00")).unwrap();
        assert_eq!(
            c.unwrap(),
            "weight.sample_time.civil_time < \"2026-01-02T10:00\""
        );
    }

    #[test]
    fn filter_daily_cuts_datetime_to_date() {
        let f = build_filter(
            ty("daily-resting-heart-rate"),
            Some("2026-01-02T08:30:00"),
            Some("2026-01-09"),
        )
        .unwrap();
        assert_eq!(
            f.unwrap(),
            "daily_resting_heart_rate.date >= \"2026-01-02\" AND daily_resting_heart_rate.date < \"2026-01-09\""
        );
    }

    #[test]
    fn filter_session_civil_ok_physical_error() {
        let f = build_filter(ty("exercise"), Some("2026-01-02T06:00:00"), None).unwrap();
        assert_eq!(
            f.unwrap(),
            "exercise.interval.civil_start_time >= \"2026-01-02T06:00:00\""
        );
        let e = err_text(build_filter(
            ty("exercise"),
            Some("2026-01-02T06:00:00Z"),
            None,
        ));
        assert!(
            e.contains("local date or YYYY-MM-DDTHH:MM:SS without a zone"),
            "{e}"
        );
    }

    #[test]
    fn filter_sleep_both_flavours_use_end_time() {
        let p = build_filter(ty("sleep"), Some("2026-01-02T00:00:00Z"), None).unwrap();
        assert_eq!(
            p.unwrap(),
            "sleep.interval.end_time >= \"2026-01-02T00:00:00Z\""
        );
        let c = build_filter(ty("sleep"), Some("2026-01-02"), Some("2026-01-09")).unwrap();
        assert_eq!(
            c.unwrap(),
            "sleep.interval.civil_end_time >= \"2026-01-02\" AND sleep.interval.civil_end_time < \"2026-01-09\""
        );
    }

    #[test]
    fn filter_ecg_start_only() {
        let f = build_filter(ty("electrocardiogram"), Some("2026-01-02T00:00:00Z"), None).unwrap();
        assert_eq!(
            f.unwrap(),
            "electrocardiogram.interval.start_time >= \"2026-01-02T00:00:00Z\""
        );
        assert!(
            build_filter(
                ty("electrocardiogram"),
                Some("2026-01-02T00:00:00Z"),
                Some("2026-01-03T00:00:00Z")
            )
            .is_err()
        );
        assert!(build_filter(ty("electrocardiogram"), None, Some("2026-01-03T00:00:00Z")).is_err());
        assert!(build_filter(ty("electrocardiogram"), Some("2026-01-02"), None).is_err());
    }

    #[test]
    fn filter_food_rejects_any_bound() {
        assert!(build_filter(ty("food"), Some("2026-01-02"), None).is_err());
        assert!(build_filter(ty("food"), None, Some("2026-01-02")).is_err());
        assert_eq!(build_filter(ty("food"), None, None).unwrap(), None);
    }

    #[test]
    fn filter_mixed_flavours_and_junk_error() {
        let e = err_text(build_filter(
            ty("steps"),
            Some("2026-01-02"),
            Some("2026-01-03T00:00:00Z"),
        ));
        assert!(e.contains("same kind"), "{e}");
        assert!(build_filter(ty("steps"), Some("yesterday"), None).is_err());
        assert!(build_filter(ty("steps"), Some("2026-13-02"), None).is_err());
        assert!(build_filter(ty("steps"), Some("2026-01-02T10:00:00+0500"), None).is_err());
        assert!(build_filter(ty("steps"), Some("2026-01-02\" OR 1=1"), None).is_err());
    }

    #[test]
    fn raw_filter_is_verbatim_and_exclusive() {
        let raw = "steps.interval.civil_start_time >= \"2026-01-02\"";
        assert_eq!(
            resolve_filter(ty("steps"), Some(raw), None, None)
                .unwrap()
                .unwrap(),
            raw
        );
        assert!(resolve_filter(ty("steps"), Some(raw), Some("2026-01-02"), None).is_err());
        assert!(resolve_filter(ty("steps"), Some(raw), None, Some("2026-01-02")).is_err());
        assert!(resolve_filter(ty("steps"), Some("  "), None, None).is_err());
        assert_eq!(resolve_filter(ty("steps"), None, None, None).unwrap(), None);
    }

    // --- windows ---

    #[test]
    fn window_parser_accepts_units() {
        assert_eq!(parse_window("90s").unwrap(), "90s");
        assert_eq!(parse_window("15m").unwrap(), "900s");
        assert_eq!(parse_window("1h").unwrap(), "3600s");
        assert_eq!(parse_window("1d").unwrap(), "86400s");
        assert_eq!(parse_window("3600").unwrap(), "3600s");
        assert_eq!(parse_window(" 2h ").unwrap(), "7200s");
    }

    #[test]
    fn window_parser_rejects_junk() {
        for bad in [
            "0",
            "",
            "abc",
            "1.5h",
            "0m",
            "-5",
            "h",
            "99999999999999999999d",
        ] {
            assert!(parse_window(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    // --- catalog ---

    #[test]
    fn catalog_has_41_unique_types() {
        assert_eq!(CATALOG.len(), 41);
        let mut names: Vec<&str> = CATALOG.iter().map(|d| d.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 41);
    }

    #[test]
    fn payload_keys_and_filter_fields() {
        assert_eq!(
            ty("daily-resting-heart-rate").payload_key(),
            "dailyRestingHeartRate"
        );
        assert_eq!(ty("run-vo2-max").payload_key(), "runVo2Max");
        assert_eq!(ty("daily-vo2-max").payload_key(), "dailyVo2Max");
        assert_eq!(ty("vo2-max").payload_key(), "vo2Max");
        assert_eq!(ty("steps").payload_key(), "steps");
        assert_eq!(
            ty("daily-resting-heart-rate").filter_field(),
            "daily_resting_heart_rate"
        );
        assert_eq!(ty("run-vo2-max").filter_field(), "run_vo2_max");
    }

    #[test]
    fn lookup_normalises_and_unknown_lists_types() {
        assert_eq!(lookup(" Heart_Rate ").unwrap().name, "heart-rate");
        let e = err_text(lookup("bogus"));
        assert!(e.contains("unknown data type 'bogus'"), "{e}");
        assert!(
            e.contains("steps") && e.contains("electrocardiogram"),
            "{e}"
        );
    }

    #[test]
    fn ops_gating_names_supported_operations() {
        let tc = ty("total-calories");
        let e = err_text(require(tc, Op::List));
        assert!(e.contains("rollup") && e.contains("dailyRollup"), "{e}");
        assert!(e.contains("`list`") && e.contains("total-calories"), "{e}");
        assert!(require(tc, Op::Rollup).is_ok());
        assert_eq!(
            ty("floors").operations(),
            ["reconcile", "rollup", "dailyRollup"]
        );
        assert_eq!(ty("weight").operations().len(), 5);
        assert!(require(ty("steps"), Op::Get).is_err());
        assert!(require(ty("exercise"), Op::Get).is_ok());
        assert!(require(ty("exercise"), Op::Rollup).is_err());
    }

    #[test]
    fn catalog_json_shape() {
        let v = catalog_json();
        assert_eq!(v["dataTypes"].as_array().unwrap().len(), 41);
        let steps = v["dataTypes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["dataType"] == "steps")
            .unwrap();
        assert_eq!(steps["kind"], "interval");
        assert_eq!(
            steps["operations"],
            json!(["list", "reconcile", "rollup", "dailyRollup"])
        );
        assert_eq!(v["filterHints"].as_object().unwrap().len(), 7);
    }

    // --- request builders ---

    #[test]
    fn rollup_body_exact() {
        let req = RollupArgs {
            data_type: "heart-rate",
            start: "2026-01-02T00:00:00Z",
            end: "2026-01-03T00:00:00Z",
            window: "1h",
            data_source_family: None,
            page_size: None,
            page_token: None,
        }
        .build()
        .unwrap();
        assert_eq!(req.path, "users/me/dataTypes/heart-rate/dataPoints:rollUp");
        assert_eq!(
            req.body,
            json!({
                "range": {"startTime": "2026-01-02T00:00:00Z", "endTime": "2026-01-03T00:00:00Z"},
                "windowSize": "3600s"
            })
        );
    }

    #[test]
    fn rollup_body_with_optionals() {
        let req = RollupArgs {
            data_type: "steps",
            start: "2026-01-02T00:00:00+01:00",
            end: "2026-01-03T00:00:00+01:00",
            window: "15m",
            data_source_family: Some("google-wearables"),
            page_size: Some(50),
            page_token: Some("tok"),
        }
        .build()
        .unwrap();
        assert_eq!(
            req.body,
            json!({
                "range": {"startTime": "2026-01-02T00:00:00+01:00", "endTime": "2026-01-03T00:00:00+01:00"},
                "windowSize": "900s",
                "dataSourceFamily": "users/me/dataSourceFamilies/google-wearables",
                "pageSize": 50,
                "pageToken": "tok"
            })
        );
    }

    #[test]
    fn rollup_rejects_civil_bounds_and_unsupported_types() {
        let mk = |dt: &'static str, start: &'static str| RollupArgs {
            data_type: dt,
            start,
            end: "2026-01-03T00:00:00Z",
            window: "1h",
            data_source_family: None,
            page_size: None,
            page_token: None,
        };
        assert!(mk("steps", "2026-01-02").build().is_err());
        assert!(mk("exercise", "2026-01-02T00:00:00Z").build().is_err());
        assert!(mk("steps", "2026-01-02T00:00:00Z").build().is_ok());
    }

    #[test]
    fn daily_rollup_body_exact() {
        let req = DailyRollupArgs {
            data_type: "steps",
            start_date: "2026-01-02",
            end_date: "2026-02-03",
            window_days: None,
            data_source_family: None,
            page_size: None,
            page_token: None,
        }
        .build()
        .unwrap();
        assert_eq!(req.path, "users/me/dataTypes/steps/dataPoints:dailyRollUp");
        assert_eq!(
            req.body,
            json!({
                "range": {
                    "start": {"date": {"year": 2026, "month": 1, "day": 2}},
                    "end": {"date": {"year": 2026, "month": 2, "day": 3}}
                },
                "windowSizeDays": 1
            })
        );
    }

    fn rollup_for(
        dt: &'static str,
        start: &'static str,
        end: &'static str,
    ) -> Result<RollupRequest, HealthError> {
        RollupArgs {
            data_type: dt,
            start,
            end,
            window: "1h",
            data_source_family: None,
            page_size: None,
            page_token: None,
        }
        .build()
    }

    #[test]
    fn rollup_short_types_cap_at_14_days() {
        for t in [
            "heart-rate",
            "active-minutes",
            "total-calories",
            "calories-in-heart-rate-zone",
        ] {
            assert!(
                rollup_for(t, "2026-10-09T00:00:00Z", "2026-10-23T00:00:00Z").is_ok(),
                "{t}"
            );
            let e = err_text(rollup_for(
                t,
                "2026-10-08T23:59:59Z",
                "2026-10-23T00:00:00Z",
            ));
            assert!(
                e.contains(t) && e.contains("14 days") && e.contains("split"),
                "{e}"
            );
            assert!(e.contains("14d 0h 0m 1s"), "{e}");
        }
    }

    #[test]
    fn rollup_other_types_cap_at_90_days() {
        assert!(rollup_for("steps", "2026-07-25T00:00:00Z", "2026-10-23T00:00:00Z").is_ok());
        let e = err_text(rollup_for(
            "steps",
            "2026-07-24T00:00:00Z",
            "2026-10-23T00:00:00Z",
        ));
        assert!(
            e.contains("steps") && e.contains("91d") && e.contains("90 days"),
            "{e}"
        );
    }

    #[test]
    fn rollup_range_honours_offsets_and_order() {
        // Offsets shift the instant: 19:00-05:00 and 05:00+05:00 are both 00:00Z.
        let end = "2026-10-23T00:00:00Z";
        assert!(rollup_for("heart-rate", "2026-10-08T19:00:00-05:00", end).is_ok());
        assert!(rollup_for("heart-rate", "2026-10-08T18:59:59-05:00", end).is_err());
        assert!(rollup_for("heart-rate", "2026-10-09T05:00:00+05:00", end).is_ok());
        assert!(rollup_for("heart-rate", "2026-10-09T04:59:59+05:00", end).is_err());
        assert!(rollup_for("steps", "2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z").is_err());
        let e = err_text(rollup_for(
            "steps",
            "2026-10-24T00:00:00Z",
            "2026-10-23T00:00:00Z",
        ));
        assert!(e.contains("after"), "{e}");
        assert!(
            rollup_for(
                "heart-rate",
                "2026-10-09T00:00:00.5Z",
                "2026-10-23T00:00:00Z"
            )
            .is_ok()
        );
        assert!(
            rollup_for(
                "heart-rate",
                "2026-10-08T23:59:59.5Z",
                "2026-10-23T00:00:00Z"
            )
            .is_err()
        );
    }

    #[test]
    fn daily_rollup_range_caps() {
        let mk = |dt: &'static str, start: &'static str, end: &'static str| {
            DailyRollupArgs {
                data_type: dt,
                start_date: start,
                end_date: end,
                window_days: None,
                data_source_family: None,
                page_size: None,
                page_token: None,
            }
            .build()
        };
        assert!(mk("heart-rate", "2026-10-09", "2026-10-23").is_ok());
        let e = err_text(mk("heart-rate", "2026-10-08", "2026-10-23"));
        assert!(
            e.contains("heart-rate")
                && e.contains("15 days")
                && e.contains("14 days")
                && e.contains("split"),
            "{e}"
        );
        assert!(mk("steps", "2026-07-01", "2026-10-23").is_ok());
        assert!(mk("steps", "2026-10-23", "2026-10-23").is_err());
        assert!(mk("steps", "2026-10-24", "2026-10-23").is_err());
        assert!(mk("total-calories", "2026-02-20", "2026-03-06").is_ok());
        assert!(mk("total-calories", "2026-02-20", "2026-03-07").is_err());
    }

    #[test]
    fn daily_rollup_validation() {
        let mk = |dt: &'static str, start: &'static str, days: Option<u32>| DailyRollupArgs {
            data_type: dt,
            start_date: start,
            end_date: "2026-01-09",
            window_days: days,
            data_source_family: Some("all-sources"),
            page_size: Some(10),
            page_token: None,
        };
        assert!(mk("steps", "2026-01-02", Some(0)).build().is_err());
        assert!(mk("steps", "2026-01-02T00:00:00", None).build().is_err());
        assert!(mk("daily-vo2-max", "2026-01-02", None).build().is_err());
        let body = mk("steps", "2026-01-02", Some(7)).build().unwrap().body;
        assert_eq!(body["windowSizeDays"], 7);
        assert_eq!(
            body["dataSourceFamily"],
            "users/me/dataSourceFamilies/all-sources"
        );
        assert_eq!(body["pageSize"], 10);
        assert!(body.get("pageToken").is_none());
    }

    #[test]
    fn list_request_query_encoding_and_defaults() {
        let req = ListArgs {
            data_type: "steps",
            start: Some("2026-01-02"),
            end: Some("2026-01-03"),
            filter: None,
            data_source_family: Some("self-sources"),
            page_size: None,
            page_token: Some("a b"),
            reconcile: false,
        }
        .build()
        .unwrap();
        assert_eq!(req.path, "users/me/dataTypes/steps/dataPoints");
        let url = reqwest::Client::new()
            .get(format!("{BASE}/{}", req.path))
            .query(&req.query)
            .build()
            .unwrap()
            .url()
            .to_string();
        assert!(
            url.contains("filter=steps.interval.civil_start_time+%3E%3D+%222026-01-02%22+AND+"),
            "{url}"
        );
        assert!(
            !url.contains(' ') && !url.contains('"') && !url.contains(">="),
            "{url}"
        );
        assert!(
            url.contains("dataSourceFamily=users%2Fme%2FdataSourceFamilies%2Fself-sources"),
            "{url}"
        );
        assert!(url.contains("pageSize=200"), "{url}");
        assert!(url.contains("pageToken=a+b"), "{url}");
    }

    #[test]
    fn list_request_reconcile_and_gating() {
        let mk = |dt: &'static str, reconcile: bool| {
            ListArgs {
                data_type: dt,
                start: None,
                end: None,
                filter: None,
                data_source_family: None,
                page_size: Some(25),
                page_token: None,
                reconcile,
            }
            .build()
        };
        let r = mk("sleep", true).unwrap();
        assert_eq!(r.path, "users/me/dataTypes/sleep/dataPoints:reconcile");
        assert_eq!(r.query, vec![("pageSize".to_string(), "25".to_string())]);
        let e = err_text(mk("total-calories", false));
        assert!(e.contains("rollup") && e.contains("dailyRollup"), "{e}");
        assert!(mk("skin-temperature-sensors", true).is_err());
        assert!(mk("floors", true).is_ok());
        assert!(mk("nope", false).is_err());
    }

    #[test]
    fn family_expansion_rejects_unknown() {
        assert_eq!(
            expand_family("google-sources").unwrap(),
            "users/me/dataSourceFamilies/google-sources"
        );
        assert!(expand_family("users/me/dataSourceFamilies/all-sources").is_err());
        assert!(expand_family("everything").is_err());
    }

    // --- point names ---

    #[test]
    fn point_id_parsing() {
        assert_eq!(parse_point_id("exercise", "12345").unwrap(), "12345");
        assert_eq!(
            parse_point_id("exercise", "users/me/dataTypes/exercise/dataPoints/987").unwrap(),
            "987"
        );
        assert_eq!(
            parse_point_id("exercise", "users/4242/dataTypes/exercise/dataPoints/987").unwrap(),
            "987"
        );
        assert!(parse_point_id("exercise", "users/me/dataTypes/sleep/dataPoints/987").is_err());
        assert!(parse_point_id("exercise", "12ab").is_err());
        assert!(parse_point_id("exercise", "").is_err());
        assert!(parse_point_id("exercise", "../../etc/passwd").is_err());
        assert!(parse_point_id("exercise", "users/me/dataTypes/exercise/dataPoints/../1").is_err());
        assert!(parse_point_id("exercise", "users/me/dataTypes/exercise/dataPoints/1/x").is_err());
        assert!(parse_point_id("exercise", "users/evil/dataTypes/exercise/dataPoints/1").is_err());
    }

    // --- mappers ---

    fn interval_point(ds: &str, count: &str) -> Value {
        json!({
            "dataSource": {"device": {"displayName": ds}, "platform": "FITBIT"},
            "steps": {
                "interval": {
                    "startTime": "2026-01-02T15:04:00Z",
                    "startUtcOffset": "-18000s",
                    "endTime": "2026-01-02T15:05:00Z",
                    "endUtcOffset": "-18000s",
                    "civilStartTime": {"date": {"year": 2026, "month": 1, "day": 2}, "time": {"hours": 10}},
                    "civilEndTime": {"date": {"year": 2026, "month": 1, "day": 2}, "time": {"hours": 10}}
                },
                "count": count,
                "createTime": "2026-01-02T15:06:00Z",
                "updateTime": "2026-01-02T15:06:00Z"
            }
        })
    }

    #[test]
    fn slim_strips_keys_recursively() {
        let mut p = json!({
            "heartRate": {
                "sampleTime": {
                    "physicalTime": "2026-01-02T15:04:05Z",
                    "utcOffset": "-18000s",
                    "civilTime": {"date": {"year": 2026, "month": 1, "day": 2}, "time": {}}
                },
                "beatsPerMinute": "72"
            },
            "createTime": "x",
            "nested": [{"updateTime": "y", "keep": 1}]
        });
        slim_point(&mut p);
        assert_eq!(
            p,
            json!({
                "heartRate": {
                    "sampleTime": {"physicalTime": "2026-01-02T15:04:05Z", "utcOffset": "-18000s"},
                    "beatsPerMinute": "72"
                },
                "nested": [{"keep": 1}]
            })
        );
    }

    #[test]
    fn dates_flatten_with_zero_padding() {
        let mut p = json!({
            "dailyRestingHeartRate": {"date": {"year": 2026, "month": 1, "day": 2}, "beatsPerMinute": "58"}
        });
        slim_point(&mut p);
        assert_eq!(p["dailyRestingHeartRate"]["date"], "2026-01-02");
        let mut prof =
            json!({"age": 40, "membershipStartDate": {"year": 2020, "month": 11, "day": 5}});
        flatten_dates(&mut prof);
        assert_eq!(prof["membershipStartDate"], "2020-11-05");
        assert_eq!(prof["age"], 40);
    }

    #[test]
    fn data_source_hoisted_when_identical() {
        let body = json!({
            "dataPoints": [interval_point("Charge 6", "87"), interval_point("Charge 6", "12")],
            "nextPageToken": "next"
        });
        let out = map_points("steps", body);
        assert_eq!(out["dataType"], "steps");
        assert_eq!(out["nextPageToken"], "next");
        assert_eq!(out["dataSource"]["platform"], "FITBIT");
        for p in out["dataPoints"].as_array().unwrap() {
            assert!(p.get("dataSource").is_none());
            assert!(p["steps"]["interval"].get("civilStartTime").is_none());
            assert!(p["steps"].get("createTime").is_none());
        }
    }

    #[test]
    fn data_source_kept_when_different_or_missing() {
        let body = json!({"dataPoints": [interval_point("Charge 6", "1"), interval_point("Sense 2", "2")]});
        let out = map_points("steps", body);
        assert!(out.get("dataSource").is_none());
        assert!(out["dataPoints"][0].get("dataSource").is_some());
        assert!(out["dataPoints"][1].get("dataSource").is_some());

        let mut bare = interval_point("Charge 6", "1");
        bare.as_object_mut().unwrap().remove("dataSource");
        let out = map_points(
            "steps",
            json!({"dataPoints": [bare, interval_point("Charge 6", "2")]}),
        );
        assert!(out.get("dataSource").is_none());
    }

    #[test]
    fn empty_body_maps_to_empty_points() {
        assert_eq!(
            map_points("steps", json!({})),
            json!({"dataType": "steps", "dataPoints": []})
        );
        let out = map_points("steps", json!({"dataPoints": [], "nextPageToken": ""}));
        assert!(out.get("nextPageToken").is_none());
    }

    #[test]
    fn daily_rollup_maps_civil_times_to_dates() {
        let body = json!({
            "rollupDataPoints": [
                {
                    "civilStartTime": {"date": {"year": 2026, "month": 1, "day": 2}, "time": {}},
                    "civilEndTime": {"date": {"year": 2026, "month": 1, "day": 3}, "time": {}},
                    "steps": {"countSum": "9000"}
                },
                {
                    "civilStartTime": {"date": {"year": 2026, "month": 1, "day": 3}, "time": {"hours": 6, "minutes": 30}},
                    "civilEndTime": {"date": {"year": 2026, "month": 1, "day": 4}, "time": {"hours": 6, "minutes": 30}},
                    "steps": {"countSum": "100"}
                }
            ],
            "nextPageToken": "n"
        });
        let out = map_rollup("steps", body, true);
        assert_eq!(out["dataType"], "steps");
        assert_eq!(out["nextPageToken"], "n");
        let pts = out["rollupDataPoints"].as_array().unwrap();
        assert_eq!(pts[0]["date"], "2026-01-02");
        assert_eq!(pts[0]["endDate"], "2026-01-03");
        assert_eq!(pts[0]["steps"]["countSum"], "9000");
        assert!(pts[0].get("civilStartTime").is_none());
        assert_eq!(pts[1]["date"], "2026-01-03T06:30:00");
        assert_eq!(pts[1]["endDate"], "2026-01-04T06:30:00");
    }

    #[test]
    fn physical_rollup_passes_through_wrapped() {
        let body = json!({"rollupDataPoints": [{"startTime": "a", "endTime": "b", "steps": {"countSum": "1"}}]});
        let out = map_rollup("steps", body.clone(), false);
        assert_eq!(out["rollupDataPoints"], body["rollupDataPoints"]);
        assert!(out.get("nextPageToken").is_none());
        assert_eq!(
            map_rollup("steps", json!({}), true),
            json!({"dataType": "steps", "rollupDataPoints": []})
        );
    }

    #[test]
    fn paired_devices_drop_mac_address() {
        let out = map_devices(json!({
            "pairedDevices": [{"name": "d1", "batteryLevel": 80, "macAddress": "00:11:22:33:44:55"}],
            "nextPageToken": "t"
        }));
        assert_eq!(out["pairedDevices"][0]["name"], "d1");
        assert!(out["pairedDevices"][0].get("macAddress").is_none());
        assert_eq!(out["nextPageToken"], "t");
        assert_eq!(map_devices(json!({})), json!({"pairedDevices": []}));
    }

    #[test]
    fn api_message_prefers_google_error_message() {
        let body = br#"{"error":{"code":400,"message":"List is not supported for data type total-calories","status":"INVALID_ARGUMENT"}}"#;
        assert_eq!(
            api_message(body),
            "List is not supported for data type total-calories"
        );
        assert_eq!(api_message(b"plain text"), "plain text");
    }
}
