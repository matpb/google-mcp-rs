//! Workspace domains the server can serve. The `ENABLED_DOMAINS` env var
//! controls which tool surfaces load (saving agent context tokens) and
//! which OAuth scopes are requested from Google (so the consent screen
//! doesn't ask for permissions the operator never intends to use).
//!
//! Unset or empty `ENABLED_DOMAINS` means all five domains, which is the
//! historical behavior and remains the default.

use std::collections::HashSet;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    Gmail,
    Sheets,
    Drive,
    Docs,
    Calendar,
}

impl Domain {
    pub const ALL: [Domain; 5] = [
        Domain::Gmail,
        Domain::Sheets,
        Domain::Drive,
        Domain::Docs,
        Domain::Calendar,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Domain::Gmail => "gmail",
            Domain::Sheets => "sheets",
            Domain::Drive => "drive",
            Domain::Docs => "docs",
            Domain::Calendar => "calendar",
        }
    }

    /// The Google OAuth scope this domain requires.
    pub fn google_scope(&self) -> &'static str {
        match self {
            Domain::Gmail => "https://www.googleapis.com/auth/gmail.modify",
            Domain::Sheets => "https://www.googleapis.com/auth/spreadsheets",
            Domain::Drive => "https://www.googleapis.com/auth/drive",
            Domain::Docs => "https://www.googleapis.com/auth/documents",
            Domain::Calendar => "https://www.googleapis.com/auth/calendar",
        }
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Domain {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "gmail" => Ok(Domain::Gmail),
            "sheets" => Ok(Domain::Sheets),
            "drive" => Ok(Domain::Drive),
            "docs" => Ok(Domain::Docs),
            "calendar" => Ok(Domain::Calendar),
            other => Err(format!(
                "unknown domain '{other}': expected one of gmail, sheets, drive, docs, calendar"
            )),
        }
    }
}

/// Parse an `ENABLED_DOMAINS` env-var value (comma-separated,
/// case-insensitive, whitespace-trimmed). Empty or missing input
/// returns `Domain::ALL`. Duplicates are deduplicated; first occurrence
/// wins for ordering.
pub fn parse_enabled(raw: Option<&str>) -> Result<Vec<Domain>, String> {
    let trimmed = raw.map(str::trim).filter(|s| !s.is_empty());
    let Some(s) = trimmed else {
        return Ok(Domain::ALL.to_vec());
    };
    let mut seen: HashSet<Domain> = HashSet::new();
    let mut out: Vec<Domain> = Vec::new();
    for piece in s.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let d: Domain = piece.parse()?;
        if seen.insert(d) {
            out.push(d);
        }
    }
    if out.is_empty() {
        return Err("ENABLED_DOMAINS parsed to zero domains".into());
    }
    Ok(out)
}

/// Build the full Google OAuth scope list for a given domain set. Always
/// includes `openid` and `email` so the ID token can identify the user.
pub fn google_scopes(domains: &[Domain]) -> Vec<String> {
    let mut s: Vec<String> = vec!["openid".to_string(), "email".to_string()];
    for d in domains {
        s.push(d.google_scope().to_string());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_means_all() {
        assert_eq!(parse_enabled(None).unwrap(), Domain::ALL.to_vec());
        assert_eq!(parse_enabled(Some("")).unwrap(), Domain::ALL.to_vec());
        assert_eq!(parse_enabled(Some("   ")).unwrap(), Domain::ALL.to_vec());
    }

    #[test]
    fn parses_each_domain_individually() {
        assert_eq!(parse_enabled(Some("gmail")).unwrap(), vec![Domain::Gmail]);
        assert_eq!(parse_enabled(Some("sheets")).unwrap(), vec![Domain::Sheets]);
        assert_eq!(parse_enabled(Some("drive")).unwrap(), vec![Domain::Drive]);
        assert_eq!(parse_enabled(Some("docs")).unwrap(), vec![Domain::Docs]);
        assert_eq!(
            parse_enabled(Some("calendar")).unwrap(),
            vec![Domain::Calendar]
        );
    }

    #[test]
    fn google_scope_per_domain_is_exact() {
        assert_eq!(
            Domain::Gmail.google_scope(),
            "https://www.googleapis.com/auth/gmail.modify"
        );
        assert_eq!(
            Domain::Sheets.google_scope(),
            "https://www.googleapis.com/auth/spreadsheets"
        );
        assert_eq!(
            Domain::Drive.google_scope(),
            "https://www.googleapis.com/auth/drive"
        );
        assert_eq!(
            Domain::Docs.google_scope(),
            "https://www.googleapis.com/auth/documents"
        );
        assert_eq!(
            Domain::Calendar.google_scope(),
            "https://www.googleapis.com/auth/calendar"
        );
    }

    #[test]
    fn google_scopes_for_each_single_domain() {
        for d in Domain::ALL {
            let s = google_scopes(&[d]);
            assert_eq!(s.len(), 3, "{d}: should produce exactly openid+email+1");
            assert!(s.contains(&"openid".to_string()), "{d}: missing openid");
            assert!(s.contains(&"email".to_string()), "{d}: missing email");
            assert!(
                s.contains(&d.google_scope().to_string()),
                "{d}: missing its own google_scope"
            );
        }
    }

    #[test]
    fn as_str_round_trips_through_parse() {
        for d in Domain::ALL {
            let parsed: Domain = d.as_str().parse().unwrap();
            assert_eq!(parsed, d, "{d} should round-trip through as_str/parse");
        }
    }

    #[test]
    fn parses_multiple_domains_preserves_first_occurrence_order() {
        assert_eq!(
            parse_enabled(Some("calendar,gmail,docs")).unwrap(),
            vec![Domain::Calendar, Domain::Gmail, Domain::Docs]
        );
    }

    #[test]
    fn case_insensitive_and_trims_whitespace() {
        assert_eq!(
            parse_enabled(Some("GMAIL,  Drive ,docs")).unwrap(),
            vec![Domain::Gmail, Domain::Drive, Domain::Docs]
        );
    }

    #[test]
    fn deduplicates() {
        assert_eq!(
            parse_enabled(Some("gmail,gmail,GMAIL")).unwrap(),
            vec![Domain::Gmail]
        );
    }

    #[test]
    fn rejects_unknown_with_helpful_message() {
        let err = parse_enabled(Some("gmail,bogus")).unwrap_err();
        assert!(err.contains("bogus"));
        assert!(err.contains("expected one of"));
    }

    #[test]
    fn rejects_only_commas() {
        // Empty pieces are skipped; if everything is empty we error.
        assert!(parse_enabled(Some(",,,")).is_err());
    }

    #[test]
    fn google_scopes_always_includes_openid_and_email() {
        let s = google_scopes(&[Domain::Gmail]);
        assert!(s.contains(&"openid".to_string()));
        assert!(s.contains(&"email".to_string()));
        assert!(s.iter().any(|x| x.contains("gmail.modify")));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn google_scopes_for_all_returns_full_set() {
        let s = google_scopes(&Domain::ALL);
        assert_eq!(s.len(), 7);
        for needle in [
            "gmail.modify",
            "spreadsheets",
            "/drive",
            "documents",
            "calendar",
        ] {
            assert!(
                s.iter().any(|x| x.contains(needle)),
                "missing scope substring: {needle}"
            );
        }
    }
}
