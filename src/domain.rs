//! Workspace domains. `ENABLED_DOMAINS` picks the tool surfaces and OAuth scopes;
//! unset means the default eight, and Health is opt-in (`default,health`).

use std::collections::HashSet;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    Gmail,
    Sheets,
    Drive,
    Docs,
    Calendar,
    Tasks,
    People,
    SearchConsole,
    Health,
}

impl Domain {
    pub const ALL: [Domain; 8] = [
        Domain::Gmail,
        Domain::Sheets,
        Domain::Drive,
        Domain::Docs,
        Domain::Calendar,
        Domain::Tasks,
        Domain::People,
        Domain::SearchConsole,
    ];

    /// Domains that load only when named in `ENABLED_DOMAINS`.
    #[cfg(test)]
    pub const OPT_IN: [Domain; 1] = [Domain::Health];

    pub fn as_str(&self) -> &'static str {
        match self {
            Domain::Gmail => "gmail",
            Domain::Sheets => "sheets",
            Domain::Drive => "drive",
            Domain::Docs => "docs",
            Domain::Calendar => "calendar",
            Domain::Tasks => "tasks",
            Domain::People => "people",
            Domain::SearchConsole => "searchconsole",
            Domain::Health => "health",
        }
    }

    /// Human-readable name shown on the consent screen.
    pub fn human_name(&self) -> &'static str {
        match self {
            Domain::Gmail => "Gmail",
            Domain::Sheets => "Google Sheets",
            Domain::Drive => "Google Drive",
            Domain::Docs => "Google Docs",
            Domain::Calendar => "Google Calendar",
            Domain::Tasks => "Google Tasks",
            Domain::People => "Contacts",
            Domain::SearchConsole => "Search Console",
            Domain::Health => "Google Health",
        }
    }

    /// The Google OAuth scopes this domain requires.
    pub fn google_scopes(&self) -> &'static [&'static str] {
        match self {
            Domain::Gmail => &[
                "https://www.googleapis.com/auth/gmail.modify",
                "https://www.googleapis.com/auth/gmail.settings.basic",
            ],
            Domain::Sheets => &["https://www.googleapis.com/auth/spreadsheets"],
            Domain::Drive => &["https://www.googleapis.com/auth/drive"],
            Domain::Docs => &["https://www.googleapis.com/auth/documents"],
            Domain::Calendar => &["https://www.googleapis.com/auth/calendar"],
            Domain::Tasks => &["https://www.googleapis.com/auth/tasks"],
            Domain::People => &["https://www.googleapis.com/auth/contacts"],
            Domain::SearchConsole => &["https://www.googleapis.com/auth/webmasters"],
            Domain::Health => &[
                "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",
                "https://www.googleapis.com/auth/googlehealth.sleep.readonly",
                "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",
                "https://www.googleapis.com/auth/googlehealth.nutrition.readonly",
                "https://www.googleapis.com/auth/googlehealth.ecg.readonly",
                "https://www.googleapis.com/auth/googlehealth.irn.readonly",
                "https://www.googleapis.com/auth/googlehealth.profile.readonly",
                "https://www.googleapis.com/auth/googlehealth.settings.readonly",
                "https://www.googleapis.com/auth/googlehealth.location.readonly",
            ],
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
            "tasks" => Ok(Domain::Tasks),
            "people" | "contacts" => Ok(Domain::People),
            "searchconsole" | "search_console" | "search-console" | "webmasters" => {
                Ok(Domain::SearchConsole)
            }
            "health" | "fitbit" => Ok(Domain::Health),
            other => Err(format!(
                "unknown domain '{other}': expected one of gmail, sheets, drive, docs, calendar, tasks, people, searchconsole, health"
            )),
        }
    }
}

/// Parse an `ENABLED_DOMAINS` value (comma-separated, case-insensitive). Empty
/// input is `Domain::ALL`; `default` expands to it in place. First occurrence wins.
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
        if piece.eq_ignore_ascii_case("default") {
            for d in Domain::ALL {
                if seen.insert(d) {
                    out.push(d);
                }
            }
            continue;
        }
        let d: Domain = piece
            .parse()
            .map_err(|e| format!("{e} (or `default` for the standard eight)"))?;
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
        s.extend(
            d.google_scopes()
                .iter()
                .map(std::string::ToString::to_string),
        );
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
        assert_eq!(parse_enabled(Some("tasks")).unwrap(), vec![Domain::Tasks]);
        assert_eq!(parse_enabled(Some("people")).unwrap(), vec![Domain::People]);
        assert_eq!(
            parse_enabled(Some("searchconsole")).unwrap(),
            vec![Domain::SearchConsole]
        );
    }

    #[test]
    fn search_console_accepts_aliases() {
        for alias in [
            "search_console",
            "search-console",
            "webmasters",
            "SearchConsole",
        ] {
            assert_eq!(
                parse_enabled(Some(alias)).unwrap(),
                vec![Domain::SearchConsole],
                "{alias}"
            );
        }
    }

    #[test]
    fn contacts_is_an_alias_for_people() {
        assert_eq!(
            parse_enabled(Some("contacts")).unwrap(),
            vec![Domain::People]
        );
        assert_eq!(
            parse_enabled(Some("CONTACTS")).unwrap(),
            vec![Domain::People]
        );
    }

    #[test]
    fn google_scope_per_domain_is_exact() {
        assert_eq!(
            Domain::Gmail.google_scopes(),
            &[
                "https://www.googleapis.com/auth/gmail.modify",
                "https://www.googleapis.com/auth/gmail.settings.basic",
            ]
        );
        assert_eq!(
            Domain::Sheets.google_scopes(),
            &["https://www.googleapis.com/auth/spreadsheets"]
        );
        assert_eq!(
            Domain::Drive.google_scopes(),
            &["https://www.googleapis.com/auth/drive"]
        );
        assert_eq!(
            Domain::Docs.google_scopes(),
            &["https://www.googleapis.com/auth/documents"]
        );
        assert_eq!(
            Domain::Calendar.google_scopes(),
            &["https://www.googleapis.com/auth/calendar"]
        );
        assert_eq!(
            Domain::Tasks.google_scopes(),
            &["https://www.googleapis.com/auth/tasks"]
        );
        assert_eq!(
            Domain::People.google_scopes(),
            &["https://www.googleapis.com/auth/contacts"]
        );
        assert_eq!(
            Domain::SearchConsole.google_scopes(),
            &["https://www.googleapis.com/auth/webmasters"]
        );
    }

    #[test]
    fn google_scopes_for_each_single_domain() {
        for d in Domain::ALL.into_iter().chain(Domain::OPT_IN) {
            let s = google_scopes(&[d]);
            assert_eq!(
                s.len(),
                2 + d.google_scopes().len(),
                "{d}: should produce exactly openid+email+its own scopes"
            );
            assert!(s.contains(&"openid".to_string()), "{d}: missing openid");
            assert!(s.contains(&"email".to_string()), "{d}: missing email");
            for scope in d.google_scopes() {
                assert!(s.contains(&scope.to_string()), "{d}: missing scope {scope}");
            }
        }
    }

    #[test]
    fn as_str_round_trips_through_parse() {
        for d in Domain::ALL.into_iter().chain(Domain::OPT_IN) {
            let parsed: Domain = d.as_str().parse().unwrap();
            assert_eq!(parsed, d, "{d} should round-trip through as_str/parse");
        }
    }

    #[test]
    fn health_and_fitbit_parse_and_are_opt_in() {
        assert_eq!(parse_enabled(Some("health")).unwrap(), vec![Domain::Health]);
        assert_eq!(parse_enabled(Some("Fitbit")).unwrap(), vec![Domain::Health]);
        assert!(!Domain::ALL.contains(&Domain::Health));
        assert!(!parse_enabled(None).unwrap().contains(&Domain::Health));
        assert_eq!(Domain::OPT_IN, [Domain::Health]);
        assert_eq!(Domain::Health.human_name(), "Google Health");
    }

    #[test]
    fn default_token_expands_in_place() {
        let mut want = Domain::ALL.to_vec();
        want.push(Domain::Health);
        assert_eq!(parse_enabled(Some("default,health")).unwrap(), want);
        assert_eq!(parse_enabled(Some(" DEFAULT , health ")).unwrap(), want);
        assert_eq!(
            parse_enabled(Some("default")).unwrap(),
            Domain::ALL.to_vec()
        );
        assert_eq!(
            parse_enabled(Some("health,default,gmail")).unwrap()[..2],
            [Domain::Health, Domain::Gmail]
        );
    }

    #[test]
    fn health_scopes_are_exactly_the_nine_readonly() {
        let base = "https://www.googleapis.com/auth/googlehealth.";
        let want: Vec<String> = [
            "activity_and_fitness",
            "sleep",
            "health_metrics_and_measurements",
            "nutrition",
            "ecg",
            "irn",
            "profile",
            "settings",
            "location",
        ]
        .iter()
        .map(|n| format!("{base}{n}.readonly"))
        .collect();
        let got: Vec<String> = Domain::Health
            .google_scopes()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(got, want);
        assert_eq!(google_scopes(&[Domain::Health]).len(), 11);
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
        assert!(err.contains("health") && err.contains("default"));
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
        assert!(s.iter().any(|x| x.contains("gmail.settings.basic")));
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn google_scopes_for_all_returns_full_set() {
        let s = google_scopes(&Domain::ALL);
        assert_eq!(s.len(), 11);
        for needle in [
            "gmail.modify",
            "gmail.settings.basic",
            "spreadsheets",
            "/drive",
            "documents",
            "auth/calendar",
            "auth/tasks",
            "auth/contacts",
            "auth/webmasters",
        ] {
            assert!(
                s.iter().any(|x| x.contains(needle)),
                "missing scope substring: {needle}"
            );
        }
    }
}
