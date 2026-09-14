//! Google Search Console tools. Separate `#[tool_router(router = searchconsole_router)]`
//! impl block, composed in `mcp/server.rs`'s constructor via `ToolRouter::Add`.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::errors::{McpError, to_mcp};
use crate::google::searchconsole::{SearchConsoleClient, SearchConsoleError};
use crate::mcp::calendar_tools::EmptyParams;
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

#[tool_router(router = searchconsole_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "searchconsole_list_sites",
        description = "List the Search Console properties this account can access. Returns `{ siteEntry: [{siteUrl, permissionLevel}] }`. Pass `siteUrl` verbatim as `site_url` to every other searchconsole_* tool. `permissionLevel` is one of siteOwner, siteFullUser, siteRestrictedUser, siteUnverifiedUser."
    )]
    async fn searchconsole_list_sites(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(_): Parameters<EmptyParams>,
    ) -> Result<String, ErrorData> {
        let client = self.searchconsole_for(&parts).await?;
        client
            .list_sites()
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "searchconsole_get_site",
        description = "Get one property's `siteUrl` and `permissionLevel`."
    )]
    async fn searchconsole_get_site(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SearchConsoleSiteUrlParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.site_url, "site_url")?;
        let client = self.searchconsole_for(&parts).await?;
        client
            .get_site(&p.site_url)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_searchconsole_not_found(e, "site", &p.site_url))
    }

    #[tool(
        name = "searchconsole_list_sitemaps",
        description = "List the sitemaps submitted for a property. Returns `{ sitemap: [{path, lastSubmitted, lastDownloaded, isPending, isSitemapsIndex, type, warnings, errors, contents: [{type, submitted, indexed}]}] }`."
    )]
    async fn searchconsole_list_sitemaps(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SearchConsoleListSitemapsParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.site_url, "site_url")?;
        let client = self.searchconsole_for(&parts).await?;
        client
            .list_sitemaps(&p.site_url, p.sitemap_index.as_deref())
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_searchconsole_not_found(e, "site", &p.site_url))
    }

    #[tool(
        name = "searchconsole_get_sitemap",
        description = "Get one submitted sitemap's status, warnings, errors and per-type submitted/indexed counts."
    )]
    async fn searchconsole_get_sitemap(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SearchConsoleSitemapParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.site_url, "site_url")?;
        ensure_non_empty(&p.feedpath, "feedpath")?;
        let client = self.searchconsole_for(&parts).await?;
        client
            .get_sitemap(&p.site_url, &p.feedpath)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_searchconsole_not_found(e, "sitemap", &p.feedpath))
    }

    #[tool(
        name = "searchconsole_submit_sitemap",
        description = "Submit a sitemap URL to a property, or resubmit an existing one to ask Google to fetch it again. Needs owner or full-user permission on the property. Returns `{ submitted: feedpath }`."
    )]
    async fn searchconsole_submit_sitemap(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SearchConsoleSitemapParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.site_url, "site_url")?;
        ensure_non_empty(&p.feedpath, "feedpath")?;
        let client = self.searchconsole_for(&parts).await?;
        client
            .submit_sitemap(&p.site_url, &p.feedpath)
            .await
            .map(|_| json!({"submitted": p.feedpath}).to_string())
            .map_err(|e| reclassify_searchconsole_not_found(e, "sitemap", &p.feedpath))
    }

    #[tool(
        name = "searchconsole_delete_sitemap",
        description = "Remove a sitemap from a property. Google stops using it immediately and there is no undo; resubmit it with `searchconsole_submit_sitemap` to add it back. Returns `{ deleted: feedpath }`."
    )]
    async fn searchconsole_delete_sitemap(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SearchConsoleSitemapParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.site_url, "site_url")?;
        ensure_non_empty(&p.feedpath, "feedpath")?;
        let client = self.searchconsole_for(&parts).await?;
        let feedpath = p.feedpath.clone();
        client
            .delete_sitemap(&p.site_url, &p.feedpath)
            .await
            .map(|_| json!({"deleted": feedpath}).to_string())
            .map_err(|e| reclassify_searchconsole_not_found(e, "sitemap", &p.feedpath))
    }

    #[tool(
        name = "searchconsole_query_analytics",
        description = "Query search performance (clicks, impressions, ctr, position) for a property over an inclusive date range, grouped by `dimensions`. Returns `{ rows: [{keys, clicks, impressions, ctr, position}], responseAggregationType }`; `keys` follow the order of `dimensions`. Use `filters` to narrow to one page, query, country or device. `data_state=final` (default) excludes the most recent days that are still being finalized. Max 25000 rows per call; page with `start_row`."
    )]
    async fn searchconsole_query_analytics(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SearchConsoleQueryParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.site_url, "site_url")?;
        ensure_date(&p.start_date, "start_date")?;
        ensure_date(&p.end_date, "end_date")?;
        if let Some(dims) = &p.dimensions {
            for d in dims {
                ensure_one_of(d, "dimensions", DIMENSIONS)?;
            }
        }
        if let Some(t) = &p.search_type {
            ensure_one_of(t, "search_type", SEARCH_TYPES)?;
        }
        if let Some(filters) = &p.filters {
            for f in filters {
                ensure_one_of(&f.dimension, "filters.dimension", FILTER_DIMENSIONS)?;
                if let Some(op) = &f.operator {
                    ensure_one_of(op, "filters.operator", OPERATORS)?;
                }
            }
        }
        if let Some(a) = &p.aggregation_type {
            ensure_one_of(a, "aggregation_type", AGGREGATIONS)?;
        }
        if let Some(s) = &p.data_state {
            ensure_one_of(s, "data_state", DATA_STATES)?;
        }
        if let Some(limit) = p.row_limit
            && !(1..=25000).contains(&limit)
        {
            return Err(McpError::invalid_input("`row_limit` out of range")
                .with_hint("`row_limit` must be between 1 and 25000.")
                .with_service("searchconsole")
                .into());
        }

        let mut body = json!({"startDate": p.start_date, "endDate": p.end_date});
        if let Some(dims) = &p.dimensions
            && !dims.is_empty()
        {
            body["dimensions"] = json!(dims);
        }
        if let Some(t) = &p.search_type {
            body["type"] = json!(t);
        }
        if let Some(filters) = &p.filters
            && !filters.is_empty()
        {
            let filters: Vec<Value> = filters
                .iter()
                .map(|f| {
                    json!({
                        "dimension": f.dimension,
                        "operator": f.operator.as_deref().unwrap_or("equals"),
                        "expression": f.expression,
                    })
                })
                .collect();
            body["dimensionFilterGroups"] = json!([{"groupType": "and", "filters": filters}]);
        }
        if let Some(a) = &p.aggregation_type {
            body["aggregationType"] = json!(a);
        }
        if let Some(r) = p.row_limit {
            body["rowLimit"] = json!(r);
        }
        if let Some(s) = p.start_row {
            body["startRow"] = json!(s);
        }
        if let Some(s) = &p.data_state {
            body["dataState"] = json!(s);
        }

        let client = self.searchconsole_for(&parts).await?;
        client
            .query_search_analytics(&p.site_url, &body)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_searchconsole_not_found(e, "site", &p.site_url))
    }

    #[tool(
        name = "searchconsole_inspect_url",
        description = "Inspect one URL's Google index status: verdict, coverage state, last crawl time, Google-selected canonical, robots and indexing state, plus rich results when present. Returns `{ inspectionResult: {inspectionResultLink, indexStatusResult, richResultsResult, ...} }`. `inspection_url` must belong to `site_url`."
    )]
    async fn searchconsole_inspect_url(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<SearchConsoleInspectUrlParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.site_url, "site_url")?;
        ensure_non_empty(&p.inspection_url, "inspection_url")?;
        let mut body = json!({"inspectionUrl": p.inspection_url, "siteUrl": p.site_url});
        if let Some(l) = &p.language_code {
            body["languageCode"] = json!(l);
        }
        let client = self.searchconsole_for(&parts).await?;
        client
            .inspect_url(&body)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_searchconsole_not_found(e, "url", &p.inspection_url))
    }
}

impl GoogleMcp {
    pub(crate) async fn searchconsole_for(
        &self,
        parts: &Parts,
    ) -> Result<SearchConsoleClient, ErrorData> {
        let session = self.resolve_session(parts).await?;
        Ok(SearchConsoleClient::new(
            (*self.state.http).clone(),
            session.access_token,
        ))
    }
}

fn reclassify_searchconsole_not_found(
    e: SearchConsoleError,
    kind: &'static str,
    id: &str,
) -> ErrorData {
    if let SearchConsoleError::Api { status, .. } = &e
        && status.as_u16() == 404
    {
        return McpError::not_found(kind, id, "searchconsole").into();
    }
    to_mcp(e)
}

fn ensure_non_empty(s: &str, field: &str) -> Result<(), ErrorData> {
    if s.trim().is_empty() {
        return Err(
            McpError::invalid_input(format!("`{field}` must not be empty"))
                .with_service("searchconsole")
                .into(),
        );
    }
    Ok(())
}

fn ensure_date(s: &str, field: &str) -> Result<(), ErrorData> {
    let valid = s.len() == 10
        && s.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            _ => b.is_ascii_digit(),
        });
    if !valid {
        return Err(
            McpError::invalid_input(format!("`{field}` is not a valid date"))
                .with_hint("Use `YYYY-MM-DD`.")
                .with_service("searchconsole")
                .into(),
        );
    }
    Ok(())
}

fn ensure_one_of(value: &str, field: &str, allowed: &[&str]) -> Result<(), ErrorData> {
    if !allowed.contains(&value) {
        return Err(
            McpError::invalid_input(format!("unknown `{field}` value '{value}'"))
                .with_hint(format!("Allowed values: {}.", allowed.join(", ")))
                .with_service("searchconsole")
                .into(),
        );
    }
    Ok(())
}

const FILTER_DIMENSIONS: &[&str] = &["country", "device", "page", "query", "searchAppearance"];
const DIMENSIONS: &[&str] = &[
    "country",
    "device",
    "page",
    "query",
    "searchAppearance",
    "date",
    "hour",
];
const SEARCH_TYPES: &[&str] = &["web", "image", "video", "news", "discover", "googleNews"];
const OPERATORS: &[&str] = &[
    "equals",
    "notEquals",
    "contains",
    "notContains",
    "includingRegex",
    "excludingRegex",
];
const AGGREGATIONS: &[&str] = &["auto", "byPage", "byProperty", "byNewsShowcasePanel"];
const DATA_STATES: &[&str] = &["final", "all", "hourly_all"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_date_accepts_only_iso_dates() {
        assert!(ensure_date("2026-09-01", "start_date").is_ok());
        for bad in [
            "2026-9-1",
            "20260901",
            "2026/09/01",
            "2026-09-01T00:00:00Z",
            "",
        ] {
            assert!(ensure_date(bad, "start_date").is_err(), "{bad}");
        }
    }

    #[test]
    fn ensure_one_of_lists_allowed_values_in_hint() {
        assert!(ensure_one_of("web", "search_type", SEARCH_TYPES).is_ok());
        let err = ensure_one_of("bogus", "search_type", SEARCH_TYPES).unwrap_err();
        let data = err.data.expect("structured error data");
        assert!(data["hint"].as_str().unwrap().contains("googleNews"));
    }
}
