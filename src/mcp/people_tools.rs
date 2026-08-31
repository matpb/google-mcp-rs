//! Google People (Contacts) tools. Separate `#[tool_router(router = people_router)]`
//! impl block — composed in `mcp/server.rs`'s constructor via `ToolRouter::Add`.

use http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use serde_json::{Value, json};

use crate::errors::{McpError, to_mcp};
use crate::google::people::{
    DEFAULT_PERSON_FIELDS, PeopleClient, PeopleError, group_resource_name, person_resource_name,
};
use crate::mcp::params::*;
use crate::mcp::server::GoogleMcp;

#[tool_router(router = people_router, vis = "pub(crate)")]
impl GoogleMcp {
    #[tool(
        name = "people_list_contacts",
        description = "List the user's saved contacts (People `connections`). Returns `{ connections: [...], nextPageToken, totalPeople }`. Each entry's `resourceName` (`people/c123...`) is what the other people_* tools take. Page through with `page_token`; this is the complete address book, so prefer people_search_contacts when looking for someone specific."
    )]
    async fn people_list_contacts(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleListContactsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.people_for(&parts).await?;
        let fields = p.person_fields.as_deref().unwrap_or(DEFAULT_PERSON_FIELDS);
        client
            .list_connections(
                fields,
                p.page_size,
                p.page_token.as_deref(),
                p.sort_order.as_deref(),
            )
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "people_get_contact",
        description = "Get one contact by resource name (`people/c123...`) or bare ID. Returns the full Person resource including its `etag`, which people_update_contact needs."
    )]
    async fn people_get_contact(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleGetContactParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.resource_name, "resource_name")?;
        let client = self.people_for(&parts).await?;
        let name = person_resource_name(&p.resource_name);
        let fields = p.person_fields.as_deref().unwrap_or(DEFAULT_PERSON_FIELDS);
        client
            .get_person(&name, fields)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_people_not_found(e, "contact", &name))
    }

    #[tool(
        name = "people_batch_get_contacts",
        description = "Get up to 200 contacts in one call by resource name or bare ID. Returns `{ responses: [{ httpStatusCode, person }, ...] }` — check each entry, a bad ID fails only its own slot."
    )]
    async fn people_batch_get_contacts(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleBatchGetContactsParams>,
    ) -> Result<String, ErrorData> {
        if p.resource_names.is_empty() {
            return Err(
                McpError::invalid_input("`resource_names` must not be empty")
                    .with_service("people")
                    .into(),
            );
        }
        if p.resource_names.len() > 200 {
            return Err(McpError::invalid_input(format!(
                "`resource_names` has {} entries; People allows at most 200 per call",
                p.resource_names.len()
            ))
            .with_service("people")
            .into());
        }
        let client = self.people_for(&parts).await?;
        let names: Vec<String> = p
            .resource_names
            .iter()
            .map(|r| person_resource_name(r))
            .collect();
        let fields = p.person_fields.as_deref().unwrap_or(DEFAULT_PERSON_FIELDS);
        client
            .batch_get(&names, fields)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "people_search_contacts",
        description = "Search the user's contacts by name, nickname, email, phone or organization. Matching is prefix-based, so `jos` finds Joseph but `seph` does not. Returns `{ results: [{ person }, ...] }`. This is the cheap way to resolve a person to a `resourceName` before reading or editing them."
    )]
    async fn people_search_contacts(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleSearchContactsParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.query, "query")?;
        let client = self.people_for(&parts).await?;
        let fields = p.person_fields.as_deref().unwrap_or(DEFAULT_PERSON_FIELDS);
        client
            .search_contacts(&p.query, fields, p.page_size)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "people_create_contact",
        description = "Create a contact. Supply the convenience fields (`given_name`, `family_name`, `emails`, `phones`, `organization`, `job_title`, `notes`, `birthday`, `addresses`, `urls`), or pass a raw People `Person` resource as `person` to set anything this tool does not model. Returns the created Person including its `resourceName`."
    )]
    async fn people_create_contact(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleCreateContactParams>,
    ) -> Result<String, ErrorData> {
        let (body, _) = build_person(&p.fields)?;
        if body.as_object().is_none_or(|o| o.is_empty()) {
            return Err(McpError::invalid_input("no contact fields supplied")
                .with_hint("Set at least one of given_name, family_name, emails, phones, organization, notes, or pass a raw `person`.")
                .with_service("people")
                .into());
        }
        let client = self.people_for(&parts).await?;
        client
            .create_contact(&body)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "people_update_contact",
        description = "Update a contact. Each field group you supply REPLACES the existing one wholesale — passing `emails` replaces every address, it does not append, so read the contact first if you mean to add. `etag` and `update_person_fields` are fetched and derived automatically when omitted."
    )]
    async fn people_update_contact(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleUpdateContactParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.resource_name, "resource_name")?;
        let (mut body, derived) = build_person(&p.fields)?;
        let mask = match p.update_person_fields.as_deref() {
            Some(m) if !m.trim().is_empty() => m.trim().to_string(),
            _ => derived,
        };
        if mask.is_empty() {
            return Err(McpError::invalid_input("no contact fields supplied")
                .with_hint("Set at least one updatable field, or pass `update_person_fields` explicitly alongside a raw `person`.")
                .with_service("people")
                .into());
        }

        let client = self.people_for(&parts).await?;
        let name = person_resource_name(&p.resource_name);

        let etag = match p.etag {
            Some(e) if !e.trim().is_empty() => e,
            _ => {
                let current = client
                    .get_person(&name, "metadata")
                    .await
                    .map_err(|e| reclassify_people_not_found(e, "contact", &name))?;
                current
                    .get("etag")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        ErrorData::from(
                            McpError::internal("contact returned no etag").with_service("people"),
                        )
                    })?
            }
        };
        body["etag"] = json!(etag);

        client
            .update_contact(&name, &body, &mask, DEFAULT_PERSON_FIELDS)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_people_not_found(e, "contact", &name))
    }

    #[tool(
        name = "people_delete_contact",
        description = "**Irreversibly** delete a contact. There is no trash for People — the contact is gone."
    )]
    async fn people_delete_contact(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleDeleteContactParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.resource_name, "resource_name")?;
        let client = self.people_for(&parts).await?;
        let name = person_resource_name(&p.resource_name);
        client
            .delete_contact(&name)
            .await
            .map(|_| json!({"deleted": name}).to_string())
            .map_err(|e| reclassify_people_not_found(e, "contact", &name))
    }

    #[tool(
        name = "people_list_contact_groups",
        description = "List contact groups (the labels in the Contacts UI). Includes system groups like `contactGroups/myContacts` and `contactGroups/starred` alongside user-created ones."
    )]
    async fn people_list_contact_groups(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleListContactGroupsParams>,
    ) -> Result<String, ErrorData> {
        let client = self.people_for(&parts).await?;
        client
            .list_contact_groups(p.page_size, p.page_token.as_deref())
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "people_get_contact_group",
        description = "Get one contact group. Set `max_members` above 0 to also return its members' contact resource names."
    )]
    async fn people_get_contact_group(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleGetContactGroupParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.resource_name, "resource_name")?;
        let client = self.people_for(&parts).await?;
        let name = group_resource_name(&p.resource_name);
        client
            .get_contact_group(&name, p.max_members)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_people_not_found(e, "contact group", &name))
    }

    #[tool(
        name = "people_create_contact_group",
        description = "Create a contact group (label). Returns the new group including its `resourceName`."
    )]
    async fn people_create_contact_group(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleCreateContactGroupParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.name, "name")?;
        let client = self.people_for(&parts).await?;
        client
            .create_contact_group(&p.name)
            .await
            .map(|v| v.to_string())
            .map_err(to_mcp)
    }

    #[tool(
        name = "people_update_contact_group",
        description = "Rename a user-created contact group. System groups (`myContacts`, `starred`, ...) cannot be renamed. `etag` is fetched automatically when omitted."
    )]
    async fn people_update_contact_group(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleUpdateContactGroupParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.resource_name, "resource_name")?;
        ensure_non_empty(&p.name, "name")?;
        let client = self.people_for(&parts).await?;
        let name = group_resource_name(&p.resource_name);

        let etag = match p.etag {
            Some(e) if !e.trim().is_empty() => Some(e),
            _ => {
                let current = client
                    .get_contact_group(&name, Some(0))
                    .await
                    .map_err(|e| reclassify_people_not_found(e, "contact group", &name))?;
                current
                    .get("etag")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }
        };

        client
            .update_contact_group(&name, &p.name, etag.as_deref())
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_people_not_found(e, "contact group", &name))
    }

    #[tool(
        name = "people_delete_contact_group",
        description = "Delete a user-created contact group. By default the contacts survive and only lose the label; set `delete_contacts=true` to **irreversibly** delete every contact in it too."
    )]
    async fn people_delete_contact_group(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleDeleteContactGroupParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.resource_name, "resource_name")?;
        let client = self.people_for(&parts).await?;
        let name = group_resource_name(&p.resource_name);
        client
            .delete_contact_group(&name, p.delete_contacts)
            .await
            .map(|_| json!({"deleted": name, "deletedContacts": p.delete_contacts}).to_string())
            .map_err(|e| reclassify_people_not_found(e, "contact group", &name))
    }

    #[tool(
        name = "people_modify_contact_group_members",
        description = "Add or remove contacts from a group (apply or strip a label). Pass contact resource names or bare IDs in `add` / `remove`, max 1000 per call."
    )]
    async fn people_modify_contact_group_members(
        &self,
        Extension(parts): Extension<Parts>,
        Parameters(p): Parameters<PeopleModifyContactGroupMembersParams>,
    ) -> Result<String, ErrorData> {
        ensure_non_empty(&p.resource_name, "resource_name")?;
        if p.add.is_empty() && p.remove.is_empty() {
            return Err(
                McpError::invalid_input("supply at least one of `add` or `remove`")
                    .with_service("people")
                    .into(),
            );
        }
        let client = self.people_for(&parts).await?;
        let name = group_resource_name(&p.resource_name);
        let add: Vec<String> = p.add.iter().map(|r| person_resource_name(r)).collect();
        let remove: Vec<String> = p.remove.iter().map(|r| person_resource_name(r)).collect();
        client
            .modify_group_members(&name, &add, &remove)
            .await
            .map(|v| v.to_string())
            .map_err(|e| reclassify_people_not_found(e, "contact group", &name))
    }
}

impl GoogleMcp {
    pub(crate) async fn people_for(&self, parts: &Parts) -> Result<PeopleClient, ErrorData> {
        let session = self.resolve_session(parts).await?;
        Ok(PeopleClient::new(
            (*self.state.http).clone(),
            session.access_token,
        ))
    }
}

fn reclassify_people_not_found(e: PeopleError, kind: &'static str, id: &str) -> ErrorData {
    if let PeopleError::Api { status, .. } = &e
        && status.as_u16() == 404
    {
        return McpError::not_found(kind, id, "people").into();
    }
    to_mcp(e)
}

fn ensure_non_empty(s: &str, field: &str) -> Result<(), ErrorData> {
    if s.trim().is_empty() {
        return Err(
            McpError::invalid_input(format!("`{field}` must not be empty"))
                .with_service("people")
                .into(),
        );
    }
    Ok(())
}

/// Build the Person body and the matching `updatePersonFields` mask. A raw
/// `person` short-circuits both, since only the caller knows its shape.
fn build_person(f: &PeopleContactFields) -> Result<(Value, String), ErrorData> {
    if let Some(raw) = &f.person {
        let mask = raw
            .as_object()
            .map(|o| {
                o.keys()
                    .filter(|k| *k != "etag")
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .join(",");
        return Ok((raw.clone(), mask));
    }

    let mut body = json!({});
    let mut mask: Vec<&str> = Vec::new();

    if f.given_name.is_some() || f.family_name.is_some() || f.middle_name.is_some() {
        let mut n = json!({});
        if let Some(v) = &f.given_name {
            n["givenName"] = json!(v);
        }
        if let Some(v) = &f.family_name {
            n["familyName"] = json!(v);
        }
        if let Some(v) = &f.middle_name {
            n["middleName"] = json!(v);
        }
        body["names"] = json!([n]);
        mask.push("names");
    }
    if let Some(v) = &f.nickname {
        body["nicknames"] = json!([{ "value": v }]);
        mask.push("nicknames");
    }
    if let Some(v) = &f.emails {
        body["emailAddresses"] = json!(v.iter().map(|e| json!({ "value": e })).collect::<Vec<_>>());
        mask.push("emailAddresses");
    }
    if let Some(v) = &f.phones {
        body["phoneNumbers"] = json!(v.iter().map(|e| json!({ "value": e })).collect::<Vec<_>>());
        mask.push("phoneNumbers");
    }
    if f.organization.is_some() || f.job_title.is_some() {
        let mut o = json!({});
        if let Some(v) = &f.organization {
            o["name"] = json!(v);
        }
        if let Some(v) = &f.job_title {
            o["title"] = json!(v);
        }
        body["organizations"] = json!([o]);
        mask.push("organizations");
    }
    if let Some(v) = &f.notes {
        body["biographies"] = json!([{ "value": v, "contentType": "TEXT_PLAIN" }]);
        mask.push("biographies");
    }
    if let Some(v) = &f.birthday {
        body["birthdays"] = json!([{ "date": parse_birthday(v)? }]);
        mask.push("birthdays");
    }
    if let Some(v) = &f.addresses {
        body["addresses"] = json!(
            v.iter()
                .map(|a| json!({ "formattedValue": a }))
                .collect::<Vec<_>>()
        );
        mask.push("addresses");
    }
    if let Some(v) = &f.urls {
        body["urls"] = json!(v.iter().map(|u| json!({ "value": u })).collect::<Vec<_>>());
        mask.push("urls");
    }

    Ok((body, mask.join(",")))
}

/// `YYYY-MM-DD`, or `--MM-DD` for a birthday whose year is unknown.
fn parse_birthday(s: &str) -> Result<Value, ErrorData> {
    let bad = || -> ErrorData {
        McpError::invalid_input(format!("could not parse birthday '{s}'"))
            .with_hint("Use `YYYY-MM-DD`, or `--MM-DD` when the year is unknown.")
            .with_service("people")
            .into()
    };
    let (year, rest) = match s.strip_prefix("--") {
        Some(rest) => (None, rest),
        None => {
            let (y, rest) = s.split_once('-').ok_or_else(bad)?;
            (Some(y.parse::<i64>().map_err(|_| bad())?), rest)
        }
    };
    let (m, d) = rest.split_once('-').ok_or_else(bad)?;
    let month: i64 = m.parse().map_err(|_| bad())?;
    let day: i64 = d.parse().map_err(|_| bad())?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad());
    }
    let mut out = json!({ "month": month, "day": day });
    if let Some(y) = year {
        out["year"] = json!(y);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> PeopleContactFields {
        PeopleContactFields {
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            emails: None,
            phones: None,
            organization: None,
            job_title: None,
            notes: None,
            birthday: None,
            addresses: None,
            urls: None,
            person: None,
        }
    }

    #[test]
    fn empty_fields_produce_an_empty_body_and_mask() {
        let (body, mask) = build_person(&fields()).unwrap();
        assert_eq!(body, json!({}));
        assert_eq!(mask, "");
    }

    #[test]
    fn name_parts_collapse_into_one_names_entry() {
        let mut f = fields();
        f.given_name = Some("Joseph".into());
        f.family_name = Some("St-Louis".into());
        let (body, mask) = build_person(&f).unwrap();
        assert_eq!(
            body["names"],
            json!([{ "givenName": "Joseph", "familyName": "St-Louis" }])
        );
        assert_eq!(mask, "names");
    }

    #[test]
    fn mask_lists_every_supplied_group_once() {
        let mut f = fields();
        f.given_name = Some("A".into());
        f.emails = Some(vec!["a@b.c".into()]);
        f.phones = Some(vec!["+15551234567".into()]);
        f.organization = Some("Acme".into());
        f.job_title = Some("CTO".into());
        let (_, mask) = build_person(&f).unwrap();
        assert_eq!(mask, "names,emailAddresses,phoneNumbers,organizations");
    }

    #[test]
    fn multiple_emails_are_preserved_in_order() {
        let mut f = fields();
        f.emails = Some(vec!["one@x.com".into(), "two@x.com".into()]);
        let (body, _) = build_person(&f).unwrap();
        assert_eq!(
            body["emailAddresses"],
            json!([{ "value": "one@x.com" }, { "value": "two@x.com" }])
        );
    }

    #[test]
    fn notes_become_a_plain_text_biography() {
        let mut f = fields();
        f.notes = Some("met at the plumbing thing".into());
        let (body, mask) = build_person(&f).unwrap();
        assert_eq!(
            body["biographies"],
            json!([{ "value": "met at the plumbing thing", "contentType": "TEXT_PLAIN" }])
        );
        assert_eq!(mask, "biographies");
    }

    #[test]
    fn raw_person_short_circuits_and_derives_its_own_mask() {
        let mut f = fields();
        f.given_name = Some("ignored".into());
        f.person = Some(json!({ "names": [{ "givenName": "Raw" }], "etag": "e1" }));
        let (body, mask) = build_person(&f).unwrap();
        assert_eq!(body["names"], json!([{ "givenName": "Raw" }]));
        assert_eq!(mask, "names", "etag must not appear in updatePersonFields");
    }

    #[test]
    fn birthday_with_year() {
        assert_eq!(
            parse_birthday("1983-07-14").unwrap(),
            json!({ "month": 7, "day": 14, "year": 1983 })
        );
    }

    #[test]
    fn birthday_without_year() {
        assert_eq!(
            parse_birthday("--07-14").unwrap(),
            json!({ "month": 7, "day": 14 })
        );
    }

    #[test]
    fn birthday_rejects_garbage_and_out_of_range() {
        for bad in ["", "14 July", "1983-13-01", "1983-07-99", "1983/07/14"] {
            assert!(parse_birthday(bad).is_err(), "should reject: {bad}");
        }
    }
}
