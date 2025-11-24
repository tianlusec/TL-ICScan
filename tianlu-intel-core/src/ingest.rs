use crate::db::connect;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashSet;
use std::io::{self, BufRead};

#[derive(Debug, Serialize, Deserialize)]
pub struct NormalizedCVE {
    pub cve_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub cvss_v2_score: Option<f64>,
    pub cvss_v3_score: Option<f64>,
    pub publish_date: Option<String>,
    pub update_date: Option<String>,
    #[serde(default)]
    pub vendors: Vec<String>,
    #[serde(default)]
    pub products: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    
    // New fields v0.2
    pub cwe_ids: Option<Vec<String>>,
    pub attack_vector: Option<String>,
    pub privileges_required: Option<String>,
    pub user_interaction: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub availability_impact: Option<String>,
    pub is_in_kev: Option<bool>,
    pub exploit_exists: Option<bool>,

    // New fields v0.5
    pub poc_sources: Option<Vec<String>>,
    pub poc_repo_count: Option<i64>,
    pub poc_risk_label: Option<String>,
    pub feed_version: Option<String>,

    // New fields v0.6 (EPSS)
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,

    #[serde(default)]
    pub extra: serde_json::Value,
}

pub async fn ingest_data(db_path: &str, source: &str) -> Result<()> {
    let pool = connect(db_path).await?;
    let stdin = io::stdin();
    let handle = stdin.lock();

    let mut tx = pool.begin().await?;
    let mut count = 0;

    for line in handle.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let new_cve: NormalizedCVE = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to parse JSON line: {}", e);
                continue;
            }
        };

        // Check if exists
        let existing = sqlx::query("SELECT * FROM cve_records WHERE cve_id = ?")
            .bind(&new_cve.cve_id)
            .fetch_optional(&mut *tx)
            .await?;

        if let Some(row) = existing {
            // Merge
            let vendors_str: Option<String> = row.get("vendors");
            let mut vendors: HashSet<String> = vendors_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            vendors.extend(new_cve.vendors);
            
            let products_str: Option<String> = row.get("products");
            let mut products: HashSet<String> = products_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            products.extend(new_cve.products);

            let references_str: Option<String> = row.get("references");
            let mut references: HashSet<String> = references_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            references.extend(new_cve.references);

            let sources_str: Option<String> = row.get("sources");
            let mut sources: HashSet<String> = sources_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            sources.insert(source.to_string());

            // Merge CWEs
            let cwe_ids_str: Option<String> = row.try_get("cwe_ids").ok();
            let mut cwe_ids: HashSet<String> = cwe_ids_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            if let Some(new_cwes) = new_cve.cwe_ids {
                cwe_ids.extend(new_cwes);
            }

            // Merge PoC Sources
            let poc_sources_str: Option<String> = row.try_get("poc_sources").ok().flatten();
            let mut poc_sources: HashSet<String> = poc_sources_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            if let Some(new_poc_sources) = new_cve.poc_sources {
                poc_sources.extend(new_poc_sources);
            }

            // Merge PoC Repo Count (Max)
            let old_poc_repo_count: Option<i64> = row.try_get("poc_repo_count").ok().flatten();
            let poc_repo_count = match (old_poc_repo_count, new_cve.poc_repo_count) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };

            // Merge PoC Risk Label (Overwrite if new is present)
            let poc_risk_label = new_cve.poc_risk_label.or_else(|| row.try_get("poc_risk_label").ok().flatten());

            // Merge Feed Version (Overwrite)
            let feed_version = new_cve.feed_version.or_else(|| row.try_get("feed_version").ok().flatten());

            // Merge EPSS (Overwrite if new is present)
            let epss_score = new_cve.epss_score.or(row.try_get("epss_score").ok().flatten());
            let epss_percentile = new_cve.epss_percentile.or(row.try_get("epss_percentile").ok().flatten());

            // Simple strategy for other fields: overwrite if new value is present
            let title = new_cve.title.or_else(|| row.get("title"));
            let description = new_cve.description.or_else(|| row.get("description"));
            let severity = new_cve.severity.or_else(|| row.get("severity"));
            let cvss_v2 = new_cve.cvss_v2_score.or(row.get("cvss_v2_score"));
            let cvss_v3 = new_cve.cvss_v3_score.or(row.get("cvss_v3_score"));
            let publish_date = new_cve.publish_date.or_else(|| row.get("publish_date"));
            let update_date = new_cve.update_date.or_else(|| row.get("update_date"));
            
            // New scalar fields
            let attack_vector = new_cve.attack_vector.or_else(|| row.try_get("attack_vector").ok().flatten());
            let privileges_required = new_cve.privileges_required.or_else(|| row.try_get("privileges_required").ok().flatten());
            let user_interaction = new_cve.user_interaction.or_else(|| row.try_get("user_interaction").ok().flatten());
            let confidentiality_impact = new_cve.confidentiality_impact.or_else(|| row.try_get("confidentiality_impact").ok().flatten());
            let integrity_impact = new_cve.integrity_impact.or_else(|| row.try_get("integrity_impact").ok().flatten());
            let availability_impact = new_cve.availability_impact.or_else(|| row.try_get("availability_impact").ok().flatten());

            // Boolean fields (OR logic)
            let old_is_in_kev: Option<bool> = row.try_get("is_in_kev").ok().flatten();
            let is_in_kev = new_cve.is_in_kev.unwrap_or(false) || old_is_in_kev.unwrap_or(false);
            
            let old_exploit_exists: Option<bool> = row.try_get("exploit_exists").ok().flatten();
            let exploit_exists = new_cve.exploit_exists.unwrap_or(false) || old_exploit_exists.unwrap_or(false);

            let raw_data = serde_json::to_string(&new_cve.extra).unwrap_or_default();

            sqlx::query(
                r#"
                UPDATE cve_records SET
                    title = ?, description = ?, severity = ?, 
                    cvss_v2_score = ?, cvss_v3_score = ?,
                    publish_date = ?, update_date = ?,
                    vendors = ?, products = ?, "references" = ?, sources = ?, raw_data = ?,
                    cwe_ids = ?, attack_vector = ?, privileges_required = ?, user_interaction = ?,
                    confidentiality_impact = ?, integrity_impact = ?, availability_impact = ?,
                    is_in_kev = ?, exploit_exists = ?,
                    poc_sources = ?, poc_repo_count = ?, poc_risk_label = ?, feed_version = ?,
                    epss_score = ?, epss_percentile = ?
                WHERE cve_id = ?
                "#
            )
            .bind(title)
            .bind(description)
            .bind(severity)
            .bind(cvss_v2)
            .bind(cvss_v3)
            .bind(publish_date)
            .bind(update_date)
            .bind(serde_json::to_string(&vendors)?)
            .bind(serde_json::to_string(&products)?)
            .bind(serde_json::to_string(&references)?)
            .bind(serde_json::to_string(&sources)?)
            .bind(raw_data)
            .bind(serde_json::to_string(&cwe_ids)?)
            .bind(attack_vector)
            .bind(privileges_required)
            .bind(user_interaction)
            .bind(confidentiality_impact)
            .bind(integrity_impact)
            .bind(availability_impact)
            .bind(is_in_kev)
            .bind(exploit_exists)
            .bind(serde_json::to_string(&poc_sources)?)
            .bind(poc_repo_count)
            .bind(poc_risk_label)
            .bind(feed_version)
            .bind(epss_score)
            .bind(epss_percentile)
            .bind(&new_cve.cve_id)
            .execute(&mut *tx)
            .await?;

        } else {
            // Insert
            let vendors_json = serde_json::to_string(&new_cve.vendors)?;
            let products_json = serde_json::to_string(&new_cve.products)?;
            let references_json = serde_json::to_string(&new_cve.references)?;
            let sources_json = serde_json::to_string(&vec![source])?;
            let raw_data = serde_json::to_string(&new_cve.extra).unwrap_or_default();
            
            // New fields
            let cwe_ids_json = serde_json::to_string(&new_cve.cwe_ids.unwrap_or_default())?;
            let is_in_kev = new_cve.is_in_kev.unwrap_or(false);
            let exploit_exists = new_cve.exploit_exists.unwrap_or(false);

            // v0.5 fields
            let poc_sources_json = serde_json::to_string(&new_cve.poc_sources.unwrap_or_default())?;

            sqlx::query(
                r#"
                INSERT INTO cve_records (
                    cve_id, title, description, severity, cvss_v2_score, cvss_v3_score,
                    publish_date, update_date, vendors, products, "references", sources, raw_data,
                    cwe_ids, attack_vector, privileges_required, user_interaction,
                    confidentiality_impact, integrity_impact, availability_impact,
                    is_in_kev, exploit_exists,
                    poc_sources, poc_repo_count, poc_risk_label, feed_version,
                    epss_score, epss_percentile
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(&new_cve.cve_id)
            .bind(&new_cve.title)
            .bind(&new_cve.description)
            .bind(&new_cve.severity)
            .bind(&new_cve.cvss_v2_score)
            .bind(&new_cve.cvss_v3_score)
            .bind(&new_cve.publish_date)
            .bind(&new_cve.update_date)
            .bind(vendors_json)
            .bind(products_json)
            .bind(references_json)
            .bind(sources_json)
            .bind(raw_data)
            .bind(cwe_ids_json)
            .bind(&new_cve.attack_vector)
            .bind(&new_cve.privileges_required)
            .bind(&new_cve.user_interaction)
            .bind(&new_cve.confidentiality_impact)
            .bind(&new_cve.integrity_impact)
            .bind(&new_cve.availability_impact)
            .bind(is_in_kev)
            .bind(exploit_exists)
            .bind(poc_sources_json)
            .bind(&new_cve.poc_repo_count)
            .bind(&new_cve.poc_risk_label)
            .bind(&new_cve.feed_version)
            .bind(&new_cve.epss_score)
            .bind(&new_cve.epss_percentile)
            .execute(&mut *tx)
            .await?;
        }

        count += 1;
        if count % 1000 == 0 {
            tx.commit().await?;
            tx = pool.begin().await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
