use crate::db::connect;
use crate::query::CveRecord;
use anyhow::{Context, Result};
use serde::Deserialize;
use sqlx::Row;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct WatchlistConfig {
    pub items: Vec<WatchlistItem>,
}

#[derive(Debug, Deserialize)]
pub struct WatchlistItem {
    pub name: String,
    pub keywords: Option<Vec<String>>,
    pub vendors: Option<Vec<String>>,
    pub products: Option<Vec<String>>,
    pub severity_min: Option<String>, // LOW, MEDIUM, HIGH, CRITICAL
}

fn severity_to_rank(sev: &str) -> i32 {
    match sev.to_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn parse_since_date(since: &str) -> String {
    if since.ends_with('d') {
        if let Ok(days) = since.trim_end_matches('d').parse::<i64>() {
             let date = chrono::Local::now() - chrono::Duration::days(days);
             return date.format("%Y-%m-%d").to_string();
        }
    }
    if since.ends_with('w') {
        if let Ok(weeks) = since.trim_end_matches('w').parse::<i64>() {
             let date = chrono::Local::now() - chrono::Duration::weeks(weeks);
             return date.format("%Y-%m-%d").to_string();
        }
    }
    since.to_string()
}

pub async fn generate_digest(db_path: &str, config_path: &str, since: &str, cve_pattern: &Option<String>) -> Result<()> {
    let pool = connect(db_path).await?;
    
    let config_content = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path))?;
    let config: Vec<WatchlistItem> = serde_yaml::from_str(&config_content)
        .with_context(|| "Failed to parse YAML config")?;

    let parsed_since = parse_since_date(since);

    println!("# Tianlu Intelligence Digest");
    println!("**Date**: {}\n", chrono::Local::now().format("%Y-%m-%d"));
    println!("**Since**: {} (Effective: {})\n", since, parsed_since);
    if let Some(pattern) = cve_pattern {
        println!("**CVE Filter**: {}\n", pattern);
    }

    for item in config {
        println!("## {}\n", item.name);

        let mut query_str = "SELECT * FROM cve_records WHERE publish_date >= ?".to_string();
        
        // Build dynamic query parts
        let mut conditions = Vec::new();
        
        // Keywords (OR logic within keywords)
        if let Some(kws) = &item.keywords {
            if !kws.is_empty() {
                let kw_conds: Vec<String> = kws.iter()
                    .map(|_| "(title LIKE ? OR description LIKE ?)".to_string())
                    .collect();
                conditions.push(format!("({})", kw_conds.join(" OR ")));
            }
        }

        // Vendors (OR logic)
        if let Some(vs) = &item.vendors {
            if !vs.is_empty() {
                let v_conds: Vec<String> = vs.iter()
                    .map(|_| "vendors LIKE ?".to_string())
                    .collect();
                conditions.push(format!("({})", v_conds.join(" OR ")));
            }
        }

        // Products (OR logic)
        if let Some(ps) = &item.products {
            if !ps.is_empty() {
                let p_conds: Vec<String> = ps.iter()
                    .map(|_| "products LIKE ?".to_string())
                    .collect();
                conditions.push(format!("({})", p_conds.join(" OR ")));
            }
        }

        if !conditions.is_empty() {
            query_str.push_str(" AND (");
            query_str.push_str(&conditions.join(" AND ")); 
            query_str.push_str(")");
        }

        // Apply CVE Pattern filter if provided
        if cve_pattern.is_some() {
            query_str.push_str(" AND cve_id LIKE ?");
        }

        query_str.push_str(" ORDER BY publish_date DESC");

        let mut query = sqlx::query_as::<_, CveRecord>(&query_str)
            .bind(&parsed_since);

        // Bind parameters
        if let Some(kws) = &item.keywords {
            for kw in kws {
                let pattern = format!("%{}%", kw);
                query = query.bind(pattern.clone()).bind(pattern);
            }
        }
        if let Some(vs) = &item.vendors {
            for v in vs {
                let pattern = format!("%{}%", v);
                query = query.bind(pattern);
            }
        }
        if let Some(ps) = &item.products {
            for p in ps {
                let pattern = format!("%{}%", p);
                query = query.bind(pattern);
            }
        }

        // Bind CVE Pattern
        if let Some(pattern) = cve_pattern {
            // If user didn't provide %, add it? 
            // User asked for "CVE-2025开头" (starts with CVE-2025).
            // If they pass "CVE-2025", we should probably treat it as "CVE-2025%".
            // But standard CLI behavior is usually explicit.
            // However, for ease of use, if it doesn't contain %, maybe we append it?
            // Let's stick to explicit for now, or just append % if not present?
            // The user said "CVE-2025开头".
            // If I pass "CVE-2025%", it works.
            // Let's just bind what they pass. I'll document/tell them to use %.
            // Actually, to be nice, if they say "CVE-2025", I'll make it "CVE-2025%".
            let mut p = pattern.clone();
            if !p.contains('%') {
                p.push('%');
            }
            query = query.bind(p);
        }

        let rows = query.fetch_all(&pool).await?;
        
        let min_rank = item.severity_min.as_ref().map(|s| severity_to_rank(s)).unwrap_or(0);
        
        let mut count = 0;
        for row in rows {
            let row_rank = severity_to_rank(row.severity.as_deref().unwrap_or("UNKNOWN"));
            if row_rank < min_rank {
                continue;
            }
            
            count += 1;
            let score = row.cvss_v3_score.or(row.cvss_v2_score).unwrap_or(0.0);
            let severity = row.severity.as_deref().unwrap_or("UNKNOWN");
            let title = row.title.as_deref().unwrap_or("No Title");
            let date = row.publish_date.as_deref().unwrap_or("Unknown Date");
            
            let mut flags: Vec<String> = Vec::new();
            if row.is_in_kev.unwrap_or(false) { flags.push("🚨 **KEV**".to_string()); }
            if row.exploit_exists.unwrap_or(false) { flags.push("💥 **Exploit**".to_string()); }
            
            if let Some(epss) = row.epss_score {
                if epss > 0.1 { // > 10% probability is considered high
                    flags.push(format!("🔥 **EPSS: {:.1}%**", epss * 100.0));
                }
            }

            let flags_str = if flags.is_empty() { "".to_string() } else { format!(" {} ", flags.join(" ")) };

            println!("- **{}** ({}, CVSS {}){} - {}", row.cve_id, severity, score, flags_str, title);
            println!("  - *Published*: {}", date);
            if let Some(desc) = &row.description {
                let short_desc: String = desc.chars().take(150).collect();
                println!("  - *Summary*: {}...", short_desc.replace("\n", " "));
            }
            // Sources
            let sources: Vec<String> = serde_json::from_str(&row.sources).unwrap_or_default();
            println!("  - *Sources*: {}", sources.join(", "));
            println!();
        }

        if count == 0 {
            println!("*No new vulnerabilities found matching criteria.*\n");
        }
    }

    Ok(())
}
