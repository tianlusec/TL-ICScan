use crate::cli::ExportFormat;
use crate::db::connect;
use anyhow::Result;
use serde::Serialize;
use sqlx::FromRow;
use sqlx::QueryBuilder;
use sqlx::Sqlite;

#[derive(Debug, Serialize, FromRow)]
pub struct CveRecord {
    pub cve_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub cvss_v2_score: Option<f64>,
    pub cvss_v3_score: Option<f64>,
    pub publish_date: Option<String>,
    pub update_date: Option<String>,
    pub vendors: String,
    pub products: String,
    pub references: String,
    pub sources: String,
    pub raw_data: Option<String>,
    
    pub cwe_ids: Option<String>,
    pub attack_vector: Option<String>,
    pub privileges_required: Option<String>,
    pub user_interaction: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub availability_impact: Option<String>,
    pub is_in_kev: Option<bool>,
    pub exploit_exists: Option<bool>,

    pub poc_sources: Option<String>,
    pub poc_repo_count: Option<i64>,
    pub poc_risk_label: Option<String>,
    pub feed_version: Option<String>,

    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
}

pub async fn list_cves(
    db_path: &str,
    since: Option<String>,
    until: Option<String>,
    severity: Option<String>,
    keyword: Option<String>,
    cwe: Option<String>,
    attack_vector: Option<String>,
    in_kev: bool,
    source: Option<String>,
    vendor: Option<String>,
    product: Option<String>,
    limit: i64,
) -> Result<()> {
    let pool = connect(db_path).await?;
    
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT * FROM cve_records WHERE 1=1");
    
    if let Some(s) = &since {
        qb.push(" AND publish_date >= ");
        qb.push_bind(s);
    }
    if let Some(u) = &until {
        qb.push(" AND publish_date <= ");
        qb.push_bind(u);
    }
    if let Some(sev) = &severity {
        qb.push(" AND severity = ");
        qb.push_bind(sev);
    }
    if let Some(kw) = &keyword {
        let pattern = format!("%{}%", kw);
        qb.push(" AND (title LIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" OR description LIKE ");
        qb.push_bind(pattern);
        qb.push(")");
    }
    if let Some(c) = &cwe {
        qb.push(" AND cwe_ids LIKE ");
        qb.push_bind(format!("%{}%", c));
    }
    if let Some(av) = &attack_vector {
        qb.push(" AND attack_vector = ");
        qb.push_bind(av);
    }
    if in_kev {
        qb.push(" AND is_in_kev = 1");
    }
    if let Some(src) = &source {
        qb.push(" AND sources LIKE ");
        qb.push_bind(format!("%{}%", src));
    }
    if let Some(v) = &vendor {
        qb.push(" AND vendors LIKE ");
        qb.push_bind(format!("%{}%", v));
    }
    if let Some(p) = &product {
        qb.push(" AND products LIKE ");
        qb.push_bind(format!("%{}%", p));
    }
    
    qb.push(" ORDER BY publish_date DESC LIMIT ");
    qb.push_bind(limit);

    let rows = qb.build_query_as::<CveRecord>()
        .fetch_all(&pool)
        .await?;

    println!("{:<15} {:<8} {:<5} {:<8} {:<12} {:<5} {:<30}", "CVE ID", "SEVERITY", "CVSS", "EPSS", "PUBLISHED", "KEV", "TITLE");
    println!("{}", "-".repeat(95));

    for row in rows {
        let score = row.cvss_v3_score.or(row.cvss_v2_score).unwrap_or(0.0);
        let epss = row.epss_score.map(|s| format!("{:.2}%", s * 100.0)).unwrap_or_else(|| "-".to_string());
        let title = row.title.unwrap_or_default();
        let short_title: String = title.chars().take(30).collect();
        let kev_mark = if row.is_in_kev.unwrap_or(false) { "YES" } else { "" };
        
        println!(
            "{:<15} {:<8} {:<5.1} {:<8} {:<12} {:<5} {:<30}",
            row.cve_id,
            row.severity.unwrap_or_else(|| "UNKNOWN".to_string()),
            score,
            epss,
            row.publish_date.unwrap_or_default(),
            kev_mark,
            short_title
        );
    }

    Ok(())
}

pub async fn show_cve(db_path: &str, cve_id: &str) -> Result<()> {
    let pool = connect(db_path).await?;
    
    let row = sqlx::query_as::<_, CveRecord>("SELECT * FROM cve_records WHERE cve_id = ?")
        .bind(cve_id)
        .fetch_optional(&pool)
        .await?;

    if let Some(row) = row {
        println!("CVE ID:        {}", row.cve_id);
        println!("Title:         {}", row.title.unwrap_or_default());
        println!("Severity:      {} (CVSS v3: {:?})", row.severity.unwrap_or_default(), row.cvss_v3_score);
        if let Some(epss) = row.epss_score {
            println!("EPSS Score:    {:.2}% (Percentile: {:.2}%)", epss * 100.0, row.epss_percentile.unwrap_or(0.0) * 100.0);
        }
        println!("Published:     {}", row.publish_date.unwrap_or_default());
        println!("Last Updated:  {}", row.update_date.unwrap_or_default());
        
        if let Some(av) = &row.attack_vector { println!("Attack Vector: {}", av); }
        if let Some(pr) = &row.privileges_required { println!("Privileges:    {}", pr); }
        if let Some(ui) = &row.user_interaction { println!("User Interact: {}", ui); }
        if let Some(kev) = row.is_in_kev { if kev { println!("KEV Status:    In CISA KEV"); } }
        if let Some(exp) = row.exploit_exists { if exp { println!("Exploit:       Exists"); } }
        
        if let Some(poc_risk) = &row.poc_risk_label { println!("PoC Risk:      {}", poc_risk); }
        if let Some(poc_count) = row.poc_repo_count { println!("PoC Repos:     {}", poc_count); }
        if let Some(feed_ver) = &row.feed_version { println!("Feed Version:  {}", feed_ver); }

        println!();
        
        let vendors: Vec<String> = serde_json::from_str(&row.vendors).unwrap_or_default();
        println!("Vendors:       {}", vendors.join(", "));
        
        let products: Vec<String> = serde_json::from_str(&row.products).unwrap_or_default();
        println!("Products:      {}", products.join(", "));
        println!();
        
        println!("Description:");
        println!("  {}", row.description.unwrap_or_default());
        println!();
        
        println!("References:");
        let refs: Vec<String> = serde_json::from_str(&row.references).unwrap_or_default();
        for r in refs {
            println!("  - {}", r);
        }
        println!();
        
        println!("Sources:");
        let sources: Vec<String> = serde_json::from_str(&row.sources).unwrap_or_default();
        for s in sources {
            println!("  - {}", s);
        }

        if let Some(poc_srcs_str) = &row.poc_sources {
            let poc_srcs: Vec<String> = serde_json::from_str(poc_srcs_str).unwrap_or_default();
            if !poc_srcs.is_empty() {
                println!();
                println!("PoC Sources:");
                for s in poc_srcs {
                    println!("  - {}", s);
                }
            }
        }

    } else {
        println!("CVE not found: {}", cve_id);
    }

    Ok(())
}

pub async fn export_cves(
    db_path: &str,
    format: ExportFormat,
    since: Option<String>,
    severity: Option<String>,
) -> Result<()> {
    let pool = connect(db_path).await?;
    
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT * FROM cve_records WHERE 1=1");
    
    if let Some(s) = &since {
        qb.push(" AND publish_date >= ");
        qb.push_bind(s);
    }
    if let Some(sev) = &severity {
        qb.push(" AND severity = ");
        qb.push_bind(sev);
    }
    
    let rows = qb.build_query_as::<CveRecord>()
        .fetch_all(&pool)
        .await?;

    match format {
        ExportFormat::Json => {
            let json = serde_json::to_string_pretty(&rows)?;
            println!("{}", json);
        }
        ExportFormat::Csv => {
            println!("cve_id,severity,cvss_v3_score,epss_score,publish_date,title");
            for row in rows {
                let mut title = row.title.unwrap_or_default();
                if title.starts_with('=') || title.starts_with('+') || title.starts_with('-') || title.starts_with('@') {
                    title.insert(0, '\'');
                }
                
                println!(
                    "{},{},{},{},{},\"{}\"",
                    row.cve_id,
                    row.severity.unwrap_or_default(),
                    row.cvss_v3_score.unwrap_or(0.0),
                    row.epss_score.unwrap_or(0.0),
                    row.publish_date.unwrap_or_default(),
                    title.replace("\"", "\"\"")
                );
            }
        }
    }

    Ok(())
}
