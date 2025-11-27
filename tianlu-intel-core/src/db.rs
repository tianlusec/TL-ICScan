use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use anyhow::Result;
use std::fs::File;
use std::path::Path;

pub async fn connect(db_path: &str) -> Result<Pool<Sqlite>> {
    let db_url = format!("sqlite:{}", db_path);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&db_url)
        .await?;
    
    sqlx::query("PRAGMA busy_timeout = 30000;")
        .execute(&pool)
        .await?;

    sqlx::query("PRAGMA journal_mode = WAL;")
        .execute(&pool)
        .await?;
        
    Ok(pool)
}

pub async fn init_db(db_path: &str) -> Result<()> {
    if !Path::new(db_path).exists() {
        File::create(db_path)?;
    }

    let pool = connect(db_path).await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cve_records (
            cve_id          TEXT PRIMARY KEY,
            title           TEXT,
            description     TEXT,
            severity        TEXT,
            cvss_v2_score   REAL,
            cvss_v3_score   REAL,
            publish_date    TEXT,
            update_date     TEXT,
            vendors         TEXT,
            products        TEXT,
            "references"    TEXT,
            sources         TEXT,
            raw_data        TEXT,
            cwe_ids         TEXT,
            attack_vector   TEXT,
            privileges_required TEXT,
            user_interaction TEXT,
            confidentiality_impact TEXT,
            integrity_impact TEXT,
            availability_impact TEXT,
            is_in_kev       BOOLEAN,
            exploit_exists  BOOLEAN,
            poc_sources     TEXT,
            poc_repo_count  INTEGER,
            poc_risk_label  TEXT,
            feed_version    TEXT,
            epss_score      REAL,
            epss_percentile REAL
        );
        CREATE INDEX IF NOT EXISTS idx_publish_date ON cve_records(publish_date);
        CREATE INDEX IF NOT EXISTS idx_severity ON cve_records(severity);
        CREATE INDEX IF NOT EXISTS idx_is_in_kev ON cve_records(is_in_kev);
        "#
    )
    .execute(&pool)
    .await?;

    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN vendors TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN products TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN \"references\" TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN sources TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN raw_data TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN cwe_ids TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN attack_vector TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN privileges_required TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN user_interaction TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN confidentiality_impact TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN integrity_impact TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN availability_impact TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN is_in_kev BOOLEAN").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN exploit_exists BOOLEAN").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN poc_sources TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN poc_repo_count INTEGER").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN poc_risk_label TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN feed_version TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN epss_score REAL").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE cve_records ADD COLUMN epss_percentile REAL").execute(&pool).await;

    println!("Database initialized at {}", db_path);
    Ok(())
}
