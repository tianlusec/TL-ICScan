mod cli;
mod db;
mod ingest;
mod query;
mod digest;
mod errors;

use clap::Parser;
use cli::{Cli, Commands};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::InitDb { db } => {
            db::init_db(&db).await?;
        }
        Commands::Ingest { source, db } => {
            ingest::ingest_data(&db, &source).await?;
        }
        Commands::List { db, since, until, severity, keyword, cwe, attack_vector, in_kev, source, vendor, product, limit } => {
            query::list_cves(&db, since, until, severity, keyword, cwe, attack_vector, in_kev, source, vendor, product, limit).await?;
        }
        Commands::Show { cve_id, db } => {
            query::show_cve(&db, &cve_id).await?;
        }
        Commands::Export { db, format, since, severity } => {
            query::export_cves(&db, format, since, severity).await?;
        }
        Commands::Digest { db, config, since, cve_pattern } => {
            digest::generate_digest(&db, &config, &since, &cve_pattern).await?;
        }
    }

    Ok(())
}
