use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    InitDb {
        #[arg(long, default_value = "tianlu_intel_v2.db")]
        db: String,
    },
    Ingest {
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "tianlu_intel_v2.db")]
        db: String,
    },
    List {
        #[arg(long, default_value = "tianlu_intel_v2.db")]
        db: String,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        keyword: Option<String>,
        #[arg(long)]
        cwe: Option<String>,
        #[arg(long)]
        attack_vector: Option<String>,
        #[arg(long)]
        in_kev: bool,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        vendor: Option<String>,
        #[arg(long)]
        product: Option<String>,
        #[arg(long, default_value = "50")]
        limit: i64,
    },
    Show {
        cve_id: String,
        #[arg(long, default_value = "tianlu_intel_v2.db")]
        db: String,
    },
    Export {
        #[arg(long, default_value = "tianlu_intel_v2.db")]
        db: String,
        #[arg(long, value_enum)]
        format: ExportFormat,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        severity: Option<String>,
    },
    Digest {
        #[arg(long, default_value = "tianlu_intel_v2.db")]
        db: String,
        #[arg(long)]
        config: String,
        #[arg(long)]
        since: String,
        #[arg(long)]
        cve_pattern: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
}
