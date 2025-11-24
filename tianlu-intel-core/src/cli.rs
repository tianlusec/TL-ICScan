use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the database
    InitDb {
        /// Database path
        #[arg(long, default_value = "tianlu_intel.db")]
        db: String,
    },
    /// Ingest data from STDIN
    Ingest {
        /// Source name (e.g., nvd, cisa_kev)
        #[arg(long)]
        source: String,
        /// Database path
        #[arg(long, default_value = "tianlu_intel.db")]
        db: String,
    },
    /// List CVEs
    List {
        /// Database path
        #[arg(long, default_value = "tianlu_intel.db")]
        db: String,
        /// Start date (ISO 8601)
        #[arg(long)]
        since: Option<String>,
        /// End date (ISO 8601)
        #[arg(long)]
        until: Option<String>,
        /// Filter by severity
        #[arg(long)]
        severity: Option<String>,
        /// Keyword search in title or description
        #[arg(long)]
        keyword: Option<String>,
        /// Filter by CWE ID (e.g., CWE-79)
        #[arg(long)]
        cwe: Option<String>,
        /// Filter by Attack Vector (NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL)
        #[arg(long)]
        attack_vector: Option<String>,
        /// Filter by KEV status (only show those in KEV)
        #[arg(long)]
        in_kev: bool,
        /// Filter by Source (e.g., nvd, cisa_kev, msrc)
        #[arg(long)]
        source: Option<String>,
        /// Filter by Vendor (e.g., microsoft, apache)
        #[arg(long)]
        vendor: Option<String>,
        /// Filter by Product (e.g., exchange_server, log4j)
        #[arg(long)]
        product: Option<String>,
        /// Limit results
        #[arg(long, default_value = "50")]
        limit: i64,
    },
    /// Show CVE details
    Show {
        /// CVE ID
        cve_id: String,
        /// Database path
        #[arg(long, default_value = "tianlu_intel.db")]
        db: String,
    },
    /// Export data
    Export {
        /// Database path
        #[arg(long, default_value = "tianlu_intel.db")]
        db: String,
        /// Output format
        #[arg(long, value_enum)]
        format: ExportFormat,
        /// Start date (ISO 8601)
        #[arg(long)]
        since: Option<String>,
        /// Filter by severity
        #[arg(long)]
        severity: Option<String>,
    },
    /// Generate a digest report based on a watchlist
    Digest {
        /// Database path
        #[arg(long, default_value = "tianlu_intel.db")]
        db: String,
        /// Watchlist configuration file (YAML)
        #[arg(long)]
        config: String,
        /// Start date (ISO 8601) or relative (e.g. 3d, 1w)
        #[arg(long)]
        since: String,
        /// Filter by CVE ID pattern (e.g. CVE-2025-%)
        #[arg(long)]
        cve_pattern: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
}
