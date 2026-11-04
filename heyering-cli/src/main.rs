#![doc = include_str!("../README.md")]

use std::{fmt::Formatter, fs::File, io::Read, net::Ipv4Addr, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use csv::ReaderBuilder;
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};
use thiserror::Error;
use tracing::Level;

/// Commandline Arguments
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the CSV file to be ingested
    #[arg(short, long)]
    path: PathBuf,
}

/// MITE category of malicious activity
#[allow(missing_docs)]
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all(serialize = "lowercase"))]
enum Category {
    ContentInjection,
    DrivebyCompromise,
    ExploitPublicFacingApplication,
    ExternalRemoteServices,
    HardwareAdditions,
    Phishing,
    ReplicationThroughRemovableMedia,
    SupplyChainCompromise,
    TrustedRelationship,
    ValidAccounts,
}

struct CategoryVisitor;

const CATEGORY_VISITOR_EXPECTING_MSG: &'static str =
    "a string representing a MITE category of malicious activity";

impl<'de> Visitor<'de> for CategoryVisitor {
    type Value = Category;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str(CATEGORY_VISITOR_EXPECTING_MSG)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        // Remove common word delimiters and lowercase the input string
        let normalized_value = value
            .replace(" ", "")
            .replace("-", "")
            .replace("_", "")
            .to_lowercase();

        // For some categories, even the normalized input value contains
        // recurring spelling errors.
        // The below assumes that these ought to be parsed as the category that
        // (to the human reader) is obviously meant by the misspelled input.
        match normalized_value.as_str() {
            "contentinjection" => Ok(Category::ContentInjection),
            "drivebycompromise" | "compromise(driveby)" => Ok(Category::DrivebyCompromise),
            "exploitpublicfacingapplication" | "exploitpublicfacing" | "explaoitpublicfacing" => {
                Ok(Category::ExploitPublicFacingApplication)
            }
            "externalremoteservices" | "externalremoteservice" => {
                Ok(Category::ExternalRemoteServices)
            }
            "hardwareadditions" => Ok(Category::HardwareAdditions),
            "phishing" | "phising" => Ok(Category::Phishing),
            "replicationthroughremovablemedia" => Ok(Category::ReplicationThroughRemovableMedia),
            "supplychaincompromise" => Ok(Category::SupplyChainCompromise),
            "trustedrelationship" => Ok(Category::TrustedRelationship),
            "validaccounts" | "validaaccounts" => Ok(Category::ValidAccounts),
            _ => Err(serde::de::Error::custom(format!(
                "Expected {}, found '{}'",
                CATEGORY_VISITOR_EXPECTING_MSG, value
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for Category {
    fn deserialize<D>(deserializer: D) -> Result<Category, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CategoryVisitor)
    }
}

/// Strongly-typed malicious activity record representing a single line of the input CSV
#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct MaliciousActivityRecord {
    id: i64,
    asset_name: String,
    ip: Ipv4Addr,
    // Ideally this ought to be represented by `chrono::DateTime<Utc>` or at
    // least `chrono::NaiveDateTime`, but given that the input format is not
    // compliant with RFC 3339, this would require yet another custom
    // (de)serializer.
    // --> Out of scope here given time constraints.
    created_utc: String,
    source: String,
    category: Category,
}

/// Result of ingesting CSV file
struct ReadResult {
    records: Vec<MaliciousActivityRecord>,
    skipped_erroneous_lines_count: u32,
}

impl ReadResult {
    fn new() -> Self {
        Self {
            records: vec![],
            skipped_erroneous_lines_count: 0,
        }
    }
}

/// Potential errors while reading CSV file
#[derive(Error, Debug)]
pub enum CsvReadError {
    /// Propagated from `csv` crate
    #[error("Error propagated from `csv` crate")]
    CsvError(#[from] csv::Error),
    /// Missing or malformed header
    #[error("Missing or malformed CSV header")]
    MissingOrMalformedHeader(csv::StringRecord),
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let args = Args::parse();

    tracing::info!("Attempting to read input data from {:#?}", args.path);

    let file = File::open(args.path)?;

    let result = read_csv(file);

    match result {
        Err(e) => {
            tracing::error!("Failed to read CSV file: {:?}", e);
            anyhow::bail!("Failed to read CSV file: {:?}", e);
        }
        Ok(successful) => {
            let read_result = successful;

            tracing::info!(
                "Successfully ingested {} lines from input CSV, skipped {} erroneous lines",
                read_result.records.len(),
                read_result.skipped_erroneous_lines_count
            );

            Ok(())
        }
    }
}

/// Read the colon-separated input CSV into a `ReadResult`
fn read_csv<R>(reader: R) -> Result<ReadResult, CsvReadError>
where
    R: Read,
{
    let expected_headers = vec![
        "id",
        "asset_name",
        "ip",
        "created_utc",
        "source",
        "category",
    ];

    let mut reader = ReaderBuilder::new().delimiter(b';').from_reader(reader);

    let headers = reader.headers()?;
    if headers != expected_headers {
        return Err(CsvReadError::MissingOrMalformedHeader(headers.to_owned()));
    }

    let mut read_result = ReadResult::new();

    for result in reader.deserialize::<MaliciousActivityRecord>() {
        match result {
            Ok(record) => {
                read_result.records.push(record);
            }
            Err(err) => {
                tracing::warn!(
                    "error reading from input CSV, skipping the affected line:\n{}",
                    err
                );
                read_result.skipped_erroneous_lines_count += 1;
            }
        }
    }

    Ok(read_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CSV_DATA: &str = "id;asset_name;ip;created_utc;source;category
119611;server_horizon;102.145.229.227;27/02/2024 00:00;pxtrpf;explaoit-public facing
142280;address_artichoke;118.123.166.144;06/09/2024 00:00;defender;valida_accounts
315061;server_spray;18.147.227.44;08/04/2024 00:00;crowdstrike;supply chain compromise";

    const INVALID_CSV_DATA: &str = "id;asset_name;ip;created_utc;source;category
119611;server_horizon;102.145.229.227;27/02/2024 00:00;pxtrpf;exploit-pubic facing
142280;address_artichoke;118.123.166.144;06/09/2024 00:00;defender
315061;server_spray;42;08/04/2024 00:00;crowdstrike;supply chain compromise";

    const MISSING_CSV_HEADER: &str =
        "119611;server_horizon;102.145.229.227;27/02/2024 00:00;pxtrpf;explaoit-public facing
142280;address_artichoke;118.123.166.144;06/09/2024 00:00;defender;valida_accounts
315061;server_spray;18.147.227.44;08/04/2024 00:00;crowdstrike;supply chain compromise";

    #[test]
    fn read_valid_csv_data() {
        let result = read_csv(VALID_CSV_DATA.as_bytes());

        assert!(result.is_ok());

        let read_result = result.unwrap();

        assert_eq!(read_result.records.len(), 3);
        assert_eq!(read_result.skipped_erroneous_lines_count, 0);
    }

    #[test]
    fn read_invalid_csv_data() {
        let result = read_csv(INVALID_CSV_DATA.as_bytes());

        assert!(result.is_ok());

        let read_result = result.unwrap();

        assert_eq!(read_result.records.len(), 0);
        assert_eq!(read_result.skipped_erroneous_lines_count, 3);
    }

    #[test]
    fn read_missing_csv_header() {
        let result = read_csv(MISSING_CSV_HEADER.as_bytes());

        assert!(result.is_err());
    }
}
