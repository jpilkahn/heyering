#![doc = include_str!("../README.md")]

use std::{fs::File, io::Read, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use csv::ReaderBuilder;
use reqwest::Client;
use thiserror::Error;
use tokio::time::{Duration, sleep};
use tracing::Level;

use heyering_lib::{
    MAX_CHUNK_SIZE, MaliciousActivityRecord, PROCESSOR_API_ADDRESS, RATE_LIMIT_DURATION_SECONDS,
};

/// Commandline Arguments
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the CSV file to be ingested
    #[arg(short, long)]
    path: PathBuf,
}

/// Result of ingesting CSV file
struct ReadResult {
    records: Vec<MaliciousActivityRecord>,
    skipped_erroneous_lines_count: usize,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let args = Args::parse();

    tracing::info!("Attempting to read input data from {:#?}", args.path);

    let file = File::open(args.path)?;

    let result = read_csv(file);

    match result {
        Err(err) => {
            tracing::error!("Failed to read CSV file: {:?}", err);
            anyhow::bail!("Failed to read CSV file: {:?}", err);
        }
        Ok(read_result) => {
            let total_records_length = read_result.records.len();
            let skipped_erroneous_lines_count = read_result.skipped_erroneous_lines_count;
            let mut remaining = read_result;

            tracing::info!(
                "Successfully ingested {} lines from input CSV, skipped {} erroneous lines",
                total_records_length,
                skipped_erroneous_lines_count
            );

            tracing::info!("Beginning processing of records");

            process_records(&mut remaining.records).await?;

            tracing::info!("Successfully processed {} records", total_records_length);
        }
    }

    Ok(())
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
    // This check does not only verify that the expected CSV headers are
    // present in the input file, it also ensures that the input is
    // separated by the expected delimiter (i.e. a semi-colon) and that
    // the number of fields is 6, as expected. If the the `csv::Reader`
    // found n fields in the first line parsed, it will conveniently error out
    // on subsequent lines with a field count other than n.
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

/// Process records
async fn process_records(records: &mut Vec<MaliciousActivityRecord>) -> anyhow::Result<()> {
    while records.len() > 0 {
        let chunk = records.split_off(records.len() - std::cmp::min(MAX_CHUNK_SIZE, records.len()));

        tracing::info!("Processing a chunk of length: {}", chunk.len());
        tracing::info!("Number of unprocessed records remaining: {}", records.len());

        sleep(Duration::from_secs(RATE_LIMIT_DURATION_SECONDS)).await;

        process_chunk(&chunk).await?
    }

    Ok(())
}

/// Process chunk
async fn process_chunk(chunk: &Vec<MaliciousActivityRecord>) -> anyhow::Result<()> {
    let request_builder = Client::new().post(format!("http://{}/records", PROCESSOR_API_ADDRESS));

    let response = request_builder.json(chunk).send().await?;
    tracing::debug!("{:?}", response);

    let status = response.status();

    if !status.is_success() {
        let message = format!(
            "The processor API responded with status code '{}' and message '{}'.",
            status,
            response.text().await?
        );
        tracing::error!(message);
        return Err(anyhow::Error::msg(message));
    }

    Ok(())
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
