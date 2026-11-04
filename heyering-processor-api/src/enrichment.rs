use std::net::Ipv4Addr;

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use heyering_lib::{CategoryName, MaliciousActivityRecord};

use crate::common::{Response, request_builder};

/// Request body for calling the enrichment service
#[derive(Debug, Serialize)]
pub struct EnrichmentRequestBody {
    id: i64,
    asset: String,
    ip: Ipv4Addr,
    category: CategoryName,
}

/// Response of the enrichment service
#[derive(Debug, Deserialize)]
pub struct EnrichmentResponse {
    pub asn: String,
    pub category: String,
    #[serde(rename = "correlationId")]
    pub correlation_id: i64,
}

impl From<&MaliciousActivityRecord> for EnrichmentRequestBody {
    fn from(value: &MaliciousActivityRecord) -> Self {
        Self {
            id: value.id,
            asset: value.asset_name.clone(),
            ip: value.ip,
            category: value.category.clone(),
        }
    }
}

#[derive(Debug)]
pub struct EnrichedRecord {
    pub record: MaliciousActivityRecord,
    pub enrichment: EnrichmentResponse,
}

impl EnrichedRecord {
    fn new(record: MaliciousActivityRecord, enrichment: EnrichmentResponse) -> Self {
        Self { record, enrichment }
    }
}

/// Potential errors while calling the enrichment service
#[derive(thiserror::Error, Debug)]
pub enum EnrichmentServiceError {
    /// Network error, propagated from `reqwest` crate
    #[error("Network error, propagated from `reqwest` crate")]
    NetworkError(#[from] reqwest::Error),
    /// Unsuccessful request
    #[error("Response from the enrichment service with a status other than 200 OK")]
    UnsuccessfulRequest(Response),
}

/// Call the enrichment service
pub async fn enrich_record(
    record: &MaliciousActivityRecord,
) -> Result<EnrichedRecord, EnrichmentServiceError> {
    match request_builder("enrichment")
        .json(&EnrichmentRequestBody::from(record))
        .send()
        .await
    {
        Err(err) => {
            tracing::error!(
                "Network error when calling the heyering API's enrichment endpoint: {:?}",
                err
            );
            return Err(err.into());
        }
        Ok(response) => {
            let status = response.status();
            match status {
                StatusCode::BAD_REQUEST | StatusCode::INTERNAL_SERVER_ERROR => {
                    let message = response.text().await?;

                    tracing::error!(
                        "The heyering API enrichment endpoint responded with status code '{}' and message '{}'.",
                        status,
                        message
                    );

                    return Err(EnrichmentServiceError::UnsuccessfulRequest(Response::new(
                        status, message,
                    )));
                }
                StatusCode::OK => {
                    return Ok(EnrichedRecord::new(record.clone(), response.json().await?));
                }
                other => {
                    panic!("Unexpected status code: {}", other);
                }
            }
        }
    }
}
