use std::net::Ipv4Addr;

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::{
    common::{Response, request_builder},
    enrichment::EnrichedRecord,
};

/// Request body for calling the analytics service
#[derive(Debug, Serialize)]
pub struct AnalyticsRequestBodyItem {
    id: i64,
    asset: String,
    ip: Ipv4Addr,
    category: String,
    asn: String,
    #[serde(rename = "correlationId")]
    correlation_id: i64,
}

impl From<&EnrichedRecord> for AnalyticsRequestBodyItem {
    fn from(value: &EnrichedRecord) -> Self {
        Self {
            id: value.record.id,
            asset: value.record.asset_name.clone(),
            ip: value.record.ip,
            category: value.enrichment.category.clone(),
            asn: value.enrichment.asn.clone(),
            correlation_id: value.enrichment.correlation_id,
        }
    }
}

/// Response of the analytics service
#[derive(Debug, Deserialize)]
pub struct AnalyticsResponse {
    pub status: String,
    #[serde(rename = "itemsIngested")]
    pub items_ingested: i64,
}

/// Potential errors while calling the analytics service
#[derive(thiserror::Error, Debug)]
pub enum AnalyticsServiceError {
    /// Network error, propagated from `reqwest` crate
    #[error("Network error, propagated from `reqwest` crate")]
    NetworkError(#[from] reqwest::Error),
    /// Unsuccessful request
    #[error("Response from the analytics service with a status other than 200 OK")]
    UnsuccessfulRequest(Response),
}

/// Call the analytics service
pub async fn store_records(
    records: &Vec<EnrichedRecord>,
) -> Result<AnalyticsResponse, AnalyticsServiceError> {
    let body: Vec<AnalyticsRequestBodyItem> = records.iter().map(|record| record.into()).collect();

    match request_builder("analytics").json(&body).send().await {
        Err(err) => {
            tracing::error!(
                "Network error when calling the heyering API's analytics endpoint: {:?}",
                err
            );
            return Err(err.into());
        }
        Ok(response) => {
            let status = response.status();
            match status {
                StatusCode::BAD_REQUEST
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::INTERNAL_SERVER_ERROR => {
                    let message = response.text().await?;

                    tracing::error!(
                        "The heyering API analytics endpoint responded with status code '{}' and message '{}'.",
                        status,
                        message
                    );

                    return Err(AnalyticsServiceError::UnsuccessfulRequest(Response::new(
                        status, message,
                    )));
                }
                StatusCode::OK => return Ok(response.json().await?),
                other => {
                    panic!("Unexpected status code: {}", other);
                }
            }
        }
    }
}
