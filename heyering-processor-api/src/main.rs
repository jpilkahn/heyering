#![doc = include_str!("../README.md")]

mod analytics;
mod common;
mod enrichment;

use axum::{Router, extract::Json, http::StatusCode, routing::post};
use tokio::time::{Duration, sleep};
use tracing::{Level, info};
use tracing_subscriber;

use heyering_lib::{
    MAX_CHUNK_SIZE, MaliciousActivityRecord, PROCESSOR_API_ADDRESS, RATE_LIMIT_DURATION_SECONDS,
};

use crate::{
    analytics::{AnalyticsResponse, AnalyticsServiceError, store_records},
    common::Response,
    enrichment::{EnrichedRecord, EnrichmentServiceError, enrich_record},
};

const RETRY_LIMIT: usize = 5;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let app = Router::new().route("/records", post(process_records));

    // run our app with hyper, listening globally on port 5000
    let listener = tokio::net::TcpListener::bind(PROCESSOR_API_ADDRESS)
        .await
        .unwrap();
    info!("Server is listening on http://{}", PROCESSOR_API_ADDRESS);
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

/// Handler for the POST /records route
async fn process_records(
    Json(payload): Json<Vec<MaliciousActivityRecord>>,
) -> Result<(), (StatusCode, String)> {
    if payload.len() > MAX_CHUNK_SIZE {
        let message = format!(
            "Max chunk size exceeded. Limit chunks to at most {} records.",
            MAX_CHUNK_SIZE
        );
        tracing::error!(message);
        return Err((StatusCode::BAD_REQUEST, message));
    }

    let mut enriched_records = vec![];

    for record in payload {
        tracing::info!("Enriching record with ID {}", record.id);

        let mut result: Result<EnrichedRecord, EnrichmentServiceError> =
            Err(EnrichmentServiceError::UnsuccessfulRequest(Response::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "dummy".to_owned(),
            )));
        let mut retries = 0;

        while result.is_err() && retries <= RETRY_LIMIT {
            result = enrich_record(&record).await;
            tracing::info!("{:?}", result);
            retries += 1;
        }

        match result {
            Err(err) => {
                let message = format!(
                    "Calling the enrichment service failed after {} unsuccessful retries: {}",
                    RETRY_LIMIT, err
                );
                tracing::error!(message);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, message));
            }
            Ok(enriched) => {
                tracing::info!("Successfully enriched record with ID {}", record.id);
                enriched_records.push(enriched);
            }
        }
    }

    tracing::debug!("{:?}", enriched_records);

    tracing::info!(
        "Posting {} enriched records to the analytics service",
        enriched_records.len()
    );

    let mut result: Result<AnalyticsResponse, AnalyticsServiceError> =
        Err(AnalyticsServiceError::UnsuccessfulRequest(Response::new(
            StatusCode::TOO_MANY_REQUESTS,
            "dummy".to_owned(),
        )));
    let mut retries = 0;
    while (result.is_err()) && retries <= RETRY_LIMIT {
        result = store_records(&enriched_records).await;
        tracing::info!("{:?}", result);
        sleep(Duration::from_secs(RATE_LIMIT_DURATION_SECONDS)).await;
        retries += 1;
    }

    match result {
        Err(err) => {
            let message = format!(
                "Calling the analytics service failed after {} unsuccessful retries: {}",
                RETRY_LIMIT, err
            );
            tracing::error!(message);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, message));
        }
        Ok(response) => {
            tracing::info!(
                "The analytics endpoint responded with status '{}' and successfully ingested {} records",
                response.status,
                response.items_ingested
            );
        }
    }

    Ok(())
}
