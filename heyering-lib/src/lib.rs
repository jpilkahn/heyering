#![doc = include_str!("../README.md")]

use std::{fmt::Formatter, net::Ipv4Addr};

use serde::{Deserialize, Deserializer, Serialize, de::Visitor};

/// Address the processor API server is listening on
pub const PROCESSOR_API_ADDRESS: &'static str = "0.0.0.0:5000";

/// Maximum number of records that can be processed in a single request
pub const MAX_CHUNK_SIZE: usize = 20;

/// Duration to wait between chunk processing to satisfy rate limit
pub const RATE_LIMIT_DURATION_SECONDS: u64 = 11;

/// Strongly-typed malicious activity record representing a single line of the input CSV
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MaliciousActivityRecord {
    /// Numeric unique identifier of the log line
    pub id: i64,
    /// Name of the involved asset (e.g. computer, server, laptop)
    pub asset_name: String,
    /// IP address of the involved asset
    pub ip: Ipv4Addr,
    // Ideally this ought to be represented by `chrono::DateTime<Utc>` or at
    // least `chrono::NaiveDateTime`, but given that the input format is not
    // compliant with RFC 3339, this would require yet another custom
    // (de)serializer.
    // --> Out of scope here given time constraints.
    /// Time of log line creation
    pub created_utc: String,
    /// Source of log line
    pub source: String,
    /// MITE category name belonging to the log line event
    pub category: CategoryName,
}

/// MITE category of malicious activity
#[allow(missing_docs)]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all(serialize = "lowercase"))]
pub enum CategoryName {
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

struct CategoryNameVisitor;

const CATEGORY_VISITOR_EXPECTING_MSG: &'static str =
    "a string representing a MITE category of malicious activity";

impl<'de> Visitor<'de> for CategoryNameVisitor {
    type Value = CategoryName;

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
            "contentinjection" => Ok(CategoryName::ContentInjection),
            "drivebycompromise" | "compromise(driveby)" => Ok(CategoryName::DrivebyCompromise),
            "exploitpublicfacingapplication" | "exploitpublicfacing" | "explaoitpublicfacing" => {
                Ok(CategoryName::ExploitPublicFacingApplication)
            }
            "externalremoteservices" | "externalremoteservice" => {
                Ok(CategoryName::ExternalRemoteServices)
            }
            "hardwareadditions" => Ok(CategoryName::HardwareAdditions),
            "phishing" | "phising" => Ok(CategoryName::Phishing),
            "replicationthroughremovablemedia" => {
                Ok(CategoryName::ReplicationThroughRemovableMedia)
            }
            "supplychaincompromise" => Ok(CategoryName::SupplyChainCompromise),
            "trustedrelationship" => Ok(CategoryName::TrustedRelationship),
            "validaccounts" | "validaaccounts" => Ok(CategoryName::ValidAccounts),
            _ => Err(serde::de::Error::custom(format!(
                "Expected {}, found '{}'",
                CATEGORY_VISITOR_EXPECTING_MSG, value
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for CategoryName {
    fn deserialize<D>(deserializer: D) -> Result<CategoryName, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CategoryNameVisitor)
    }
}
