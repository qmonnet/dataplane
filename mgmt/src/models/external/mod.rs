// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod configdb;
pub mod overlay;

use crate::models::external::configdb::gwconfig::GenId;
use crate::models::external::overlay::vpc::VpcId;
use crate::models::external::overlay::vpcpeering::VpcExpose;

use routing::prefix::Prefix;
use thiserror::Error;

/// The reasons why we may reject a configuration
#[derive(Debug, Error, PartialEq)]
pub enum ApiError {
    #[error("A VPC with name '{0}' already exists")]
    DuplicateVpcName(String),
    #[error("A VPC with id '{0}' already exists")]
    DuplicateVpcId(VpcId),
    #[error("VNI '{0}' is already in use")]
    DuplicateVpcVni(u32),
    #[error("A VPC peering with id '{0}' already exists")]
    DuplicateVpcPeeringId(String),
    #[error("The VPC peering '{0}' is incomplete")]
    IncompletePeeringData(String),
    #[error("A VPC peering object refers to non-existent VPC '{0}'")]
    NoSuchVpc(String),
    #[error("'{0}' is not a valid VNI")]
    InvalidVpcVni(u32),
    #[error("VPC peering name is missing")]
    MissingPeeringName,
    #[error("VPC manifest name is missing")]
    MissingManifestName,
    #[error("Manifest contains no 'expose'")]
    EmptyManifest,
    #[error("Config with id {0} not found")]
    NoSuchConfig(GenId),
    #[error("Failure applying config")]
    FailureApply,
    #[error("Forbidden")]
    Forbidden,
    #[error("Bad VPC Id")]
    BadVpcId(String),
    // Peering and VpcExpose validation
    #[error("Empty vpc.expose ('ips' or 'as' are empty)")]
    EmptyExpose,
    #[error("All prefixes are excluded (resulting 'ips' or 'as' is empty)")]
    ExcludedAllPrefixes(VpcExpose),
    #[error("Exclusion prefix not contained within existing allowed prefix")]
    OutOfRangeExclusionPrefix(Prefix),
    #[error("VPC prefixes overlap")]
    OverlappingPrefixes(Prefix, Prefix),
    #[error("Inconsistent IP version")]
    InconsistentIpVersion(VpcExpose),
    // NAT-specific
    #[error("Mismatched prefixes sizes for static NAT")]
    MismatchedPrefixSizes(u128, u128),
    // Other
}

/// Result-like type for configurations
pub type ApiResult = Result<(), ApiError>;
