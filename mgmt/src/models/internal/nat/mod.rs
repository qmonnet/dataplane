// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT internal models: tables for NAT rules
//!
//! This module provides the internal models for NAT rules, including the code to build the rule
//! tables from a configuration object

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]

#[allow(unused)]
pub mod peering;
mod prefixtrie;
pub mod tables;
