// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Static NAT address mapping

use routing::prefix::Prefix;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

#[tracing::instrument(level = "trace")]
pub fn addr_offset_in_prefix(ip: &IpAddr, prefix: &Prefix) -> Option<u128> {
    if !prefix.covers_addr(ip) {
        return None;
    }
    match (ip, prefix.as_address()) {
        (IpAddr::V4(ip), IpAddr::V4(start)) => {
            Some(u128::from(ip.to_bits()) - u128::from(start.to_bits()))
        }
        (IpAddr::V6(ip), IpAddr::V6(start)) => Some(ip.to_bits() - start.to_bits()),
        // We can't have the prefix covering the address if we have an IP
        // version mismatch, and we'd have returned from the function earlier.
        _ => unreachable!(),
    }
}

#[tracing::instrument(level = "trace")]
pub fn addr_from_prefix_offset(prefix: &Prefix, offset: u128) -> Option<IpAddr> {
    if offset >= prefix.size() {
        return None;
    }
    match prefix.as_address() {
        IpAddr::V4(start) => {
            let bits = start.to_bits() + u32::try_from(offset).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(bits)))
        }
        IpAddr::V6(start) => {
            let bits = start.to_bits() + offset;
            Some(IpAddr::V6(Ipv6Addr::from(bits)))
        }
    }
}
