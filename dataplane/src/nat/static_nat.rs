// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Static NAT address mapping

use crate::nat::prefixtrie::{PrefixTrie, TrieError};
use net::vxlan::Vni;
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

/// From a current address prefix, find the target address prefix.
#[derive(Debug, Clone)]
pub struct NatPrefixRuleTable {
    pub rules: PrefixTrie<Prefix>,
}

/// From a current address prefix, find the relevant [`NatPrefixRuleTable`] for
/// the target prefix lookup.
#[derive(Debug)]
pub struct NatPeerRuleTable {
    pub rules: PrefixTrie<usize>,
}

impl NatPrefixRuleTable {
    #[tracing::instrument(level = "trace")]
    pub fn new() -> Self {
        Self {
            rules: PrefixTrie::with_roots(Prefix::root_v4(), Prefix::root_v6()),
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn insert(&mut self, key: &Prefix, value: Prefix) -> Result<(), TrieError> {
        self.rules.insert(key, value)
    }

    #[tracing::instrument(level = "trace")]
    pub fn lookup(&self, addr: &IpAddr) -> Option<(Prefix, &Prefix)> {
        self.rules.lookup(addr)
    }
}

impl NatPeerRuleTable {
    #[tracing::instrument(level = "trace")]
    pub fn new() -> Self {
        Self {
            rules: PrefixTrie::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn insert(&mut self, prefix: &Prefix, target_index: usize) -> Result<(), TrieError> {
        self.rules.insert(prefix, target_index)
    }

    #[tracing::instrument(level = "trace")]
    pub fn find(&self, addr: &IpAddr) -> Option<usize> {
        self.rules.find(addr).copied()
    }
}

#[derive(Debug)]
pub struct VniTable {
    name: String,
    vni: Vni,
    pub table_dst_nat: NatPrefixRuleTable,
    pub table_src_nat_peers: NatPeerRuleTable,
    pub table_src_nat_prefixes: Vec<NatPrefixRuleTable>,
}

impl VniTable {
    #[tracing::instrument(level = "trace")]
    pub fn new(name: String, vni: Vni) -> Self {
        Self {
            name,
            vni,
            table_dst_nat: NatPrefixRuleTable::new(),
            table_src_nat_peers: NatPeerRuleTable::new(),
            table_src_nat_prefixes: Vec::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn name(&self) -> &String {
        &self.name
    }

    #[tracing::instrument(level = "trace")]
    pub fn vni(&self) -> Vni {
        self.vni
    }

    #[tracing::instrument(level = "trace")]
    pub fn lookup_src_prefix(&self, addr: &IpAddr) -> Option<(Prefix, &Prefix)> {
        // Find relevant prefix table for involved peer
        let peer_index = self.table_src_nat_peers.find(addr)?;

        // Look up for the NAT prefix in that table
        if let Some(table) = self.table_src_nat_prefixes.get(peer_index) {
            table.lookup(addr)
        } else {
            None
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn lookup_dst_prefix(&self, addr: &IpAddr) -> Option<(Prefix, &Prefix)> {
        self.table_dst_nat.lookup(addr)
    }
}
