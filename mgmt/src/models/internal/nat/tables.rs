// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::models::internal::nat::prefixtrie::{PrefixTrie, TrieError};
use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug)]
pub struct NatTables {
    pub tables: HashMap<u32, VniTable>,
}

/// An object containing the [`Nat`] object state, not in terms of stateful NAT
/// processing, but instead holding references to the different fabric objects
/// that the [`Nat`] component uses, namely VPCs and their PIFs, and peering
/// interfaces.
///
/// This context will likely change and be shared with other components in the
/// future.
impl NatTables {
    #[tracing::instrument(level = "trace")]
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn add_table(&mut self, vni: Vni, table: VniTable) {
        self.tables.insert(vni.as_u32(), table);
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
