// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::models::internal::nat::prefixtrie::{PrefixTrie, TrieError};
use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

#[derive(Debug)]
pub struct NatTables {
    pub tables: HashMap<u32, VniTable>,
}

/// An object containing the rules for the NAT pipeline stage, not in terms of states for the
/// different connections established, but instead holding the base rules for stateful or static
/// NAT.
impl NatTables {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    pub fn add_table(&mut self, vni: Vni, table: VniTable) {
        self.tables.insert(vni.as_u32(), table);
    }
}

#[derive(Debug)]
pub struct VniTable {
    pub table_dst_nat: NatPrefixRuleTable,
    pub table_src_nat_peers: NatPeerRuleTable,
    pub table_src_nat_prefixes: Vec<NatPrefixRuleTable>,
}

impl VniTable {
    pub fn new() -> Self {
        Self {
            table_dst_nat: NatPrefixRuleTable::new(),
            table_src_nat_peers: NatPeerRuleTable::new(),
            table_src_nat_prefixes: Vec::new(),
        }
    }

    pub fn lookup_src_prefix(&self, addr: &IpAddr) -> Option<&TrieValue> {
        // Find relevant prefix table for involved peer
        let peer_index = self.table_src_nat_peers.lookup(addr)?;

        // Look up for the NAT prefix in that table
        let prefix_table = self.table_src_nat_prefixes.get(peer_index)?;
        let (_, value) = prefix_table.lookup(addr)?;

        value.as_ref()
    }

    pub fn lookup_dst_prefix(&self, addr: &IpAddr) -> Option<&TrieValue> {
        // Look up for the NAT prefix in the table
        let (_, value) = self.table_dst_nat.lookup(addr)?;

        value.as_ref()
    }
}

/// From a current address prefix, find the target address prefix.
#[derive(Debug, Clone)]
pub struct NatPrefixRuleTable {
    pub rules: PrefixTrie<Option<TrieValue>>,
}

/// From a current address prefix, find the relevant [`NatPrefixRuleTable`] for the target prefix
/// lookup.
#[derive(Debug)]
pub struct NatPeerRuleTable {
    pub rules: PrefixTrie<usize>,
}

impl NatPrefixRuleTable {
    pub fn new() -> Self {
        Self {
            rules: PrefixTrie::new(),
        }
    }

    pub fn insert(&mut self, key: &Prefix, value: TrieValue) -> Result<(), TrieError> {
        self.rules.insert(key, Some(value))
    }

    pub fn insert_none(&mut self, key: &Prefix) -> Result<(), TrieError> {
        self.rules.insert(key, None)
    }

    pub fn lookup(&self, addr: &IpAddr) -> Option<(Prefix, &Option<TrieValue>)> {
        self.rules.lookup(addr)
    }
}

impl NatPeerRuleTable {
    pub fn new() -> Self {
        Self {
            rules: PrefixTrie::new(),
        }
    }

    pub fn insert(&mut self, prefix: &Prefix, target_index: usize) -> Result<(), TrieError> {
        self.rules.insert(prefix, target_index)
    }

    pub fn lookup(&self, addr: &IpAddr) -> Option<usize> {
        self.rules.lookup(addr).map(|(_, v)| v).copied()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrieValue {
    orig: BTreeSet<Prefix>,
    orig_excludes: BTreeSet<Prefix>,
    target: BTreeSet<Prefix>,
    target_excludes: BTreeSet<Prefix>,
}

impl TrieValue {
    pub fn new(
        orig: BTreeSet<Prefix>,
        orig_excludes: BTreeSet<Prefix>,
        target: BTreeSet<Prefix>,
        target_excludes: BTreeSet<Prefix>,
    ) -> Self {
        Self {
            orig,
            orig_excludes,
            target,
            target_excludes,
        }
    }

    /// Accessor for original prefixes
    pub fn orig_prefixes(&self) -> &BTreeSet<Prefix> {
        &self.orig
    }

    /// Accessor for original exclusion prefixes
    pub fn orig_excludes(&self) -> &BTreeSet<Prefix> {
        &self.orig_excludes
    }

    /// Accessor for target prefixes
    pub fn target_prefixes(&self) -> &BTreeSet<Prefix> {
        &self.target
    }

    /// Accessor for target exclusion prefixes
    pub fn target_excludes(&self) -> &BTreeSet<Prefix> {
        &self.target_excludes
    }

    /// Iterates over the original prefixes
    pub fn orig_prefixes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.orig.iter()
    }

    /// Iterates over the original exclusion prefixes
    pub fn orig_excludes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.orig_excludes.iter()
    }

    /// Iterates over the target prefixes
    pub fn target_prefixes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.target.iter()
    }

    /// Iterates over the target exclusion prefixes
    pub fn target_excludes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.target_excludes.iter()
    }
}
