// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT rule tables entries creation

use crate::models::external::overlay::vpc::Peering;
use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use crate::models::internal::nat::prefixtrie::{PrefixTrie, TrieError};
use crate::models::internal::nat::tables::{NatPrefixRuleTable, PerVniTable, TrieValue};
use routing::prefix::Prefix;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Create a [`TrieValue`] from the public side of a [`VpcExpose`], for a given prefix in this
/// [`VpcExpose`]
fn get_public_trie_value(expose: &VpcExpose, prefix: &Prefix) -> TrieValue {
    let orig = expose.ips.clone();
    let orig_excludes = expose.nots.clone();
    let target = expose.as_range.clone();
    let target_excludes = expose.not_as.clone();

    TrieValue::new(orig, orig_excludes, target, target_excludes)
}

/// Create a [`TrieValue`] from the private side of a [`VpcExpose`], for a given prefix in this
/// [`VpcExpose`]
fn get_private_trie_value(expose: &VpcExpose, prefix: &Prefix) -> TrieValue {
    let orig = expose.ips.clone();
    let orig_excludes = expose.nots.clone();
    let target = expose.as_range.clone();
    let target_excludes = expose.not_as.clone();

    TrieValue::new(orig, orig_excludes, target, target_excludes)
}

/// Add a [`Peering`] to a [`VniTable`]
pub fn add_peering(table: &mut PerVniTable, peering: &Peering) -> Result<(), TrieError> {
    peering.local.exposes.iter().try_for_each(|expose| {
        // Create new peering table for source NAT
        let mut peering_table = NatPrefixRuleTable::new();

        // For each private prefix, add an entry containing the exclusion prefixes and the set of
        // public prefixes
        expose.ips.iter().try_for_each(|prefix| {
            let pub_value = get_public_trie_value(expose, prefix);
            peering_table.insert(prefix, pub_value)
        })?;
        // Add "None" entries for excluded prefixes
        expose
            .nots
            .iter()
            .try_for_each(|prefix| peering_table.insert_none(prefix))?;

        // Add peering table to VniTable
        table.table_src_nat_prefixes.push(peering_table);

        // Update peering table to make relevant prefixes point to the new peering table, for each
        // private prefix
        let peering_index = table.table_src_nat_prefixes.len() - 1;
        expose.ips.iter().try_for_each(|prefix| {
            table
                .table_src_nat_peers
                .rules
                .insert(prefix, peering_index)
        })
    })?;

    // Update table for destination NAT
    peering.remote.exposes.iter().try_for_each(|expose| {
        // For each public prefix, add an entry containing the exclusion prefixes and the set of
        // private prefixes
        expose.as_range.iter().try_for_each(|prefix| {
            let priv_value = get_private_trie_value(expose, prefix);
            table.table_dst_nat.insert(prefix, priv_value)
        })?;
        // Add "None" entries for excluded prefixes
        expose
            .not_as
            .iter()
            .try_for_each(|prefix| table.table_dst_nat.insert_none(prefix))
    })?;

    Ok(())
}

/// Optimize a list of prefixes and their exclusions:
///
/// - Remove mutually-excluding prefixes/exclusion prefixes pairs
/// - Collapse prefixes and exclusion prefixes when possible
fn optimize_expose(
    prefixes: &BTreeSet<Prefix>,
    excludes: &BTreeSet<Prefix>,
) -> (BTreeSet<Prefix>, BTreeSet<Prefix>) {
    let mut clone = prefixes.clone();
    let mut clone_not = excludes.clone();
    // Sort excludes by mask length, descending.
    let mut excludes_sorted = excludes.iter().collect::<Vec<_>>();
    excludes_sorted.sort_by_key(|p| std::cmp::Reverse(p.length()));

    for prefix in prefixes {
        for exclude in &excludes_sorted {
            if !prefix.covers(exclude) {
                continue;
            }
            if prefix.length() == exclude.length() {
                // Prefix and exclusion prefix are the same. We can remove both.
                clone.remove(prefix);
                clone_not.remove(exclude);
            } else if prefix.length() == 2 * exclude.length() {
                // Exclusion prefixes is half of the prefix. We can transform the prefix by
                // extending its mask and keeping only the relevant portion, and discard the
                // exclusion prefix entirely.
                //
                // We want to try biggest exclusion prefixes first, to avoid "missing" optimization
                // for smaller exclusion prefixes before the one for bigger exclusion prefixes has
                // been applied. This is why we sorted the exclusion prefixes by mask length,
                // descending, at the beginning of the function.
                let new_length = prefix.length() + 1;
                let mut new_address;
                if prefix.as_address() == exclude.as_address() {
                    // Exclusion prefix covers the first half of the prefix.
                    // Here we need to update the address to keep the second half of the prefix.
                    new_address = match prefix.as_address() {
                        IpAddr::V4(addr) => {
                            let Ok(exclude_size) = u32::try_from(exclude.size()) else {
                                unreachable!(
                                    "Exclude size too big ({}), bug in IpList",
                                    exclude.size()
                                )
                            };
                            IpAddr::V4(Ipv4Addr::from(addr.to_bits() + exclude_size))
                        }
                        IpAddr::V6(addr) => {
                            IpAddr::V6(Ipv6Addr::from(addr.to_bits() + exclude.size()))
                        }
                        // Prefix cannot cover exclusion prefix of a different IP version
                        _ => unreachable!(
                            "Prefix and exclusion prefix are not of the same IP version"
                        ),
                    }
                } else {
                    // Exclusion prefix is the second half of the prefix; keep the first half.
                    new_address = prefix.as_address();
                }
                let new_prefix = Prefix::from((new_address, new_length));

                clone.remove(prefix);
                clone_not.remove(exclude);
                clone.insert(new_prefix);
            }
        }
    }
    (clone, clone_not)
}

/// Optimize a [`Peering`] object:
///
/// - Optimize both [`VpcManifest`] objects (see [`optimize_expose()`])
pub fn optimize_peering(peering: &Peering) -> Peering {
    // Collapse prefixes and exclusion prefixes
    let mut clone = peering.clone();
    for expose in &mut clone.local.exposes {
        let (ips, nots) = optimize_expose(&expose.ips, &expose.nots);
        expose.ips = ips;
        expose.nots = nots;
    }
    for expose in &mut clone.remote.exposes {
        let (as_range, not_as) = optimize_expose(&expose.as_range, &expose.not_as);
        expose.as_range = as_range;
        expose.not_as = not_as;
    }
    clone
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::internal::nat::tables::NatTables;
    use iptrie::{Ipv4Prefix, Ipv6Prefix};
    use net::vxlan::Vni;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Prefix {
        Ipv4Prefix::from_str(s).expect("Invalid IPv4 prefix").into()
    }

    fn prefix_v6(s: &str) -> Prefix {
        Ipv6Prefix::from_str(s).expect("Invalid IPv6 prefix").into()
    }

    #[test]
    fn test_fabric() {
        let expose1 = VpcExpose::empty()
            .ip(prefix_v4("1.1.0.0/16"))
            .not(prefix_v4("1.1.5.0/24"))
            .not(prefix_v4("1.1.3.0/24"))
            .not(prefix_v4("1.1.1.0/24"))
            .ip(prefix_v4("1.2.0.0/16"))
            .not(prefix_v4("1.2.2.0/24"))
            .as_range(prefix_v4("2.2.0.0/16"))
            .not_as(prefix_v4("2.1.10.0/24"))
            .not_as(prefix_v4("2.1.1.0/24"))
            .not_as(prefix_v4("2.1.8.0/24"))
            .not_as(prefix_v4("2.1.2.0/24"))
            .as_range(prefix_v4("2.1.0.0/16"));
        let expose2 = VpcExpose::empty()
            .ip(prefix_v4("3.0.0.0/16"))
            .as_range(prefix_v4("4.0.0.0/16"));

        let mut manifest1 = VpcManifest::new("VPC-1");
        manifest1.add_expose(expose1).expect("Failed to add expose");
        manifest1.add_expose(expose2).expect("Failed to add expose");

        let expose3 = VpcExpose::empty()
            .ip(prefix_v6("1::/64"))
            .not(prefix_v6("1::/128"))
            .as_range(prefix_v6("1:1::/64"))
            .not_as(prefix_v6("1:2::/128"));
        let expose4 = VpcExpose::empty()
            .ip(prefix_v6("2::/64"))
            .not(prefix_v6("2::/128"))
            .as_range(prefix_v6("2:4::/64"))
            .not_as(prefix_v6("2:9::/128"));

        let mut manifest2 = VpcManifest::new("VPC-2");
        manifest2.add_expose(expose3).expect("Failed to add expose");
        manifest2.add_expose(expose4).expect("Failed to add expose");

        let peering: Peering = Peering {
            name: "test_peering".into(),
            local: manifest1,
            remote: manifest2,
        };

        let mut vni_table = PerVniTable::new();
        add_peering(&mut vni_table, &peering).expect("Failed to build NAT tables");
    }
}
