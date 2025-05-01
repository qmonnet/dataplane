// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::models::external::overlay::vpc::Peering;
use crate::models::external::overlay::vpcpeering::VpcExpose;
use crate::models::internal::nat::prefixtrie::{PrefixTrie, TrieError};
use crate::models::internal::nat::tables::{NatPrefixRuleTable, TrieValue, VniTable};
use routing::prefix::Prefix;
use std::collections::BTreeSet;
use std::fmt::Debug;

fn get_public_trie_value(expose: &VpcExpose, prefix: &Prefix) -> Result<TrieValue, TrieError> {
    let orig = expose.ips.clone();
    let orig_excludes = expose.nots.clone();
    let target = expose.as_range.clone();
    let target_excludes = expose.not_as.clone();

    let mut excludes: PrefixTrie<()> = PrefixTrie::new();
    expose.nots.iter().try_for_each(|exclude| {
        // Only add excludes that are covered by the prefix
        if prefix.covers(exclude) {
            excludes.insert(exclude, ())?;
        }
        Ok(())
    })?;

    Ok(TrieValue::new(
        excludes,
        orig,
        orig_excludes,
        target,
        target_excludes,
    ))
}

fn get_private_trie_value(expose: &VpcExpose, prefix: &Prefix) -> Result<TrieValue, TrieError> {
    let orig = expose.ips.clone();
    let orig_excludes = expose.nots.clone();
    let target = expose.as_range.clone();
    let target_excludes = expose.not_as.clone();

    let mut excludes: PrefixTrie<()> = PrefixTrie::new();
    expose.not_as.iter().try_for_each(|exclude| {
        // Only add excludes that are covered by the prefix
        if prefix.covers(exclude) {
            excludes.insert(exclude, ())?;
        }
        Ok(())
    })?;

    Ok(TrieValue::new(
        excludes,
        orig,
        orig_excludes,
        target,
        target_excludes,
    ))
}

#[tracing::instrument(level = "trace")]
pub fn add_peering(table: &mut VniTable, peering: &Peering) -> Result<(), TrieError> {
    peering.local.exposes.iter().try_for_each(|expose| {
        // Create new peering table for source NAT
        let mut peering_table = NatPrefixRuleTable::new();

        // For each private prefix, add an entry containing the exclusion prefixes and the set of
        // public prefixes
        expose.ips.iter().try_for_each(|prefix| {
            let pub_value = get_public_trie_value(expose, prefix)?;
            peering_table.insert(prefix, pub_value)
        })?;

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
            let priv_value = get_private_trie_value(expose, prefix)?;
            table.table_dst_nat.insert(prefix, priv_value)
        })
    })?;

    Ok(())
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

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn addr_v6(s: &str) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from_str(s).expect("Invalid IPv6 address"))
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_fabric() {
        let mut vpc1 = VniTable::new(
            "test_vpc1".into(),
            Vni::new_checked(100).expect("Failed to create VNI"),
        );
        let mut vpc2 = VniTable::new(
            "test_vpc2".into(),
            Vni::new_checked(200).expect("Failed to create VNI"),
        );

        assert_eq!(vpc1.name(), "test_vpc1");
        assert_eq!(vpc1.vni().as_u32(), 100);
        assert_eq!(vpc2.name(), "test_vpc2");
        assert_eq!(vpc2.vni().as_u32(), 200);

        let mut peering = VpcPeering {
            name: "test_peering".into(),
            left: VpcManifest::new("test_vpc1"),
            right: VpcManifest::new("test_vpc2"),
        };
        peering.local.insert(
            "test_vpc1".into(),
            VpcPeering {
                vpc: VpcManifest {
                    exposes: vec![
                        VpcExpose {
                            cidr: prefix_v4("1.2.3.0/24"),
                        },
                        VpcExpose {
                            cidr: prefix_v4("4.5.6.0/24"),
                        },
                        VpcExpose {
                            cidr: prefix_v4("7.8.9.0/24"),
                        },
                        VpcExpose {
                            cidr: prefix_v6("abcd::/64"),
                        },
                    ],
                },
                exposes: vec![
                    VpcExpose {
                        cidr: prefix_v4("10.0.1.0/24"),
                    },
                    VpcExpose {
                        cidr: prefix_v4("10.0.2.0/24"),
                    },
                    VpcExpose {
                        cidr: prefix_v4("10.0.3.0/24"),
                    },
                    VpcExpose {
                        cidr: prefix_v6("1234::/64"),
                    },
                ],
            },
        );
        peering.local.insert(
            "test_vpc2".into(),
            VpcPeering {
                vpc: VpcManifest {
                    exposes: vec![
                        VpcExpose {
                            cidr: prefix_v4("9.9.0.0/16"),
                        },
                        VpcExpose {
                            cidr: prefix_v4("99.99.0.0/16"),
                        },
                    ],
                },
                exposes: vec![
                    VpcExpose {
                        cidr: prefix_v4("1.1.0.0/16"),
                    },
                    VpcExpose {
                        cidr: prefix_v4("1.2.0.0/16"),
                    },
                ],
            },
        );

        assert_eq!(peering.name, "test_peering");
        assert_eq!(peering.local.len(), 2);
        assert_eq!(
            peering
                .local
                .get("test_vpc1")
                .expect("Failed to get entry")
                .vpc
                .exposes
                .len(),
            4
        );
        assert_eq!(
            peering
                .remote
                .get("test_vpc2")
                .expect("Failed to get entry")
                .exposes
                .len(),
            2
        );

        assert_eq!(vpc1.table_src_nat_prefixes.len(), 0);

        add_peering(&mut vpc1, &peering).expect("Failed to add peering");
        add_peering(&mut vpc2, &peering).expect("Failed to add peering");

        assert_eq!(vpc1.table_src_nat_prefixes.len(), 1);

        assert_eq!(
            vpc1.lookup_src_prefix(&addr_v4("1.2.3.4")),
            Some((prefix_v4("1.2.3.0/24"), &prefix_v4("10.0.1.0/24")))
        );

        assert_eq!(
            vpc1.lookup_dst_prefix(&addr_v4("1.2.3.4")),
            Some((prefix_v4("1.2.0.0/16"), &prefix_v4("99.99.0.0/16")))
        );

        assert_eq!(
            vpc1.lookup_src_prefix(&addr_v6("abcd::5678")),
            Some((prefix_v6("abcd::/64"), &prefix_v6("1234::/64")))
        );
    }
}
