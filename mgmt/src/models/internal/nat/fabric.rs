// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::models::internal::nat::prefixtrie::{PrefixTrie, TrieError};
use crate::models::internal::nat::tables::{NatPrefixRuleTable, VniTable};
use routing::prefix::Prefix;
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct PeeringIps {
    pub cidr: Prefix,
}

#[derive(Debug, Clone)]
pub struct PeeringAs {
    pub cidr: Prefix,
}

#[derive(Debug, Clone)]
pub struct PeeringEntry {
    pub internal: Vec<PeeringIps>,
    pub external: Vec<PeeringAs>,
}

#[derive(Debug, Clone)]
pub struct Peering {
    pub name: String,
    pub entries: HashMap<String, PeeringEntry>,
}

#[tracing::instrument(level = "trace")]
pub fn add_peering(vrf: &mut VniTable, peering: &Peering) -> Result<(), TrieError> {
    peering.entries.iter().try_for_each(|(name, entry)| {
        match name {
            n if n == vrf.name() => {
                // Create new peering table for source NAT
                let mut peering_table = NatPrefixRuleTable::new();
                entry
                    .internal
                    .iter()
                    .zip(entry.external.iter())
                    .try_for_each(|(internal, external)| {
                        peering_table.insert(&internal.cidr, external.cidr.clone())
                    })?;
                vrf.table_src_nat_prefixes.push(peering_table);

                // Update peering table to make relevant prefixes point to
                // the new peering table
                let peering_index = vrf.table_src_nat_prefixes.len() - 1;
                entry.internal.iter().try_for_each(|internal| {
                    vrf.table_src_nat_peers
                        .rules
                        .insert(&internal.cidr, peering_index)
                })
            }
            _ => {
                // Update table for destination NAT
                entry
                    .internal
                    .iter()
                    .zip(entry.external.iter())
                    .try_for_each(|(internal, external)| {
                        vrf.table_dst_nat
                            .insert(&external.cidr, internal.cidr.clone())
                    })
            }
        }
    })
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

        let mut peering = Peering {
            name: "test_peering".into(),
            entries: HashMap::new(),
        };
        peering.entries.insert(
            "test_vpc1".into(),
            PeeringEntry {
                internal: vec![
                    PeeringIps {
                        cidr: prefix_v4("1.2.3.0/24"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("4.5.6.0/24"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("7.8.9.0/24"),
                    },
                    PeeringIps {
                        cidr: prefix_v6("abcd::/64"),
                    },
                ],
                external: vec![
                    PeeringAs {
                        cidr: prefix_v4("10.0.1.0/24"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("10.0.2.0/24"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("10.0.3.0/24"),
                    },
                    PeeringAs {
                        cidr: prefix_v6("1234::/64"),
                    },
                ],
            },
        );
        peering.entries.insert(
            "test_vpc2".into(),
            PeeringEntry {
                internal: vec![
                    PeeringIps {
                        cidr: prefix_v4("9.9.0.0/16"),
                    },
                    PeeringIps {
                        cidr: prefix_v4("99.99.0.0/16"),
                    },
                ],
                external: vec![
                    PeeringAs {
                        cidr: prefix_v4("1.1.0.0/16"),
                    },
                    PeeringAs {
                        cidr: prefix_v4("1.2.0.0/16"),
                    },
                ],
            },
        );

        assert_eq!(peering.name, "test_peering");
        assert_eq!(peering.entries.len(), 2);
        assert_eq!(
            peering
                .entries
                .get("test_vpc1")
                .expect("Failed to get entry")
                .internal
                .len(),
            4
        );
        assert_eq!(
            peering
                .entries
                .get("test_vpc2")
                .expect("Failed to get entry")
                .external
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
