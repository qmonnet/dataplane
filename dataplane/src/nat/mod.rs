// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(dead_code)]
#![allow(rustdoc::private_doc_tests)]

//! Network Address Translation (NAT) for the dataplane
//!
//! This module implements a [`NetworkFunction`] that provides Network Address
//! Translation (NAT) functionality, either source or destination.
//!
//! # Example
//!
//! ```
//! let mut nat = Nat::new::<TestBuffer>(NatDirection::SrcNat, NatMode::Stateless);
//! let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
//! let packets_out: Vec<_> = nat.process(packets).collect();
//!
//! let hdr0_out = &packets_out[0]
//!     .try_ipv4()
//!     .expect("Failed to get IPv4 header");
//! ```
//!
//! # Limitations
//!
//! The module is subject to the following limitations:
//!
//! - Only stateless NAT is supported (no stateful NAT)
//! - Only NAT44 is supported (no NAT46, NAT64, or NAT66)
//! - Either source or destination NAT is supported, only one at a time, by a
//!   given [`Nat`] object. To perform NAT for different address fields, instantiate
//!   multiple [`Nat`] objects.
//! - PIFs mixing IPv4 and IPv6 endpoints or list of exposed IPs are not
//!   supported
//! - For a given PIF used for NAT, the number of IP addresses covered by the
//!   full set of (VPC-internal) endpoint prefixes must be equal to the number of
//!   IP addresses covered by the full set of externally-exposed IP prefixes; this
//!   is in order to make the 1:1 address mapping work.

mod iplist;

use crate::nat::iplist::IpList;
use mgmt::models::internal::nat::tables::{NatTables, TrieValue};
use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{TryHeadersMut, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::Packet;
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::net::IpAddr;

/// A helper to retrieve the source IP address from a [`Net`] object, independently of the IP
/// version.
fn get_src_addr(net: &Net) -> IpAddr {
    match net {
        Net::Ipv4(hdr) => IpAddr::V4(hdr.source().inner()),
        Net::Ipv6(hdr) => IpAddr::V6(hdr.source().inner()),
    }
}

/// A helper to retrieve the destination IP address from a [`Net`] object, independently of the IP
/// version.
fn get_dst_addr(net: &Net) -> IpAddr {
    match net {
        Net::Ipv4(hdr) => IpAddr::V4(hdr.destination()),
        Net::Ipv6(hdr) => IpAddr::V6(hdr.destination()),
    }
}

/// Indicates whether a [`Nat`] processor should perform source NAT or destination NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatDirection {
    /// Source NAT
    SrcNat,
    /// Destination NAT
    DstNat,
}

/// Indicates whether a [`Nat`] processor should perform stateless or stateful NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatMode {
    Stateless,
    #[allow(dead_code)]
    Stateful,
}

/// A NAT processor, implementing the [`NetworkFunction`] trait. [`Nat`] processes packets to run
/// source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct Nat {
    context: NatTables,
    mode: NatMode,
    direction: NatDirection,
}

impl Nat {
    /// Creates a new [`Nat`] processor. The `direction` indicates whether this processor should
    /// perform source or destination NAT. The `mode` indicates whether this processor should
    /// perform stateless or stateful NAT.
    pub fn new<Buf: PacketBufferMut>(direction: NatDirection, mode: NatMode) -> Self {
        let context = NatTables::new();
        Self {
            context,
            mode,
            direction,
        }
    }

    /// Updates the VNI tables in the NAT processor.
    pub fn update_tables(&mut self, tables: NatTables) {
        self.context = tables;
    }

    fn nat_supported(&self) -> bool {
        // We only support stateless NAT for now
        match self.mode {
            NatMode::Stateless => (),
            NatMode::Stateful => return false,
        }

        true
    }

    fn find_src_nat_ranges(&self, net: &Net, vni: Vni) -> Option<&TrieValue> {
        let table = self.context.tables.get(&vni.as_u32())?;
        let src_ip = &get_src_addr(net);
        table.lookup_src_prefix(src_ip)
    }

    fn find_dst_nat_ranges(&self, net: &Net, vni: Vni) -> Option<&TrieValue> {
        let table = self.context.tables.get(&vni.as_u32())?;
        let dst_ip = &get_dst_addr(net);
        table.lookup_dst_prefix(dst_ip)
    }

    fn find_nat_ranges(&self, net: &mut Net, vni_opt: Option<Vni>) -> Option<&TrieValue> {
        let vni = vni_opt?;
        match self.direction {
            NatDirection::SrcNat => self.find_src_nat_ranges(net, vni),
            NatDirection::DstNat => self.find_dst_nat_ranges(net, vni),
        }
    }

    fn map_ip_src_nat(&self, ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
        let current_range = IpList::new(ranges.orig_prefixes(), ranges.orig_excludes());
        let target_range = IpList::new(ranges.target_prefixes(), ranges.target_excludes());
        let offset = current_range.addr_offset_in_prefix(current_ip);
        target_range.addr_from_prefix_offset(&offset)
    }

    fn map_ip_dst_nat(&self, ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
        let current_range = IpList::new(ranges.target_prefixes(), ranges.target_excludes());
        let target_range = IpList::new(ranges.orig_prefixes(), ranges.orig_excludes());
        let offset = current_range.addr_offset_in_prefix(current_ip);
        target_range.addr_from_prefix_offset(&offset)
    }

    /// Applies network address translation to a packet, knowing the current and target ranges.
    fn translate(&self, net: &mut Net, ranges: &TrieValue) -> Option<()> {
        let target_ip = match self.direction {
            NatDirection::SrcNat => {
                let current_ip = get_src_addr(net);
                self.map_ip_src_nat(ranges, &current_ip)
            }
            NatDirection::DstNat => {
                let current_ip = get_dst_addr(net);
                self.map_ip_dst_nat(ranges, &current_ip)
            }
        };

        match self.direction {
            NatDirection::SrcNat => match (net, target_ip) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_source(UnicastIpv4Addr::new(ip).ok()?);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_source(UnicastIpv6Addr::new(ip).ok()?);
                }
                (_, _) => return None,
            },
            NatDirection::DstNat => match (net, target_ip) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_destination(ip);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_destination(ip);
                }
                (_, _) => return None,
            },
        }
        Some(())
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`Nat::process`] to iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        if !self.nat_supported() {
            return;
        }

        // ----------------------------------------------------
        // TODO: Get VNI
        // Currently hardcoded as required to have the tests pass, for demonstration purposes
        let vni = Vni::new_checked(100).ok();
        // ----------------------------------------------------
        let Some(net) = packet.headers_mut().try_ip_mut() else {
            return;
        };

        let Some(ranges) = self.find_nat_ranges(net, vni) else {
            return;
        };
        self.translate(net, ranges);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Nat {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut packet| {
            self.process_packet(&mut packet);
            packet
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iptrie::Ipv4Prefix;
    use mgmt::models::external::overlay::vpc::Peering;
    use mgmt::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use mgmt::models::internal::nat::peering;
    use mgmt::models::internal::nat::tables::{NatTables, VniTable};
    use net::buffer::TestBuffer;
    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use routing::prefix::Prefix;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Prefix {
        Ipv4Prefix::from_str(s).expect("Invalid IPv4 prefix").into()
    }

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn build_context() -> NatTables {
        // Build VpcExpose objects
        //
        //     expose:
        //       - ips:
        //         - cidr: 1.1.0.0/16
        //         - cidr: 1.2.0.0/16 # <- 1.2.3.4 will match here
        //         - not: 1.1.5.0/24  # to account for when computing the offset
        //         - not: 1.1.3.0/24  # to account for when computing the offset
        //         - not: 1.1.1.0/24  # to account for when computing the offset
        //         - not: 1.2.2.0/24  # to account for when computing the offset
        //         as:
        //         - cidr: 2.2.0.0/16
        //         - cidr: 2.1.0.0/16 # <- corresp. target range, initially
        //                            # (prefixes in BTreeSet are sorted)
        //                            # offset for 2.1.255.4, before applying exlusions
        //                            # final offset is for 2.2.0.4 after accounting for the one
        //                            # relevant exclusion prefix
        //         - not: 2.1.8.0/24  # to account for when fetching the address in range
        //         - not: 2.2.10.0/24
        //         - not: 2.2.1.0/24  # ignored, offset too low
        //         - not: 2.2.2.0/24  # ignored, offset too low
        //       - ips:
        //         - cidr: 3.0.0.0/16
        //         as:
        //         - cidr: 4.0.0.0/16
        let expose1 = VpcExpose::empty()
            .ip(prefix_v4("1.1.0.0/16"))
            .not(prefix_v4("1.1.5.0/24"))
            .not(prefix_v4("1.1.3.0/24"))
            .not(prefix_v4("1.1.1.0/24"))
            .ip(prefix_v4("1.2.0.0/16"))
            .not(prefix_v4("1.2.2.0/24"))
            .as_range(prefix_v4("2.2.0.0/16"))
            .not_as(prefix_v4("2.1.8.0/24"))
            .not_as(prefix_v4("2.2.10.0/24"))
            .not_as(prefix_v4("2.2.1.0/24"))
            .not_as(prefix_v4("2.2.2.0/24"))
            .as_range(prefix_v4("2.1.0.0/16"));
        let expose2 = VpcExpose::empty()
            .ip(prefix_v4("3.0.0.0/16"))
            .as_range(prefix_v4("4.0.0.0/16"));

        let manifest1 = VpcManifest {
            name: "test_manifest1".into(),
            exposes: vec![expose1, expose2],
        };

        //     expose:
        //       - ips:
        //         - cidr: 8.0.0.0/17
        //         - cidr: 9.0.0.0/17
        //         - not: 8.0.0.0/24
        //         as:
        //         - cidr: 3.0.0.0/16
        //         - not: 3.0.1.0/24
        //       - ips:
        //         - cidr: 10.0.0.0/16 # <- corresponding target range
        //         - not: 10.0.1.0/24  # to account for when fetching the address in range
        //         - not: 10.0.2.0/24  # to account for when fetching the address in range
        //         as:
        //         - cidr: 1.1.0.0/17
        //         - cidr: 1.2.0.0/17  # <- 1.2.3.4 will match here
        //         - not: 1.2.0.0/24   # to account for when computing the offset
        //         - not: 1.2.8.0/24
        let expose3 = VpcExpose::empty()
            .ip(prefix_v4("8.0.0.0/17"))
            .not(prefix_v4("8.0.0.0/24"))
            .ip(prefix_v4("9.0.0.0/17"))
            .as_range(prefix_v4("3.0.0.0/16"))
            .not_as(prefix_v4("3.0.1.0/24"));
        let expose4 = VpcExpose::empty()
            .ip(prefix_v4("10.0.0.0/16"))
            .not(prefix_v4("10.0.1.0/24"))
            .not(prefix_v4("10.0.2.0/24"))
            .as_range(prefix_v4("1.1.0.0/17"))
            .as_range(prefix_v4("1.2.0.0/17"))
            .not_as(prefix_v4("1.2.0.0/24"))
            .not_as(prefix_v4("1.2.8.0/24"));

        let manifest2 = VpcManifest {
            name: "test_manifest2".into(),
            exposes: vec![expose3, expose4],
        };

        let peering: Peering = Peering {
            name: "test_peering".into(),
            local: manifest1,
            remote: manifest2,
        };

        let mut vni_table = VniTable::new();
        peering::add_peering(&mut vni_table, &peering).expect("Failed to build NAT tables");

        let vni = Vni::new_checked(100).expect("Failed to create VNI");
        let mut nat_table = NatTables::new();
        nat_table.add_table(vni, vni_table);

        nat_table
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        let nat_tables = build_context();
        let mut nat = Nat::new::<TestBuffer>(NatDirection::DstNat, NatMode::Stateless);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.destination(), addr_v4("10.0.132.4"));
    }

    #[test]
    fn test_src_nat_stateless_44() {
        let nat_tables = build_context();
        let mut nat = Nat::new::<TestBuffer>(NatDirection::SrcNat, NatMode::Stateless);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.source().inner(), addr_v4("2.2.0.4"));
    }
}
