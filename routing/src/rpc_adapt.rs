// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Translation module for RPC.
//! Implements some conversion traits to perform minor adaptations from the types in the rpc
//! crate to the types used here. Strictly speaking, the conversions should be fallible. However,
//! in case of failure, there's little we can do other than logging. In addition, note that because
//! we disaggregate routing information internally (e.g. next-hops are separated from routes), some
//! of these methods incur information loss in that they are not reversible and into() would not
//! provide the expected results. Hence the use of the From trait is overloaded for convenience.

use crate::errors::RouterError;
use crate::evpn::{RmacEntry, RmacStore};
use crate::interfaces::iftablerw::IfTableReader;
use crate::rib::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::rib::nexthop::{FwAction, NhopKey};
use crate::rib::vrf::{Route, RouteNhop, RouteOrigin, Vrf};

use dplane_rpc::msg::{
    ForwardAction, IpRoute, NextHop, NextHopEncap, Rmac, RouteTableId, RouteType, VxlanEncap,
};
use lpm::prefix::Prefix;
use net::eth::mac::Mac;
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr};
use tracing::{error, warn};

impl From<RouteType> for RouteOrigin {
    fn from(value: RouteType) -> Self {
        match value {
            RouteType::Local => RouteOrigin::Local,
            RouteType::Connected => RouteOrigin::Connected,
            RouteType::Static => RouteOrigin::Static,
            RouteType::Ospf => RouteOrigin::Ospf,
            RouteType::Isis => RouteOrigin::Isis,
            RouteType::Bgp => RouteOrigin::Bgp,
            RouteType::Other => RouteOrigin::Other,
        }
    }
}
impl TryFrom<&VxlanEncap> for VxlanEncapsulation {
    type Error = RouterError;

    fn try_from(vxlan: &VxlanEncap) -> Result<Self, Self::Error> {
        Ok(VxlanEncapsulation {
            vni: Vni::new_checked(vxlan.vni).map_err(|_| {
                error!(
                    "Received VxLAN encapsulation with invalid vni {}",
                    vxlan.vni
                );
                RouterError::VniInvalid(vxlan.vni)
            })?,
            remote: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            // Note: dmac is not set in nhops, because it may not be known when the
            // next-hop is added and the encapsulation is part of the next-hop key
            // which should be immutable for keying purposes.
            // We ALWAYS set it to None when learning about next-hops via the CPI.
            // This happens because we want to reuse the VxlanEncapsulation type for other
            // purposes outside the Nhops. An alternative is to define yet another type.
            dmac: None,
        })
    }
}
impl TryFrom<&NextHopEncap> for Encapsulation {
    type Error = RouterError;

    fn try_from(value: &NextHopEncap) -> Result<Self, Self::Error> {
        match value {
            NextHopEncap::VXLAN(vxlan) => {
                Ok(Encapsulation::Vxlan(VxlanEncapsulation::try_from(vxlan)?))
            }
        }
    }
}
impl From<ForwardAction> for FwAction {
    fn from(value: ForwardAction) -> Self {
        match value {
            ForwardAction::Drop => FwAction::Drop,
            ForwardAction::Forward => FwAction::Forward,
        }
    }
}
impl TryFrom<&Rmac> for RmacEntry {
    type Error = RouterError;

    fn try_from(value: &Rmac) -> Result<Self, Self::Error> {
        Ok(Self {
            address: value.address,
            mac: Mac::from(value.mac.bytes()),
            vni: Vni::new_checked(value.vni).map_err(|_| {
                error!("Received router mac with invalid vni {}", value.vni);
                RouterError::VniInvalid(value.vni)
            })?,
        })
    }
}

impl RouteNhop {
    fn from_rpc_nhop(
        nh: &NextHop,
        origin: RouteOrigin,
        iftabler: &IfTableReader,
    ) -> Result<Self, RouterError> {
        let mut ifindex = nh.ifindex;
        let encap = match &nh.encap {
            Some(e) => {
                let mut enc = Encapsulation::try_from(e)?;
                if let Encapsulation::Vxlan(vxlan) = &mut enc {
                    if let Some(address) = nh.address {
                        vxlan.remote = address;
                    }
                    ifindex = None;
                }
                Some(enc)
            }
            None => None,
        };

        // lookup interface name
        let ifname = match ifindex {
            None => None,
            Some(0) => None,
            Some(k) => iftabler
                .enter()
                .map(|iftable| iftable.get_interface(k).map(|iface| iface.name.to_owned()))
                .flatten(),
        };

        Ok(RouteNhop {
            key: NhopKey::new(
                origin,
                nh.address,
                ifindex,
                encap,
                FwAction::from(nh.fwaction),
                ifname,
            ),
            vrfid: nh.vrfid,
        })
    }
}
impl Route {
    fn from_iproute(prefix: &Prefix, r: &IpRoute) -> Self {
        let origin = if r.rtype == RouteType::Connected && prefix.is_host() {
            RouteOrigin::Local
        } else {
            RouteOrigin::from(r.rtype)
        };

        Route {
            origin,
            distance: r.distance,
            metric: r.metric,
            s_nhops: Vec::with_capacity(1), /* shim nhops are empty here */
        }
    }
}

/// Util to tell if a route is EVPN - heuristic
pub fn is_evpn_route(iproute: &IpRoute) -> bool {
    if iproute.rtype != RouteType::Bgp || iproute.nhops.is_empty() {
        false
    } else {
        matches!(iproute.nhops[0].encap, Some(NextHopEncap::VXLAN(_)))
    }
}

impl Vrf {
    pub fn add_route_rpc(
        &mut self,
        iproute: &IpRoute,
        vrf0: Option<&Vrf>,
        rstore: &RmacStore,
        iftabler: &IfTableReader,
    ) {
        let Ok(prefix) = Prefix::try_from((iproute.prefix, iproute.prefix_len)) else {
            error!(
                "Failed to add route from RPC!: bad prefix={} len={}",
                iproute.prefix, iproute.prefix_len
            );
            return;
        };

        if let Some(tableid) = self.tableid {
            if iproute.tableid != RouteTableId::from(tableid) {
                warn!("Table id mismatch for {iproute}; vrf tableid is {tableid}");
            }
        }

        let route = Route::from_iproute(&prefix, iproute);
        let mut nhops = Vec::with_capacity(iproute.nhops.len());
        for nhop in &iproute.nhops {
            match RouteNhop::from_rpc_nhop(nhop, route.origin, iftabler) {
                Ok(nh) => nhops.push(nh),
                Err(e) => error!("Omitting next-hop in route to {prefix}: {e}"),
            }
        }
        // N.B. route and next-hops are passed separately
        self.add_route_complete(&prefix, route, &nhops, vrf0, rstore);
    }
    pub fn del_route_rpc(&mut self, iproute: &IpRoute) {
        let Ok(prefix) = Prefix::try_from((iproute.prefix, iproute.prefix_len)) else {
            error!(
                "Failed to remove route from RPC!: bad prefix={} len={}",
                iproute.prefix, iproute.prefix_len
            );
            return;
        };
        self.del_route(prefix);
    }
}
