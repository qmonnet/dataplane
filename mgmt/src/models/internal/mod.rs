// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane internal configuration model and builders.
//! The internal configuration model is the source of truth wrt to the gateway configuration.
//! Any configuration received externally (e.g. via gRPC) causes an internal configuration to be built and applied.
//! This module should contain all the tools to build a configuration in memory.

#![allow(unused)]

pub mod device;
pub mod interfaces;
pub mod nat;
pub mod routing;

use derive_builder::Builder;

use crate::models::external::configdb::gwconfig::GenId;

use crate::models::internal::device::DeviceConfig;
use crate::models::internal::interfaces::interface::{InterfaceConfig, InterfaceConfigTable};
use crate::models::internal::routing::evpn::VtepConfig;
use crate::models::internal::routing::frr::Frr;
use crate::models::internal::routing::prefixlist::{PrefixList, PrefixListTable};
use crate::models::internal::routing::routemap::{RouteMap, RouteMapTable};
use crate::models::internal::routing::vrf::{VrfConfig, VrfConfigTable};

#[derive(Debug)]
/* Main internal GW configuration */
pub struct InternalConfig {
    pub dev_cfg: DeviceConfig,
    pub frr: Frr,
    pub vtep: Option<VtepConfig>, // As a network interface
    pub vrfs: VrfConfigTable,
    pub plist_table: PrefixListTable,
    pub rmap_table: RouteMapTable,
}

impl InternalConfig {
    pub fn new(dev_cfg: DeviceConfig) -> Self {
        let frr = Frr::new(
            routing::frr::FrrProfile::Datacenter,
            &dev_cfg.settings.hostname,
        );
        Self {
            dev_cfg,
            frr,
            vtep: None,
            vrfs: VrfConfigTable::new(),
            plist_table: PrefixListTable::new(),
            rmap_table: RouteMapTable::new(),
        }
    }
    pub fn set_vtep(&mut self, vtep: VtepConfig) {
        self.vtep = Some(vtep);
    }
    pub fn add_vrf_config(&mut self, vrf_cfg: VrfConfig) {
        self.vrfs.add_vrf_config(vrf_cfg);
    }
    pub fn add_prefix_list(&mut self, plist: PrefixList) {
        self.plist_table.add_prefix_list(plist);
    }
    pub fn add_route_map(&mut self, rmap: RouteMap) {
        self.rmap_table.add_route_map(rmap);
    }
}
