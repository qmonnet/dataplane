// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display trait implementations

use crate::interface::{AdminState, OperationalState};
use crate::interface::{
    BridgeProperties, Interface, InterfaceProperties, VrfProperties, VtepProperties,
};
use crate::interface::{MultiIndexInterfaceMap, PciNetdevProperties};
use std::fmt::{Display, Formatter};
use std::string::ToString;

macro_rules! kernel_interface_fmt {
    () => {
        " {:>8} {:>8} {:>16} {:>8} {:>20} {:>8} {:>8} {:>8} {:}"
    };
}

fn fmt_kernel_interface_heading(f: &mut Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            kernel_interface_fmt!(),
            "index", "contrl", "name", "mtu", "mac", "Adm", "Oper", "type", "properties"
        )
    )
}

impl Display for AdminState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminState::Down => write!(f, "down"),
            AdminState::Up => write!(f, "up"),
        }
    }
}
impl Display for OperationalState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationalState::Down => write!(f, "down"),
            OperationalState::Up => write!(f, "up"),
            OperationalState::Unknown => write!(f, "unknown"),
            OperationalState::Complex => write!(f, "complex"),
        }
    }
}

impl Display for BridgeProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "vlan_filtering: {} vlan-proto: {:?}",
            self.vlan_filtering, self.vlan_protocol,
        )
    }
}

impl Display for VtepProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let vni = self
            .vni
            .as_ref()
            .map_or("--".to_string(), ToString::to_string);
        let ttl = self
            .ttl
            .as_ref()
            .map_or("--".to_string(), ToString::to_string);
        let local = self
            .local
            .as_ref()
            .map_or("--".to_string(), ToString::to_string);
        write!(f, "vni: {vni} ttl: {ttl} local: {local}")
    }
}

impl Display for VrfProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "table-id: {}", self.route_table_id)
    }
}

impl Display for PciNetdevProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.switch_id {
            None => {}
            Some(switch_id) => {
                write!(f, "switch-id: {switch_id}")?;
            }
        }
        match &self.port_name {
            None => {}
            Some(port_name) => {
                write!(f, "port-name: {port_name}")?;
            }
        }
        write!(f, "parent-dev: {}", self.parent_dev)
    }
}

impl Display for InterfaceProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceProperties::Bridge(bridge) => bridge.fmt(f),
            InterfaceProperties::Vrf(vrf) => vrf.fmt(f),
            InterfaceProperties::Vtep(vtep) => vtep.fmt(f),
            InterfaceProperties::Pci(rep) => rep.fmt(f),
            InterfaceProperties::Other => write!(f, "other"),
        }
    }
}

fn ifproperty_to_str(properties: &InterfaceProperties) -> &'static str {
    match properties {
        InterfaceProperties::Bridge(_) => "bridge",
        InterfaceProperties::Vrf(_) => "vrf",
        InterfaceProperties::Vtep(_) => "vtep",
        InterfaceProperties::Pci(_) => "pci",
        InterfaceProperties::Other => "other",
    }
}

impl Display for Interface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mac = self.mac.map(|mac| mac.to_string()).unwrap_or_default();
        let ctl = self
            .controller
            .map(|mac| mac.to_string())
            .unwrap_or_default();
        let mtu = self.mtu.map(|mtu| mtu.to_string()).unwrap_or_default();
        writeln!(
            f,
            "{}",
            format_args!(
                kernel_interface_fmt!(),
                self.index.to_string(),
                ctl,
                self.name.to_string(),
                mtu,
                mac,
                self.admin_state.to_string(),
                self.operational_state.to_string(),
                ifproperty_to_str(&self.properties),
                self.properties.to_string(),
            )
        )
    }
}

impl Display for MultiIndexInterfaceMap {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fmt_kernel_interface_heading(f)?;
        for iface in self.iter_by_index() {
            iface.fmt(f)?;
        }
        Ok(())
    }
}

pub struct MultiIndexInterfaceMapView<'a, F>
where
    F: Fn(&Interface) -> bool,
{
    pub map: &'a MultiIndexInterfaceMap,
    pub filter: &'a F,
}

impl<F: for<'a> Fn(&'a Interface) -> bool> Display for MultiIndexInterfaceMapView<'_, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fmt_kernel_interface_heading(f)?;
        let interfaces = self.map.iter().filter(|(_, iface)| (self.filter)(iface));
        for (_, iface) in interfaces {
            iface.fmt(f)?;
        }
        Ok(())
    }
}
