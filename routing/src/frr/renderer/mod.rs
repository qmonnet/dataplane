// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! FRR driver for frr-reload.py

pub mod bgp;
pub mod builder;
pub mod frr;
pub mod interface;
pub mod ospf;
pub mod prefixlist;
pub mod routemap;
pub mod statics;
pub mod vrf;

use crate::frr::renderer::builder::{ConfigBuilder, Render};
use crate::frr::renderer::vrf::{render_vrfs_bgp, render_vrfs_ospf};

use config::{GenId, InternalConfig};
use tracing::debug;

fn render_metadata(genid: &GenId) -> String {
    format!("! config for gen {genid}")
}

impl Render for InternalConfig {
    type Context = GenId;
    type Output = ConfigBuilder;
    fn render(&self, config: &Self::Context) -> Self::Output {
        debug!("Generating FRR config for genid {config}...");
        let mut cfg = ConfigBuilder::new();

        /* Metadata: TODO */
        cfg += render_metadata(config);

        /* we always enable logging on stdout */
        cfg += "log stdout";

        /* frr profile */
        cfg += self.frr.render(&());

        /* prefix lists */
        cfg += self.plist_table.render(&());

        /* vrfs */
        cfg += self.vrfs.render(&());

        /* interfaces live in vrfs. So, we iterate over all VRFs */
        self.vrfs
            .iter_by_tableid()
            .for_each(|vrf| cfg += vrf.interfaces.render(&()));

        /* Vrf BGP instances */
        cfg += render_vrfs_bgp(&self.vrfs);

        /* vrf OSPF instance */
        cfg += render_vrfs_ospf(&self.vrfs);

        /* route maps */
        cfg += self.rmap_table.render(&());

        cfg
    }
}
