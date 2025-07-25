// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod args;
mod drivers;
mod packet_processor;
mod statistics; // Add statistics module

use crate::args::{CmdArgs, Parser};
use drivers::dpdk::DriverDpdk;
use drivers::kernel::DriverKernel;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;
#[allow(unused)]
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::packet_processor::start_router;
use mgmt::processor::launch::start_mgmt;
use routing::RouterParamsBuilder;

// Import statistics functions
use crate::statistics::start_metrics_server;

fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_thread_names(true)
        .with_env_filter(EnvFilter::new("debug,tonic=off,h2=off"))
        .init();
}

fn setup_pipeline<Buf: PacketBufferMut>() -> DynPipeline<Buf> {
    let pipeline = DynPipeline::new();
    if false {
        /* replace false by true to try filters and write your own */
        let custom_filter = |_packet: &Packet<Buf>| -> bool {
            /* your own filter here */
            true
        };
        pipeline.add_stage(PacketDumper::new(
            "default",
            true,
            Some(Box::new(custom_filter)),
        ))
    } else {
        pipeline.add_stage(PacketDumper::new("default", true, None))
    }
}

fn main() {
    init_logging();
    info!("Starting gateway process...");

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");

    /* parse cmd line args */
    let args = CmdArgs::parse();

    let grpc_addr = match args.get_grpc_address() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid gRPC address configuration: {e}");
            panic!("Management service configuration error. Aborting...");
        }
    };

    /* router parameters */
    let Ok(config) = RouterParamsBuilder::default()
        .cli_sock_path(args.cli_sock_path())
        .cpi_sock_path(args.cpi_sock_path())
        .frr_agent_path(args.frr_agent_path())
        .build()
    else {
        error!("Bad router configuration");
        panic!("Bad router configuration");
    };

    // start the router and build a pipeline. `start_router` returns `InternalSetup` object
    // that we deconstruct here to feed different components.
    // TODO(fredi): reduce the number of args needed to start components by letting
    // `start_router` already provide those grouped in the proper types.
    let setup = match start_router(config) {
        Ok(setup) => setup,
        Err(e) => {
            error!("Failed to start router: {e}");
            panic!("Failed to start router: {e}");
        }
    };

    /* pipeline builder */
    let builder = move || setup.pipeline;

    /* mgmt: router objects */
    let router = setup.router;
    let router_ctl = router.get_ctl_tx();

    /* mgmt: nat table */
    let nattablew = setup.nattable;
    let vnitablesw = setup.vnitablesw;
    let vpcmapw = setup.vpcmapw;
    let statsr = setup.statsr;

    /* start management */
    if let Err(e) = start_mgmt(grpc_addr, router_ctl, nattablew, vnitablesw, vpcmapw) {
        error!("Failed to start gRPC server: {e}");
        panic!("Failed to start gRPC server: {e}");
    } else {
        info!("Management gRPC server started successfully");
    }

    // Start metrics server early in the process
    let _metrics_handle = if let Some(metrics_addr_result) = args.metrics_address() {
        match metrics_addr_result {
            Ok(metrics_addr) => match start_metrics_server(metrics_addr, statsr.clone()) {
                Ok(handle) => {
                    info!("Metrics server started on http://{metrics_addr}/metrics");
                    Some(handle)
                }
                Err(e) => {
                    error!("Failed to start metrics server: {}", e);
                    warn!("Continuing without metrics...");
                    None
                }
            },
            Err(e) => {
                error!("Invalid metrics address configuration: {}", e);
                warn!("Continuing without metrics...");
                None
            }
        }
    } else {
        info!("Metrics server disabled");
        None
    };

    /* start driver with the provided pipeline builder */
    match args.get_driver_name() {
        "dpdk" => {
            info!("Using driver DPDK...");
            DriverDpdk::start(args.eal_params(), &setup_pipeline);
        }
        "kernel" => {
            info!("Using driver kernel...");
            DriverKernel::start(args.kernel_params(), builder);
        }
        other => {
            error!("Unknown driver '{other}'. Aborting...");
            panic!("Packet processing pipeline failed to start. Aborting...");
        }
    }

    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    std::process::exit(0);
}
