// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub(crate) use clap::Parser;
#[derive(Parser)]
#[command(name = "Hedgehog Fabric Gateway dataplane")]
#[command(version = "1.0")] // FIXME
#[command(about = "A next-gen dataplane for next-gen fabric gateway", long_about = None)]
pub(crate) struct CmdArgs {
    #[arg(long, value_name = "core-id used as main", default_value_t = 2)]
    main_lcore: u8,
    #[arg(long, value_name = "map lcore set to cpu set")]
    lcores: Option<String>,
    #[arg(long, value_name = "in-memory flag", default_value_t = false)]
    in_memory: bool,
    #[arg(long, value_name = "PCI devices to probe")]
    allow: Vec<String>,
    #[arg(long, value_name = "huge pages", default_value_t = 8192)]
    huge_worker_stack: u32,
    #[arg(long, value_name = "socket memory")]
    socket_mem: Option<String>,
    #[arg(long, value_name = "iova mode(va|pa)")]
    iova_mode: Option<String>,
    #[arg(long, value_name = "loglevel for a specific component")]
    log_level: Vec<String>,
    // other non-EAL params (NAT, routing, etc.)
}
impl CmdArgs {
    pub fn eal_params(&self) -> Vec<String> {
        let mut out = Vec::new();

        out.push("--main-lcore".to_owned());
        out.push(self.main_lcore.to_string());

        out.push("--lcores".to_string());
        out.push(
            self.lcores
                .clone()
                .map_or_else(|| "2-4".to_owned(), |lcores| lcores.to_owned()),
        );

        if self.in_memory {
            out.push("--in-memory".to_string());
        }

        /* IOVA mode */
        out.push(format!(
            "--iova-mode={}",
            &self
                .iova_mode
                .clone()
                .map_or_else(|| { "va".to_owned() }, |mode| mode.to_owned())
        ));

        /* worker huge page stack size */
        out.push(format!("--huge-worker-stack={}", self.huge_worker_stack));

        /* --allow */
        for a in self.allow.iter() {
            out.push("--allow".to_string());
            out.push(a.to_owned());
        }

        /* --log-level */
        for level in self.log_level.iter() {
            out.push("--log-level".to_string());
            out.push(level.to_owned());
        }

        out
    }
}
