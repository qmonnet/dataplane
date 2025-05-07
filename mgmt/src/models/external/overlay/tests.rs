// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration tests and samples

#[cfg(test)]
#[allow(dead_code)]
pub mod test {
    use crate::models::external::ApiError;
    use crate::models::external::overlay::Overlay;
    use crate::models::external::overlay::display::VpcDetailed;
    use crate::models::external::overlay::vpc::{Vpc, VpcTable};
    use crate::models::external::overlay::vpcpeering::VpcExpose;
    use crate::models::external::overlay::vpcpeering::VpcManifest;
    use crate::models::external::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};

    use routing::prefix::Prefix;

    /* Build sample manifests for a peering */
    fn build_manifest_vpc1() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-1");
        let expose = VpcExpose::empty()
            .ip(Prefix::from(("10.0.0.0", 25)))
            .ip(Prefix::from(("10.0.2.128", 25)))
            .not(Prefix::from(("10.0.1.13", 32)))
            .not(Prefix::from(("10.0.2.130", 32)))
            .as_range(Prefix::from(("100.64.1.0", 24)))
            .not_as(Prefix::from(("100.64.1.13", 32)));
        m1.add_expose(expose).expect("Should succeed");
        m1
    }
    fn build_manifest_vpc2() -> VpcManifest {
        let mut m2 = VpcManifest::new("VPC-2");
        let expose = VpcExpose::empty()
            .ip(Prefix::from(("10.0.0.0", 24)))
            .as_range(Prefix::from(("100.64.2.0", 24)));

        m2.add_expose(expose).expect("Should succeed");
        m2
    }

    /* build sample peering between VPC-1 and VPC-2 */
    fn build_vpc_peering() -> VpcPeering {
        // build vpc manifests
        let m1 = build_manifest_vpc1();
        let m2 = build_manifest_vpc2();
        // build vpc peering with the manifests
        VpcPeering::new("VPC-1--VPC-2", m1, m2)
    }

    #[test]
    fn test_vpc_checks() {
        let mut vpc_table = VpcTable::new();

        /* invalid vni should be rejected */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 0);
        assert_eq!(vpc1, Err(ApiError::InvalidVpcVni(0)));

        /* add vpc with valid vni 3000 */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed");
        vpc_table.add(vpc1).expect("Should succeed");

        /* vpc with duplicate name should be rejected */
        let bad = Vpc::new("VPC-1", "BBBBB", 2000).expect("Should succeed");
        assert_eq!(
            vpc_table.add(bad),
            Err(ApiError::DuplicateVpcName("VPC-1".to_string()))
        );

        /* vpc with colliding VNI should be rejected */
        let bad = Vpc::new("VPC-2", "CCCCC", 3000).expect("Should succeed");
        assert_eq!(vpc_table.add(bad), Err(ApiError::DuplicateVpcVni(3000)));

        /* vpc with colliding Id should be rejected */
        let bad = Vpc::new("VPC-2", "AAAAA", 9000).expect("Should succeed");
        assert_eq!(
            vpc_table.add(bad),
            Err(ApiError::DuplicateVpcId("AAAAA".try_into().unwrap()))
        );

        /* vpc with bad Id should not build */
        let bad = Vpc::new("VPC-2", "AAA", 9000);
        assert_eq!(bad, Err(ApiError::BadVpcId("AAA".to_string())));

        /* vpc with bad Id should not build */
        let bad = Vpc::new("VPC-2", "!1234", 9000);
        assert_eq!(bad, Err(ApiError::BadVpcId("!1234".to_string())));
    }

    #[test]
    fn test_overlay_missing_vpc() {
        /* build VPCs */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed");

        /* build VPC table */
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).expect("Should succeed");

        /* build peering, referring to non-declared VPC VPC-2 */
        let peering = build_vpc_peering();

        /* build VPC pering table and add one peering */
        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering).expect("Should succeed");

        /* build overlay object and validate it */
        let overlay = Overlay::new(vpc_table, peering_table);
        assert_eq!(
            overlay.validate(),
            Err(ApiError::NoSuchVpc("VPC-2".to_owned()))
        );
    }

    #[test]
    fn test_overlay() {
        /* build VPCs */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed");
        let vpc2 = Vpc::new("VPC-2", "BBBBB", 4000).expect("Should succeed");

        /* build peering */
        let peering = build_vpc_peering();

        /* build VPC table */
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).expect("Should succeed");
        vpc_table.add(vpc2).expect("Should succeed");

        /* build VPC pering table and add one peering */
        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering).expect("Should succeed");

        println!("{peering_table}");

        /* build overlay object and validate it */
        let overlay = Overlay::new(vpc_table, peering_table);
        assert_eq!(overlay.validate(), Ok(()));
    }

    #[test]
    fn test_peering_iter() {
        let mut peering_table = VpcPeeringTable::new();

        let mut m1 = VpcManifest::new("VPC-1");
        m1.add_expose(
            VpcExpose::empty()
                .ip(Prefix::from(("1.1.1.0", 24)))
                .as_range(Prefix::from(("1.1.2.0", 24))),
        )
        .expect("Failed to add expose");
        let mut m2 = VpcManifest::new("VPC-2");
        m2.add_expose(
            VpcExpose::empty()
                .ip(Prefix::from(("1.2.1.0", 24)))
                .as_range(Prefix::from(("1.2.2.0", 24))),
        )
        .expect("Failed to add expose");
        let peering = VpcPeering::new("Peering-1", m1, m2);
        peering_table.add(peering).unwrap();

        let mut m1 = VpcManifest::new("VPC-1");
        m1.add_expose(
            VpcExpose::empty()
                .ip(Prefix::from(("2.1.1.0", 24)))
                .as_range(Prefix::from(("2.2.2.0", 24))),
        )
        .expect("Failed to add expose");
        let mut m2 = VpcManifest::new("VPC-3");
        m2.add_expose(
            VpcExpose::empty()
                .ip(Prefix::from(("2.2.1.0", 24)))
                .as_range(Prefix::from(("2.2.2.0", 24))),
        )
        .expect("Failed to add expose");
        let peering = VpcPeering::new("Peering-2", m1, m2);
        peering_table.add(peering).unwrap();

        let mut m1 = VpcManifest::new("VPC-2");
        m1.add_expose(
            VpcExpose::empty()
                .ip(Prefix::from(("3.1.1.0", 24)))
                .as_range(Prefix::from(("3.1.2.0", 24))),
        )
        .expect("Failed to add expose");
        let mut m2 = VpcManifest::new("VPC-4");
        m2.add_expose(
            VpcExpose::empty()
                .ip(Prefix::from(("3.2.1.0", 24)))
                .as_range(Prefix::from(("3.2.2.0", 24))),
        )
        .expect("Failed to add expose");
        let peering = VpcPeering::new("Peering-3", m1, m2);
        peering_table.add(peering).unwrap();

        let mut m1 = VpcManifest::new("VPC-1");
        m1.add_expose(
            VpcExpose::empty()
                .ip(Prefix::from(("4.1.1.0", 24)))
                .as_range(Prefix::from(("4.1.2.0", 24))),
        )
        .expect("Failed to add expose");
        let mut m2 = VpcManifest::new("VPC-4");
        m2.add_expose(
            VpcExpose::empty()
                .ip(Prefix::from(("4.2.1.0", 24)))
                .as_range(Prefix::from(("4.2.2.0", 24))),
        )
        .expect("Failed to add expose");
        let peering = VpcPeering::new("Peering-4", m1, m2);
        peering_table.add(peering).unwrap();

        // all peerings of VPC-1
        let x: Vec<String> = peering_table
            .peerings_vpc("VPC-1")
            .map(|p| p.name.clone())
            .collect();

        assert!(x.contains(&"Peering-1".to_owned()));
        assert!(x.contains(&"Peering-2".to_owned()));
        assert!(x.contains(&"Peering-4".to_owned()));
        assert!(!x.contains(&"Peering-3".to_owned()), "not there");
    }

    #[test]
    fn test_vpc_collect_peerings() {
        fn man_vpc1_with_vpc2() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-1");
            let expose = VpcExpose::empty()
                .ip(Prefix::from(("192.168.50.0", 24)))
                .not(Prefix::from(("192.168.50.13", 32)));
            m1.add_expose(expose).expect("Should succeed");

            let expose = VpcExpose::empty()
                .ip(Prefix::from(("192.168.111.0", 24)))
                .not(Prefix::from(("192.168.111.2", 32)))
                .not(Prefix::from(("192.168.111.254", 32)))
                .as_range(Prefix::from(("100.64.200.0", 24)))
                .not_as(Prefix::from(("100.64.200.13", 32)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc1_with_vpc3() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-1");
            let expose = VpcExpose::empty().ip(Prefix::from(("192.168.60.0", 24)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc1_with_vpc4() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-1");
            let expose = VpcExpose::empty().ip(Prefix::from(("192.168.70.0", 24)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc2_with_vpc1() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-2");
            let expose = VpcExpose::empty().ip(Prefix::from(("192.168.80.0", 24)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc2_with_vpc3() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-2");
            let expose = VpcExpose::empty().ip(Prefix::from(("192.168.90.0", 24)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc3_with_vpc1() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-3");
            let expose = VpcExpose::empty().ip(Prefix::from(("192.168.128.0", 27)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc3_with_vpc2() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-3");
            let expose = VpcExpose::empty().ip(Prefix::from(("192.168.128.32", 27)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc4_with_vpc1() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-4");
            let expose = VpcExpose::empty()
                .ip(Prefix::from(("192.168.201.1", 32)))
                .ip(Prefix::from(("192.168.202.2", 32)))
                .ip(Prefix::from(("192.168.203.3", 32)));
            m1.add_expose(expose).expect("Should succeed");

            let expose = VpcExpose::empty()
                .ip(Prefix::from(("192.168.204.4", 32)))
                .as_range(Prefix::from(("100.64.204.4", 32)));
            m1.add_expose(expose).expect("Should succeed");

            let expose = VpcExpose::empty()
                .ip(Prefix::from(("192.168.210.0", 29)))
                .not(Prefix::from(("192.168.210.1", 32)));
            m1.add_expose(expose).expect("Should succeed");

            m1
        }

        /* build VPC table with 3 vpcs */
        let mut vpc_table = VpcTable::new();
        let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed"));
        let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 4000).expect("Should succeed"));
        let _ = vpc_table.add(Vpc::new("VPC-3", "CCCCC", 2000).expect("Should succeed"));
        let _ = vpc_table.add(Vpc::new("VPC-4", "DDDDD", 6000).expect("Should succeed"));

        /* build peering table with 3 peerings */
        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-2",
                man_vpc1_with_vpc2(),
                man_vpc2_with_vpc1(),
            ))
            .expect("Should succeed");

        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-3",
                man_vpc1_with_vpc3(),
                man_vpc3_with_vpc1(),
            ))
            .expect("Should succeed");

        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-4",
                man_vpc1_with_vpc4(),
                man_vpc4_with_vpc1(),
            ))
            .expect("Should succeed");

        peering_table
            .add(VpcPeering::new(
                "VPC-2--VPC-3",
                man_vpc2_with_vpc3(),
                man_vpc3_with_vpc2(),
            ))
            .expect("Should succeed");

        /* display peering table */
        println!("{peering_table}");

        /* collect the peerings for each VPC */
        vpc_table.collect_peerings(&peering_table);

        /* display VPC table */
        println!("{vpc_table}");

        /* get vpc VPC1 */
        if let Some(vpc) = vpc_table.get_vpc("VPC-1") {
            println!("{}", VpcDetailed(vpc));
        }
    }
}
