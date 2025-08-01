// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv4 address types

use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};

/// Thin wrapper around [`Ipv4Addr`]
///
/// This wrapper scopes addresses to be unicast.
///
/// This wrapper is zero cost save for the need to check that the [`Ipv4Addr`] is in fact unicast.
#[non_exhaustive]
#[repr(transparent)]
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct UnicastIpv4Addr(Ipv4Addr);

impl Debug for UnicastIpv4Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl UnicastIpv4Addr {
    /// Map an unqualified [`Ipv4Addr`] to a [`UnicastIpv4Addr`].
    ///
    /// # Errors
    ///
    /// Returns the supplied address back in the [`Err`] case if it is not a unicast address.
    pub fn new(ip: Ipv4Addr) -> Result<UnicastIpv4Addr, Ipv4Addr> {
        if ip.is_multicast() {
            Err(ip)
        } else {
            Ok(UnicastIpv4Addr(ip))
        }
    }

    /// Get the inner (wrapped) [`Ipv4Addr`]
    #[must_use]
    pub fn inner(&self) -> Ipv4Addr {
        self.0
    }
}

impl Display for UnicastIpv4Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<Ipv4Addr> for UnicastIpv4Addr {
    type Error = Ipv4Addr;

    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UnicastIpv4Addr> for Ipv4Addr {
    fn from(value: UnicastIpv4Addr) -> Self {
        value.inner()
    }
}

impl TryFrom<IpAddr> for UnicastIpv4Addr {
    type Error = IpAddr;
    fn try_from(value: IpAddr) -> Result<Self, Self::Error> {
        match value {
            IpAddr::V4(addr) => Ok(UnicastIpv4Addr(addr)),
            IpAddr::V6(_) => Err(value),
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ipv4::addr::UnicastIpv4Addr;
    use bolero::{Driver, TypeGenerator};
    use std::net::Ipv4Addr;

    impl TypeGenerator for UnicastIpv4Addr {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let raw = u.produce::<[u8; 4]>()?;
            let ip = Ipv4Addr::from(raw);
            if ip.is_multicast() {
                // multicast addresses start with 0b1110
                // Swap the top bit to map multicast space back to unicast space
                Some(UnicastIpv4Addr(Ipv4Addr::new(
                    raw[0] ^ 0b1000_0000,
                    raw[1],
                    raw[2],
                    raw[3],
                )))
            } else {
                Some(UnicastIpv4Addr(ip))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ipv4::addr::UnicastIpv4Addr;

    #[test]
    fn generated_unicast_ipv4_address_is_unicast() {
        bolero::check!()
            .with_type()
            .for_each(|unicast: &UnicastIpv4Addr| assert!(!unicast.0.is_multicast()));
    }
}
