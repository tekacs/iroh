use std::{
    collections::BTreeMap,
    fmt,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};
use tracing::{trace, warn};

use super::{ProbeReport, probes::Probe};

/// A net_report report.
#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
#[non_exhaustive]
pub struct Report {
    /// A QAD IPv4 round trip completed.
    pub udp_v4: bool,
    /// A QAD IPv6 round trip completed.
    pub udp_v6: bool,
    /// Whether the reported public address differs when probing different servers (on IPv4).
    pub mapping_varies_by_dest_ipv4: Option<bool>,
    /// Whether the reported public address differs when probing different servers (on IPv6).
    pub mapping_varies_by_dest_ipv6: Option<bool>,
    /// The relay server with the lowest latency, if any.
    pub preferred_relay: Option<RelayUrl>,
    /// The measured latency to each relay, keyed by relay URL.
    pub relay_latency: RelayLatencies,
    /// The discovered global IPv4 address and port, if any.
    pub global_v4: Option<SocketAddrV4>,
    /// The discovered global IPv6 address and port, if any.
    pub global_v6: Option<SocketAddrV6>,
    /// CaptivePortal is set when we think there's a captive portal that is
    /// intercepting HTTP traffic.
    pub captive_portal: Option<bool>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

impl Report {
    /// Do we have any indication that UDP is working?
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn has_udp(&self) -> bool {
        self.udp_v4 || self.udp_v6
    }

    /// Whether the reported public address differs when probing different servers.
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn mapping_varies_by_dest(&self) -> Option<bool> {
        match (
            self.mapping_varies_by_dest_ipv4,
            self.mapping_varies_by_dest_ipv6,
        ) {
            (Some(v4), Some(v6)) => Some(v4 || v6),
            (None, Some(v6)) => Some(v6),
            (Some(v4), None) => Some(v4),
            (None, None) => None,
        }
    }
}

/// Collects the latest observation per relay without publishing construction state.
#[derive(Debug, Default)]
pub(super) struct Builder {
    pub(super) report: Report,
    #[cfg(not(wasm_browser))]
    v4: Mapping<SocketAddrV4>,
    #[cfg(not(wasm_browser))]
    v6: Mapping<SocketAddrV6>,
}

/// At most one observation per probed relay, in first-response order.
#[cfg(not(wasm_browser))]
#[derive(Debug)]
struct Mapping<A>(Vec<(RelayUrl, A)>);

#[cfg(not(wasm_browser))]
impl<A> Default for Mapping<A> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

#[cfg(not(wasm_browser))]
impl<A: Copy + Eq> Mapping<A> {
    fn update(&mut self, relay: RelayUrl, addr: A) -> (A, Option<bool>) {
        match self.0.iter_mut().find(|(url, _)| *url == relay) {
            Some((_, observed)) => *observed = addr,
            None => self.0.push((relay, addr)),
        }
        // Keep choosing the first responding relay, including its later changes.
        let primary = self.0[0].1;
        let varies =
            (self.0.len() > 1).then(|| self.0.iter().any(|(_, observed)| *observed != primary));
        (primary, varies)
    }
}

impl Builder {
    /// Applies a measurement, replacing previous observations from the same relay.
    pub(super) fn update(&mut self, report: &ProbeReport) {
        match report {
            ProbeReport::Https(report) => {
                self.report.relay_latency.update_relay(
                    report.relay.clone(),
                    report.latency,
                    Probe::Https,
                );
            }
            #[cfg(not(wasm_browser))]
            ProbeReport::QadIpv4(report) => {
                let SocketAddr::V4(addr) = report.addr else {
                    warn!("received IPv6 address from IPv4 QAD: {}", report.addr);
                    return;
                };
                self.report.relay_latency.update_relay(
                    report.relay.clone(),
                    report.latency,
                    Probe::QadIpv4,
                );
                let (global, varies) = self.v4.update(report.relay.clone(), addr);
                self.report.udp_v4 = true;
                self.report.global_v4 = Some(global);
                self.report.mapping_varies_by_dest_ipv4 = varies;
                trace!(?global, ?varies, "stored IPv4 QAD observation");
            }
            #[cfg(not(wasm_browser))]
            ProbeReport::QadIpv6(report) => {
                let SocketAddr::V6(addr) = report.addr else {
                    warn!("received IPv4 address from IPv6 QAD: {}", report.addr);
                    return;
                };
                self.report.relay_latency.update_relay(
                    report.relay.clone(),
                    report.latency,
                    Probe::QadIpv6,
                );
                let (global, varies) = self.v6.update(report.relay.clone(), addr);
                self.report.udp_v6 = true;
                self.report.global_v6 = Some(global);
                self.report.mapping_varies_by_dest_ipv6 = varies;
                trace!(?global, ?varies, "stored IPv6 QAD observation");
            }
        }
    }
}

#[cfg(all(test, not(wasm_browser)))]
mod tests {
    use super::*;
    use crate::net_report::reportgen::QadProbeReport;

    fn observe(builder: &mut Builder, relay: &str, addr: SocketAddr) {
        let report = QadProbeReport {
            relay: relay.parse().unwrap(),
            addr,
            latency: Duration::from_millis(1),
        };
        builder.update(&match addr {
            SocketAddr::V4(_) => ProbeReport::QadIpv4(report),
            SocketAddr::V6(_) => ProbeReport::QadIpv6(report),
        });
    }

    #[test]
    fn mapping_compares_latest_addresses_from_distinct_relays() {
        for ip in ["192.0.2.1", "2001:db8::1"] {
            let first = SocketAddr::new(ip.parse().unwrap(), 1000);
            let changed = SocketAddr::new(first.ip(), 2000);
            let mut builder = Builder::default();
            let a = "https://a.example.test";
            let b = "https://b.example.test";

            observe(&mut builder, a, first);
            observe(&mut builder, a, first);
            assert_eq!(builder.report.mapping_varies_by_dest(), None);

            // A new value between snapshot and subscription updates the primary
            // address, but is not evidence from a second destination.
            observe(&mut builder, a, changed);
            assert_eq!(builder.report.mapping_varies_by_dest(), None);
            let global = builder
                .report
                .global_v4
                .map(SocketAddr::V4)
                .or_else(|| builder.report.global_v6.map(SocketAddr::V6));
            assert_eq!(global, Some(changed));

            observe(&mut builder, b, changed);
            assert_eq!(builder.report.mapping_varies_by_dest(), Some(false));
            observe(&mut builder, b, first);
            assert_eq!(builder.report.mapping_varies_by_dest(), Some(true));
            observe(&mut builder, a, changed);
            assert_eq!(builder.report.mapping_varies_by_dest(), Some(true));

            // Replacing, rather than appending, observations allows convergence.
            observe(&mut builder, a, first);
            assert_eq!(builder.report.mapping_varies_by_dest(), Some(false));
        }
    }
}

/// Latencies per relay endpoint.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
pub struct RelayLatencies {
    #[cfg(not(wasm_browser))]
    ipv4: BTreeMap<RelayUrl, Duration>,
    #[cfg(not(wasm_browser))]
    ipv6: BTreeMap<RelayUrl, Duration>,
    https: BTreeMap<RelayUrl, Duration>,
}

impl RelayLatencies {
    /// Updates a relay's latency, if it is faster than before.
    pub(super) fn update_relay(&mut self, url: RelayUrl, latency: Duration, probe: Probe) {
        let list = match probe {
            Probe::Https => &mut self.https,
            #[cfg(not(wasm_browser))]
            Probe::QadIpv4 => &mut self.ipv4,
            #[cfg(not(wasm_browser))]
            Probe::QadIpv6 => &mut self.ipv6,
        };
        let old_latency = list.entry(url).or_insert(latency);
        if latency < *old_latency {
            *old_latency = latency;
        }
    }

    /// Merges another [`RelayLatencies`] into this one.
    ///
    /// For each relay the latency is updated using [`RelayLatencies::update_relay`].
    pub(super) fn merge(&mut self, other: &RelayLatencies) {
        for (url, latency) in other.https.iter() {
            self.update_relay(url.clone(), *latency, Probe::Https);
        }
        #[cfg(not(wasm_browser))]
        for (url, latency) in other.ipv4.iter() {
            self.update_relay(url.clone(), *latency, Probe::QadIpv4);
        }
        #[cfg(not(wasm_browser))]
        for (url, latency) in other.ipv6.iter() {
            self.update_relay(url.clone(), *latency, Probe::QadIpv6);
        }
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg(not(wasm_browser))]
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn iter(&self) -> impl Iterator<Item = (Probe, &'_ RelayUrl, Duration)> + '_ {
        self.https
            .iter()
            .map(|(url, l)| (Probe::Https, url, *l))
            .chain(self.ipv4.iter().map(|(url, l)| (Probe::QadIpv4, url, *l)))
            .chain(self.ipv6.iter().map(|(url, l)| (Probe::QadIpv6, url, *l)))
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg(wasm_browser)]
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn iter(&self) -> impl Iterator<Item = (Probe, &'_ RelayUrl, Duration)> + '_ {
        self.https.iter().map(|(k, v)| (Probe::Https, k, *v))
    }

    #[cfg(not(wasm_browser))]
    pub(super) fn is_empty(&self) -> bool {
        self.https.is_empty() && self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    #[cfg(wasm_browser)]
    pub(super) fn is_empty(&self) -> bool {
        self.https.is_empty()
    }

    /// Returns the lowest latency across records.
    pub(super) fn get(&self, url: &RelayUrl) -> Option<Duration> {
        let mut list = Vec::with_capacity(3);
        if let Some(val) = self.https.get(url) {
            list.push(*val);
        }
        #[cfg(not(wasm_browser))]
        if let Some(val) = self.ipv4.get(url) {
            list.push(*val);
        }
        #[cfg(not(wasm_browser))]
        if let Some(val) = self.ipv6.get(url) {
            list.push(*val);
        }
        list.into_iter().min()
    }
}
