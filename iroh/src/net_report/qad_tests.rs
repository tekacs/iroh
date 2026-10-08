//! Retained QAD observations across report rounds and real socket changes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use iroh_relay::{RelayQuicConfig, server};

use super::*;

struct Fixture {
    client: Client,
    ep: noq::Endpoint,
    servers: Vec<server::Server>,
    ipv6: bool,
}

impl Fixture {
    async fn new(ipv6: bool, count: usize) -> Option<Self> {
        let bind = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        if ipv6 {
            match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => {
                    eprintln!("skipping IPv6 QAD case: loopback unavailable ({err})");
                    return None;
                }
                Err(err) => panic!("failed to bind IPv6 loopback: {err}"),
            }
        }

        let mut servers = Vec::new();
        let mut relays = Vec::new();
        for _ in 0..count {
            let mut config = server::testing::server_config();
            config.relay = None;
            config.quic.as_mut().unwrap().bind_addr = (bind, 0).into();
            let server = server::Server::spawn(config).await.unwrap();
            let port = server.quic_addr().unwrap().port();
            let addr = SocketAddr::new(Self::loopback(ipv6), port);
            relays.push(RelayConfig::new(
                format!("https://{addr}").parse().unwrap(),
                Some(RelayQuicConfig::new(port)),
            ));
            servers.push(server);
        }

        let ep = noq::Endpoint::client((bind, 0).into()).unwrap();
        let tls = iroh_relay::tls::make_dangerous_client_config();
        let options = Options::new(tls.clone())
            .quic_config(Some(QuicConfig {
                ep: ep.clone(),
                client_config: tls,
                ipv4: !ipv6,
                ipv6,
            }))
            .net_report_config(NetReportConfig::minimal());
        let client = Client::new(
            DnsResolver::new(),
            RelayMap::from_iter(relays),
            options,
            Default::default(),
        );
        Some(Self {
            client,
            ep,
            servers,
            ipv6,
        })
    }

    fn loopback(ipv6: bool) -> IpAddr {
        if ipv6 {
            Ipv6Addr::LOCALHOST.into()
        } else {
            Ipv4Addr::LOCALHOST.into()
        }
    }

    fn address(&self) -> SocketAddr {
        SocketAddr::new(
            Self::loopback(self.ipv6),
            self.ep.local_addr().unwrap().port(),
        )
    }

    fn connection(&self) -> &QadConn {
        if self.ipv6 {
            self.client.qad_conns.v6.as_ref().unwrap()
        } else {
            self.client.qad_conns.v4.as_ref().unwrap()
        }
    }

    async fn report(&mut self, major: bool) -> Report {
        let cancel = CancellationToken::new();
        let report = time::timeout(
            Duration::from_secs(10),
            self.client.get_report(
                IfStateDetails {
                    have_v4: !self.ipv6,
                    have_v6: self.ipv6,
                },
                major,
                cancel.child_token(),
            ),
        )
        .await
        .expect("network report timed out");
        // A caller can end its report scope without ending retained observation.
        cancel.cancel();
        let observed = if self.ipv6 {
            report.global_v6.map(SocketAddr::V6)
        } else {
            report.global_v4.map(SocketAddr::V4)
        };
        assert_eq!(observed, Some(self.address()));
        report
    }

    async fn close(mut self) {
        self.client.qad_conns.clear();
        self.ep.close(0u32.into(), b"test complete");
        time::timeout(Duration::from_secs(10), async {
            self.ep.wait_idle().await;
            for server in self.servers {
                server.shutdown().await.unwrap();
            }
        })
        .await
        .expect("QAD cleanup timed out");
    }
}

#[tokio::test]
async fn reuses_observation_without_new_handshakes() {
    for ipv6 in [false, true] {
        // More than ENOUGH_ENDPOINTS exercises successful-batch cancellation.
        let Some(mut fixture) = Fixture::new(ipv6, ENOUGH_ENDPOINTS + 1).await else {
            continue;
        };
        let initial = fixture.report(false).await;
        assert_eq!(initial.relay_latency.iter().count(), ENOUGH_ENDPOINTS);
        let handshakes = fixture.ep.stats().outgoing_handshakes;
        assert!(handshakes >= ENOUGH_ENDPOINTS as u64);
        let connection = fixture.connection().conn.clone();
        for _ in 0..3 {
            fixture.report(false).await;
            assert_eq!(fixture.ep.stats().outgoing_handshakes, handshakes);
            assert_eq!(
                fixture.connection().conn.stable_id(),
                connection.stable_id()
            );
            assert!(connection.close_reason().is_none());
        }
        fixture.close().await;
    }
}

#[tokio::test]
async fn observes_rebind_after_probe_batch_cancellation() {
    for ipv6 in [false, true] {
        let Some(mut fixture) = Fixture::new(ipv6, ENOUGH_ENDPOINTS + 1).await else {
            continue;
        };
        let initial = fixture.report(false).await;
        assert_eq!(initial.relay_latency.iter().count(), ENOUGH_ENDPOINTS);
        let handshakes = fixture.ep.stats().outgoing_handshakes;
        let connection = fixture.connection().conn.clone();
        let mut observations = fixture.connection().watch();
        assert_eq!(observations.next().await.unwrap().addr, fixture.address());

        // Move the live connection onto another UDP port, not a mocked observer.
        let bind = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let socket = UdpSocket::bind((bind, 0)).unwrap();
        let new_addr =
            SocketAddr::new(Fixture::loopback(ipv6), socket.local_addr().unwrap().port());
        assert_ne!(new_addr, fixture.address());
        fixture.ep.rebind(socket).unwrap();
        time::timeout(Duration::from_secs(10), async {
            loop {
                let report = observations
                    .next()
                    .await
                    .expect("observation stream closed");
                if report.addr == new_addr {
                    break;
                }
            }
        })
        .await
        .expect("retained connection did not observe the changed address");
        assert_eq!(fixture.connection().current().unwrap().addr, new_addr);
        // A subscription created after the change must not discard its first value.
        assert_eq!(
            fixture.connection().watch().next().await.unwrap().addr,
            new_addr
        );
        fixture.report(false).await;
        assert_eq!(fixture.ep.stats().outgoing_handshakes, handshakes);
        assert_eq!(
            fixture.connection().conn.stable_id(),
            connection.stable_id()
        );
        drop(observations);
        fixture.close().await;
    }
}

#[tokio::test]
async fn single_relay_replay_preserves_mapping_evidence() {
    for ipv6 in [false, true] {
        let Some(mut fixture) = Fixture::new(ipv6, 1).await else {
            continue;
        };
        // A full report with one relay enters the stream-consumption loop.
        let initial = fixture.report(false).await;
        assert_eq!(initial.mapping_varies_by_dest(), None);

        // Previous evidence of destination-dependent mapping must survive a round
        // that only obtains one relay's observation, even when that stream replays.
        let previous = fixture.client.reports.last.as_mut().unwrap();
        if ipv6 {
            previous.mapping_varies_by_dest_ipv6 = Some(true);
        } else {
            previous.mapping_varies_by_dest_ipv4 = Some(true);
        }
        let report = time::timeout(
            Duration::from_secs(10),
            fixture
                .client
                .get_report(IfStateDetails::fake(), false, CancellationToken::new()),
        )
        .await
        .expect("mixed-family incremental report timed out");
        assert_eq!(report.mapping_varies_by_dest(), Some(true));
        fixture.close().await;
    }
}

#[tokio::test]
async fn replaces_closed_connections_and_full_reports() {
    for ipv6 in [false, true] {
        for major in [false, true] {
            let Some(mut fixture) = Fixture::new(ipv6, ENOUGH_ENDPOINTS + 1).await else {
                continue;
            };
            fixture.report(false).await;
            let handshakes = fixture.ep.stats().outgoing_handshakes;
            let connection = fixture.connection().conn.clone();
            if !major {
                connection.close(0u32.into(), b"exercise closed connection");
            }
            fixture.report(major).await;
            assert!(fixture.ep.stats().outgoing_handshakes > handshakes);
            assert_ne!(
                fixture.connection().conn.stable_id(),
                connection.stable_id()
            );
            assert!(connection.close_reason().is_some());
            fixture.close().await;
        }
    }
}
