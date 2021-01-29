// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::device::*;
use parking_lot::{Mutex, RwLock};
use std::cell::Cell;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Default, Debug)]
pub struct Endpoint<S: Sock> {
    pub addr: Option<SocketAddr>,
    pub conn: Option<Arc<S>>,
}

pub struct Peer<S: Sock> {
    pub(crate) tunnel: Box<Tunn>, // The associated tunnel struct
    index: u32,                   // The index the tunnel uses
    endpoint: RwLock<Endpoint<S>>,
    endpoints: Vec<RwLock<Endpoint<S>>>,
    allowed_ips: AllowedIps<()>,
    preshared_key: Option<[u8; 32]>,
    pub assigned_ip: Mutex<Cell<[u8; 5]>>,
}

#[derive(Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl<S: Sock> Peer<S> {
    pub fn new(
        tunnel: Box<Tunn>,
        index: u32,
        endpoint: Option<SocketAddr>,
        endpoints: Option<Vec<SocketAddr>>,
        allowed_ips: &[AllowedIP],
        preshared_key: Option<[u8; 32]>,
    ) -> Peer<S> {
        let mut endpoints_vec = Vec::new();
        if let Some(e) = endpoints {
            for endpoint in e {
                endpoints_vec.push(RwLock::new(Endpoint {
                    addr: Some(endpoint),
                    conn: None,
                }));
            }
        }

        Peer {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            endpoints: endpoints_vec,
            allowed_ips: allowed_ips.iter().collect(),
            preshared_key,
            assigned_ip: Mutex::new(Cell::new([0, 0, 0, 0, 0])),
        }
    }

    pub fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn get_assigned_ip(&self) -> [u8; 5] {
        let assigned_ip = self.tunnel.assigned_ip.lock().get();
        return assigned_ip;
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint<S>> {
        self.endpoint.read()
    }

    pub fn shutdown_endpoint(&self) {
        if let Some(conn) = self.endpoint.write().conn.take() {
            info!(self.tunnel.logger, "Disconnecting from endpoint");
            conn.shutdown();
        }
    }

    pub fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            // We only need to update the endpoint if it differs from the current one
            if let Some(conn) = endpoint.conn.take() {
                conn.shutdown();
            }

            *endpoint = Endpoint {
                addr: Some(addr),
                conn: None,
            }
        };
    }

    pub fn connect_endpoint(&self, port: u16, fwmark: Option<u32>) -> Result<Arc<S>, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let udp_conn = Arc::new(match endpoint.addr {
            Some(addr @ SocketAddr::V4(_)) => S::new()?
                .set_non_blocking()?
                .set_reuse()?
                .bind(port)?
                .connect(&addr)?,
            Some(addr @ SocketAddr::V6(_)) => S::new6()?
                .set_non_blocking()?
                .set_reuse()?
                .bind(port)?
                .connect(&addr)?,
            None => panic!("Attempt to connect to undefined endpoint"),
        });

        if let Some(fwmark) = fwmark {
            udp_conn.set_fwmark(fwmark)?;
        }

        info!(
            self.tunnel.logger,
            "Connected endpoint :{}->{}",
            port,
            endpoint.addr.unwrap()
        );

        endpoint.conn = Some(Arc::clone(&udp_conn));

        Ok(udp_conn)
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
    }

    pub fn allowed_ips(&self) -> Iter<()> {
        self.allowed_ips.iter()
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}
