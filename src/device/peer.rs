// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::device::*;
use parking_lot::{Mutex, RwLock};
use rand::{thread_rng, Rng};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Default, Debug)]
pub struct Endpoint<S: Sock> {
    pub addr: Option<SocketAddr>,
    pub conn: Option<Arc<S>>,
}

pub struct Peer<S: Sock> {
    pub(crate) tunnel: Box<Tunn>, // The associated tunnel struct
    index: u32,                   // The index the tunnel uses
    endpoint: Arc<RwLock<Endpoint<S>>>,
    endpoints: Arc<RwLock<Vec<Arc<RwLock<Endpoint<S>>>>>>,
    allowed_ips: AllowedIps<()>,
    preshared_key: Option<[u8; 32]>,
    pub assigned_ip: Mutex<[u8; 5]>,
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
        allowed_ips: &[AllowedIP],
        preshared_key: Option<[u8; 32]>,
    ) -> Peer<S> {
        let endpoints_vec: Vec<Arc<RwLock<Endpoint<S>>>> = Vec::new();

        Peer {
            tunnel,
            index,
            endpoint: Arc::new(RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            })),
            endpoints: Arc::new(RwLock::new(endpoints_vec)),
            allowed_ips: allowed_ips.iter().collect(),
            preshared_key,
            assigned_ip: Mutex::new([0, 0, 0, 0, 0]),
        }
    }

    pub fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn get_assigned_ip(&self) -> Option<[u8; 5]> {
        *self.tunnel.assigned_ip.lock()
    }

    pub fn populate_endpoints(&self) {
        if self.tunnel.endpoints.is_none() {
            return;
        }

        let tunn_lock = self.tunnel.endpoints.as_ref().unwrap().lock();
        let tunn_endpoints = *tunn_lock;

        for endpoint in tunn_endpoints.iter() {
            let endpoints_clone = self.endpoints.clone();

            // TODO maybe put normal endpoint in here so we can simplify endpoint_rand()
            let mut endpoints_mut = endpoints_clone.write();
            (*endpoints_mut).push(Arc::new(RwLock::new(Endpoint {
                addr: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        endpoint[0],
                        endpoint[1],
                        endpoint[2],
                        endpoint[3],
                    )),
                    0,
                )),
                conn: None,
            })));
        }
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

    pub fn shutdown_endpoints(&self) {
        // Shutdown the initial endpoint
        if let Some(conn) = self.endpoint.write().conn.take() {
            info!(self.tunnel.logger, "Disconnecting from endpoint");
            conn.shutdown();
        }

        // Shutdown our list of additional endpoints, if any were passed in the handshake
        let endpoints = self.endpoints.write();
        for (i, endpoint) in endpoints.iter().enumerate() {
            if let Some(conn) = endpoint.write().conn.take() {
                info!(self.tunnel.logger, "Disconnecting from endpoint {}", i);
                conn.shutdown();
            }
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

    pub fn endpoint_rand(&self) -> Arc<RwLock<Endpoint<S>>> {
        let mut rng = thread_rng();

        let endpoints_clone = self.endpoints.clone();
        let endpoints_lock = endpoints_clone.read();
        let endpoints = endpoints_lock.deref().clone();
        let endpoints_len: usize = endpoints.len();
        let n: usize = rng.gen_range(0..endpoints_len + 1);
        if n == endpoints_len + 1 || endpoints_len == 0 {
            return Arc::clone(&self.endpoint);
        }

        let deref_rand = &endpoints[n];

        Arc::clone(&deref_rand)
    }

    pub fn connect_endpoints(
        &self,
        port: u16,
        fwmark: Option<u32>,
    ) -> Result<Vec<(IpAddr, Arc<S>)>, Error> {
        let mut endpoints_sockets: Vec<(IpAddr, Arc<S>)> = Vec::new();
        let endpoints = self.endpoints.write();
        for e in endpoints.iter() {
            let mut endpoint = e.write();
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

            endpoints_sockets.push((endpoint.addr.unwrap().ip(), udp_conn));
        }

        Ok(endpoints_sockets)
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
