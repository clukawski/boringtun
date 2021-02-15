extern crate cidr;

use crate::noise::errors::WireGuardError;
use cidr::{Cidr, Ipv4Cidr};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::vec::Vec;

// IpList contains a list of IPs and allocation data
pub struct IpList {
    pub list: Vec<[u8; 5]>,
    pub allocated: HashSet<[u8; 5]>,
    pub peer_ips: HashMap<[u8; 32], [u8; 5]>,
    index: AtomicUsize,
}

impl IpList {
    pub fn new(cidr: [u8; 5]) -> Option<IpList> {
        let subnet: u8 = cidr[4];
        // It can also be created from string representations.
        let net = Ipv4Cidr::new(Ipv4Addr::new(cidr[0], cidr[1], cidr[2], cidr[3]), subnet)
            .expect("Expected valid ip range");

        let mut ip_list: Vec<[u8; 5]> = Vec::new();
        for ip in net.iter() {
            let octets = ip.octets();
            // Ensure only valid addresses are enumerated
            if octets[3] == 255 || octets[3] == 0 {
                continue;
            }
            let full_ip: [u8; 5] = [octets[0], octets[1], octets[2], octets[3], subnet];
            ip_list.push(full_ip);
        }

        if ip_list.len() == 0 {
            return None;
        }

        return Some(IpList {
            list: ip_list,
            allocated: HashSet::new(),
            peer_ips: HashMap::new(),
            index: AtomicUsize::new(0),
        });
    }

    // get_ip returns the first available IP to the caller, or None if the range is exhausted
    pub fn get_ip(&self) -> Option<[u8; 5]> {
        let mut current = self.index.load(Ordering::SeqCst);
        let mut ip_avail = false;
        let allocated = &self.allocated;

        while !ip_avail {
            if current == self.list.len() {
                self.index.store(0, Ordering::SeqCst);
            }
            current = self.index.load(Ordering::SeqCst);
            if self.allocated.len() == self.list.len() {
                // If we've cycled through the list without finding a free IP, return one
                return None;
            }

            let ip = self.list[self.index.load(Ordering::SeqCst)];
            ip_avail = !&allocated.contains(&ip);
            self.index.store(current + 1, Ordering::SeqCst);
        }

        current = self.index.load(Ordering::SeqCst);

        return Some(self.list[current - 1]);
    }

    // allocate allocates the IP for the peer and stores the mapping of pubkey -> IP in memory to avoid IP exhaustion
    pub fn allocate(
        &mut self,
        ip: [u8; 5],
        static_public: [u8; 32],
    ) -> Result<[u8; 5], WireGuardError> {
        // don't allocate this IP if we've already got one
        // there might be a better way of doing this, this was the least complex
        // to implement
        if !self.peer_ips.contains_key(&static_public) {
            self.peer_ips.insert(static_public, ip);
            &self.allocated.insert(ip);
            Ok(ip)
        } else {
            if self.allocated.contains(&ip) {
                if let Some(new_ip) = self.get_ip() {
                    self.peer_ips.insert(static_public, new_ip);
                    &self.allocated.insert(new_ip);
                    Ok(new_ip)
                } else {
                    Err(WireGuardError::IPListExhausted)
                }
            } else {
                Ok(ip)
            }
        }
    }

    // deallocate removes the IP allocation and pubkey -> IP mapping
    pub fn deallocate(&mut self, ip: [u8; 5], static_public: [u8; 32]) {
        let allocated = &mut self.allocated;
        let peer_ips = &mut self.peer_ips;

        allocated.remove(&ip);
        peer_ips.remove(&static_public);
    }
}
