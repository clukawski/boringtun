extern crate cidr;

use crate::noise::errors::WireGuardError;
use cidr::{Cidr, Ipv4Cidr};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::vec::Vec;

// IpList contains a list of IPs and allocation data
pub struct IpList {
    pub list: Vec<[u8; 5]>,
    pub allocated: HashSet<[u8; 5]>,
    pub peer_ips: HashMap<[u8; 32], [u8; 5]>,
    index: Cell<usize>,
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

        if ip_list.is_empty() {
            return None;
        }

        Some(IpList {
            list: ip_list,
            allocated: HashSet::new(),
            peer_ips: HashMap::new(),
            index: Cell::new(0),
        })
    }

    // get_ip returns the first available IP to the caller, or None if the range is exhausted
    fn get_ip(&self) -> Option<[u8; 5]> {
        let mut current = self.index.get();
        let allocated = &self.allocated;

        loop {
            if current == self.list.len() {
                self.index.set(0);
            }
            current = self.index.get();
            if self.allocated.len() == self.list.len() {
                // If we've cycled through the list without finding a free IP, return None
                return None;
            }

            let ip = self.list[self.index.get()];
            if !&allocated.contains(&ip) {
                break;
            }
            self.index.set(current + 1);
            current = self.index.get();
        }

        Some(self.list[current - 1])
    }

    // allocate allocates the IP for the peer and stores the mapping of pubkey -> IP in memory to avoid IP exhaustion
    pub fn allocate(&mut self, static_public: [u8; 32]) -> Result<[u8; 5], WireGuardError> {
        if let Some(new_ip) = self.get_ip() {
            self.peer_ips.insert(static_public, new_ip);
            self.allocated.insert(new_ip);
            Ok(new_ip)
        } else {
            Err(WireGuardError::IPListExhausted)
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
