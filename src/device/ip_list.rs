extern crate cidr;

use cidr::{Cidr, Ipv4Cidr};
use std::cell::Cell;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::vec::Vec;

// IpList contains a list of IPs and allocation data
pub struct IpList {
    pub list: Vec<[u8; 5]>,
    pub allocated: HashMap<[u8; 5], bool>,
    pub peer_ips: HashMap<[u8; 32], [u8; 5]>,
    index: Cell<usize>,
}

impl IpList {
    pub fn new(cidr: [u8; 5]) -> Option<IpList> {
        let subnet: u8 = cidr[4];
        let index: usize = 0;
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
            allocated: HashMap::new(),
            peer_ips: HashMap::new(),
            index: Cell::new(index),
        });
    }

    // get_ip returns the first available IP to the caller, or None if the range is exhausted
    pub fn get_ip(&mut self) -> Option<[u8; 5]> {
        let mut current = self.index.get();
        let list = &self.list;
        let mut ip_avail = false;
        let allocated = &self.allocated;
        let mut counter: usize = 0;

        while !ip_avail {
            if current == list.len() {
                self.index.set(0);
            }
            current = self.index.get();
            if counter == list.len() {
                // If we've cycled through the list without finding a free IP, return one
                return None;
            }

            let ip = list[self.index.get()];
            ip_avail = !allocated.contains_key(&ip);
            counter += 1;
            self.index.set(current + 1);
        }

        return Some(list[self.index.get() - 1]);
    }

    // allocate allocates the IP for the peer and stores the mapping of pubkey -> IP in memory to avoid IP exhaustion
    pub fn allocate(&mut self, ip: [u8; 5], static_public: [u8; 32]) {
        let allocated = &mut self.allocated;
        let peer_ips = &mut self.peer_ips;

        // don't allocate this IP if we've already got one
        // there might be a better way of doing this, this was the least complex
        // to implement
        if !peer_ips.contains_key(&static_public) {
            peer_ips.insert(static_public, ip);
            allocated.insert(ip, true);
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
