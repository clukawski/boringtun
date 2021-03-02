// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod crypto;

#[cfg(not(target_os = "windows"))]
pub mod device;

pub mod ffi;
pub mod noise;

use crate::device::drop_privileges::*;
use crate::device::ip_list::IpList;
use crate::device::*;
use clap::{value_t, App, Arg};
use crypto::x25519::X25519SecretKey;
use daemonize::Daemonize;
use parking_lot::Mutex;
use slog::{error, info, o, Drain, Logger};
use std::fs;
use std::fs::File;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use std::sync::Arc;

fn check_tun_name(_v: String) -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if device::tun::parse_utun_name(&_v).is_ok() {
            Ok(())
        } else {
            Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

fn main() {
    let matches = App::new("boringtun")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vlad Krasnov <vlad@cloudflare.com>")
        .args(&[
            Arg::with_name("INTERFACE_NAME")
                .required(true)
                .takes_value(true)
                .validator(check_tun_name)
                .help("The name of the created interface"),
            Arg::with_name("foreground")
                .long("foreground")
                .short("f")
                .help("Run and log in the foreground"),
            Arg::with_name("threads")
                .takes_value(true)
                .long("threads")
                .short("-t")
                .env("WG_THREADS")
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::with_name("private-key")
                .takes_value(true)
                .long("private-key")
                .short("-k")
                .env("WG_PRIVATE_KEY")
                .help("Path to the private key"),
            Arg::with_name("dynamic-address-allocation")
                .long("dynamic-address-allocation")
                .short("-d")
                .help("Use dynamic address allocation"),
            Arg::with_name("cidr")
                .takes_value(true)
                .long("cidr")
                .short("-c")
                .env("WG_PEER_CIDR")
                .help("Allocated CIDR"),
            Arg::with_name("listen-port")
                .takes_value(true)
                .long("listen-port")
                .short("-p")
                .env("WG_LISTEN_PORT")
                .help("The port to listen on at start"),
            Arg::with_name("verbosity")
                .takes_value(true)
                .long("verbosity")
                .short("-v")
                .env("WG_LOG_LEVEL")
                .possible_values(&["error", "info", "debug", "trace"])
                .help("Log verbosity")
                .default_value("error"),
            Arg::with_name("log")
                .takes_value(true)
                .long("log")
                .short("-l")
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/boringtun.out"),
            Arg::with_name("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .help("Do not drop sudo privileges"),
            Arg::with_name("disable-connected-udp")
                .long("disable-connected-udp")
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::with_name("disable-multi-queue")
                .long("disable-multi-queue")
                .help("Disable using multiple queues for the tunnel interface"),
        ])
        .get_matches();

    let background = !matches.is_present("foreground");
    let tun_name = matches.value_of("INTERFACE_NAME").unwrap();
    let n_threads = value_t!(matches.value_of("threads"), usize).unwrap_or_else(|e| e.exit());
    let log_level =
        value_t!(matches.value_of("verbosity"), slog::Level).unwrap_or_else(|e| e.exit());
    let listen_port: u16 = matches
        .value_of("listen-port")
        .unwrap_or_default()
        .parse()
        .unwrap_or_default();
    let init_pkey = matches.value_of("private-key").unwrap_or_default();
    let cidr = matches.value_of("cidr").unwrap_or_default();
    let is_dynamic = !matches.is_present("dynamic-address-allocation");

    let mut private_key = None;
    //if init_pkey is set, read it and parse it
    if init_pkey.len() > 0 {
        let contents = fs::read_to_string(init_pkey).expect("could not read private key file");
        private_key = match contents.trim().parse::<X25519SecretKey>() {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("Failed to parse private key: {:?}", e);
                exit(1);
            }
        };
    }

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let logger;

    if background {
        let log = matches.value_of("log").unwrap();

        let log_file =
            File::create(&log).unwrap_or_else(|_| panic!("Could not create log file {}", log));

        let plain = slog_term::PlainSyncDecorator::new(log_file);
        let drain = slog_term::CompactFormat::new(plain)
            .build()
            .filter_level(log_level);
        let drain = std::sync::Mutex::new(drain).fuse();
        logger = Logger::root(drain, o!());

        let daemonize = Daemonize::new()
            .working_directory("/tmp")
            .exit_action(move || {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    println!("BoringTun started successfully");
                } else {
                    eprintln!("BoringTun failed to start");
                    exit(1);
                };
            });

        match daemonize.start() {
            Ok(_) => info!(logger, "BoringTun started successfully"),
            Err(e) => {
                error!(logger, "Error, {}", e);
                exit(1);
            }
        }
    } else {
        let plain = slog_term::TermDecorator::new().stdout().build();
        let drain = slog_term::FullFormat::new(plain)
            .build()
            .filter_level(log_level);
        let drain = std::sync::Mutex::new(drain).fuse();
        logger = Logger::root(drain, o!());
    }

    // Ingest CIDR range if peer is allocating IPs
    let mut ip_list: Option<Arc<Mutex<IpList>>> = None;
    if cidr.len() > 0 {
        let cidr_str: Vec<&str> = cidr.split("/").collect();
        let cidr_subnet = cidr_str[1].parse::<u8>().unwrap();
        let cidr_addr: Ipv4Addr = cidr_str[0].parse().unwrap();
        let octets = cidr_addr.octets();
        let cidr_slice: [u8; 5] = [octets[0], octets[1], octets[2], octets[3], cidr_subnet];
        let list = IpList::new(cidr_slice).unwrap();
        ip_list = Some(Arc::new(Mutex::new(list)));
    }

    let config = DeviceConfig {
        n_threads,
        logger: logger.clone(),
        use_connected_socket: !matches.is_present("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.is_present("disable-multi-queue"),
        listen_port: listen_port,
        tun_name: Some(tun_name.to_string()),
        ip_list: ip_list.clone(),
        is_dynamic,
    };

    let mut device_handle: DeviceHandle = match DeviceHandle::new(&tun_name, config, private_key) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            error!(logger, "Failed to initialize tunnel: {:?}", e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if !matches.is_present("disable-drop-privileges") {
        if let Err(e) = drop_privileges() {
            error!(logger, "Failed to drop privileges: {:?}", e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);

    info!(logger, "BoringTun started successfully");

    device_handle.wait();
}
