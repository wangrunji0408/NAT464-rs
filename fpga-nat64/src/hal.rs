//! Hardware Abstract Layer implementation on FPGA-NAT64

use core::time::Duration;
use nat464::smoltcp::wire::*;
use nat464::{HALError, HALResult, Metadata, HAL};

pub struct FpgaHal {}

impl HAL for FpgaHal {
    fn recv_packet(&mut self, buf: &mut [u8]) -> HALResult<Metadata> {
        Ok(Metadata {
            iface_id: 0,
            len: 0,
        })
    }

    fn send_packet(&mut self, iface_id: usize, buf: &[u8]) -> HALResult<()> {
        Ok(())
    }

    fn get_time(&self) -> HALResult<Duration> {
        let ticks = unsafe { eth_get_clock() };
        let dur = Duration::from_micros(ticks * (1000000 / 16));
        Ok(dur)
    }

    fn get_iface_mac(&self, iface_id: usize) -> HALResult<EthernetAddress> {
        Ok(EthernetAddress::from_ffi(unsafe { eth_get_mac(iface_id) }))
    }

    fn amc_get(&self, ip: IpAddress) -> HALResult<IpAddress> {
        let mut naddr = [0u8; 16];
        let ret = unsafe { amc_query(ip.to_ffi(), &mut naddr) };
        if ret != 0 {
            return Err(HALError::Unknown);
        }
        Ok(IpAddress::from_ffi(naddr))
    }

    fn amc_add(&self, ip: IpAddress, new_ip: IpAddress) -> HALResult<()> {
        unsafe {
            amc_update(ip.to_ffi(), new_ip.to_ffi(), true);
        }
        Ok(())
    }

    fn fib_get(&self, ip: IpAddress) -> HALResult<IpAddress> {
        unimplemented!()
    }

    fn fib_add(&mut self, _ip: IpCidr, _next_hop: IpAddress) -> HALResult<()> {
        unimplemented!()
    }

    fn arc_get_mac(&self, ip: &IpAddress) -> HALResult<EthernetAddress> {
        let mut mac = 0u64;
        let ret = unsafe { arc_query(ip.to_ffi(), &mut mac) };
        if ret != 0 {
            return Err(HALError::Unknown);
        }
        Ok(EthernetAddress::from_ffi(mac))
    }

    fn arc_add_mac(&mut self, ip: IpAddress, mac: EthernetAddress) -> HALResult<()> {
        unsafe {
            arc_update(ip.to_ffi(), mac.to_ffi(), true);
        }
        Ok(())
    }
}

trait FFIConvert<T> {
    fn to_ffi(self) -> T;
    fn from_ffi(ffi: T) -> Self;
}

impl FFIConvert<ipv6_addr_t> for IpAddress {
    fn to_ffi(self) -> ipv6_addr_t {
        match self {
            IpAddress::Ipv6(ipv6) => ipv6.0,
            IpAddress::Ipv4(ipv4) => {
                let mut ipv6 = [0u8; 16];
                ipv6[12..].copy_from_slice(&ipv4.0);
                ipv6
            }
            _ => panic!("invalid IP type"),
        }
    }

    fn from_ffi(ip: ipv6_addr_t) -> Self {
        if &ip[..12] == &[0; 12] {
            IpAddress::Ipv4(Ipv4Address::from_bytes(&ip[12..]))
        } else {
            IpAddress::Ipv6(Ipv6Address(ip))
        }
    }
}

impl FFIConvert<u64> for EthernetAddress {
    fn to_ffi(self) -> u64 {
        ((self.0[0] as u64) << 0)
            | ((self.0[1] as u64) << 8)
            | ((self.0[2] as u64) << 16)
            | ((self.0[3] as u64) << 24)
            | ((self.0[4] as u64) << 32)
            | ((self.0[5] as u64) << 40)
    }

    fn from_ffi(ip: u64) -> Self {
        EthernetAddress::from_bytes(&ip.to_ne_bytes()[..6])
    }
}

extern "C" {
    fn arc_query(addr: ipv6_addr_t, mac: *mut u64) -> i32;
    fn arc_update(addr: ipv6_addr_t, mac: u64, upsert: bool);
    fn arc_remove(addr: ipv6_addr_t);

    fn amc_query(addr: ipv6_addr_t, naddr: *mut ipv6_addr_t) -> i32;
    fn amc_update(addr: ipv6_addr_t, naddr: ipv6_addr_t, upsert: bool);
    fn amc_remove(addr: ipv6_addr_t);

    fn fib_query(addr: ipv6_addr_t) -> i32;
    fn fib_update(prefix: ipv6_addr_t, prefixlen: u8, nexthop_id: u16, upsert: bool) -> i32;
    fn fib_remove(prefix: ipv6_addr_t, prefixlen: u8) -> i32;

    fn eth_get_mac(i: usize) -> u64;
    fn eth_get_clock() -> u64; // in 1/16s
}

#[allow(non_camel_case_types)]
type ipv6_addr_t = [u8; 16];
