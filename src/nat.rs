//! The core of Network Address Translation (NAT) logic

use crate::hal::{HALResult, HAL};
use smoltcp::wire::*;

struct NAT<H: HAL> {
    hal: H,
    ifaces: [IFaceConfig; 4],
}

struct IFaceConfig {
    mac: EthernetAddress,
    ipv4: Ipv4Address,
    ipv6: Ipv6Address,
}

impl<H: HAL> NAT<H> {
    fn run(&mut self) -> HALResult<()> {
        loop {
            let mut recv_buf: [u8; 0x1000] =
                unsafe { core::mem::MaybeUninit::uninit().assume_init() };
            let metadata = self.hal.recv_packet(&mut recv_buf)?;
            let frame = EthernetFrame::new_unchecked(&recv_buf[..]);
            match frame.ethertype() {
                EthernetProtocol::Arp => {
                    self.process_arp(frame.payload());
                }
                EthernetProtocol::Ipv4 => {
                    self.process_ipv4(frame.payload());
                }
                EthernetProtocol::Ipv6 => {
                    self.process_ipv6(frame.payload());
                }
                EthernetProtocol::Unknown(type_) => {
                    warn!("unknown ethernet type: {}", type_);
                }
            }
        }
    }

    fn process_arp(&mut self, arp_buf: &[u8]) {
        let arp = ArpPacket::new_unchecked(arp_buf);
        match arp.operation() {
            ArpOperation::Request => {}
            ArpOperation::Reply => {}
            ArpOperation::Unknown(op) => {
                warn!("unknown ARP operation: {}", op);
            }
        }
    }
    fn process_ipv4(&mut self, ipv4_buf: &[u8]) {}
    fn process_ipv6(&mut self, ipv6_buf: &[u8]) {}
}
