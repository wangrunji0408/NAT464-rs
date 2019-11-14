//! The core of Network Address Translation (NAT) logic

use crate::hal::{HALError, HAL};
use smoltcp::wire::*;
use smoltcp::Error as NetError;

/// Network Address Translation (NAT).
pub struct NAT<H: HAL> {
    pub hal: H,
    pub ifaces: [IFaceConfig; 4],
}

/// Configuration of a network interface.
pub struct IFaceConfig {
    pub mac: EthernetAddress,
    pub ipv4: Ipv4Address,
    pub ipv6: Ipv6Address,
}

impl<H: HAL> NAT<H> {
    /// Infinitely run until some error happened.
    pub fn run(&mut self) -> NATResult<()> {
        let mut recv_buf = [0u8; 0x1000];
        loop {
            let meta = self.hal.recv_packet(&mut recv_buf)?;
            let mut frame = EthernetFrame::new_unchecked(&mut recv_buf[..]);
            match frame.ethertype() {
                EthernetProtocol::Arp => {
                    self.process_arp(meta.iface_id, frame.into_inner())?;
                }
                EthernetProtocol::Ipv4 => {
                    self.process_ipv4(frame.payload_mut());
                }
                EthernetProtocol::Ipv6 => {
                    self.process_ipv6(frame.payload_mut());
                }
                EthernetProtocol::Unknown(type_) => {
                    warn!("unknown ethernet type: {}", type_);
                }
            }
        }
    }

    /// Process IPv4 ARP packet
    fn process_arp(&mut self, iface_id: usize, recv_buf: &mut [u8]) -> NATResult<()> {
        let mut frame = EthernetFrame::new_unchecked(recv_buf);
        let mut arp = ArpPacket::new_checked(frame.payload_mut())?;
        if let ArpRepr::EthernetIpv4 {
            operation,
            source_hardware_addr: src_mac,
            source_protocol_addr: src_ipv4,
            target_hardware_addr: dst_mac,
            target_protocol_addr: dst_ipv4,
        } = ArpRepr::parse(&arp)?
        {
            // update ARC for src
            self.hal.arc_add_mac(IpAddress::Ipv4(src_ipv4), src_mac)?;

            match operation {
                ArpOperation::Request => {
                    // reply (reuse input buffer)
                    let iface = &self.ifaces[iface_id];
                    arp.set_operation(ArpOperation::Reply);
                    arp.set_source_hardware_addr(iface.mac.as_bytes());
                    arp.set_source_protocol_addr(iface.ipv4.as_bytes());
                    arp.set_target_hardware_addr(src_mac.as_bytes());
                    arp.set_target_protocol_addr(src_ipv4.as_bytes());
                    frame.set_dst_addr(frame.src_addr());
                    frame.set_src_addr(iface.mac);
                    self.hal.send_packet(iface_id, &frame.into_inner()[..42])?;
                }
                ArpOperation::Reply => {
                    // update ARC for dst
                    self.hal.arc_add_mac(IpAddress::Ipv4(dst_ipv4), dst_mac)?;
                }
                ArpOperation::Unknown(op) => {
                    warn!("unknown ARP operation: {}", op);
                    return Err(NATError::Netstack(NetError::Unrecognized));
                }
            }
        } else {
            unreachable!()
        }
        Ok(())
    }
    /// Process IPv6 NDP packet
    fn process_ndp(&mut self, _ndp_buf: &[u8]) {}
    /// Process IPv4 packet
    fn process_ipv4(&mut self, _ipv4_buf: &[u8]) {}
    /// Process IPv6 packet
    fn process_ipv6(&mut self, _ipv6_buf: &[u8]) {}
}

/// A specialized Result type for [`NAT`](struct.NAT.html).
pub type NATResult<T> = Result<T, NATError>;

/// The error type for [`NAT`](struct.NAT.html) object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NATError {
    Netstack(NetError),
    Hal(HALError),
}

impl From<NetError> for NATError {
    fn from(e: NetError) -> Self {
        NATError::Netstack(e)
    }
}

impl From<HALError> for NATError {
    fn from(e: HALError) -> Self {
        NATError::Hal(e)
    }
}
