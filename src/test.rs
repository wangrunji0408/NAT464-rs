extern crate std;

use crate::hal::*;
use crate::ip464::Translator;
use crate::nat::{IFaceConfig, NATError, NAT};
use core::time::Duration;
use pcap_file::*;
use smoltcp::wire::*;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::format;
use std::fs::File;
use std::path::Path;
use std::vec::Vec;

fn open_pcap_in(name: &str) -> PcapReader<File> {
    let path = Path::new("testdata").join(name);
    let file = File::open(path).expect("failed to open file");
    PcapReader::new(file).expect("failed to open pcap")
}

fn create_pcap_out(name: &str) -> PcapWriter<File> {
    let path = Path::new("testdata").join(name);
    let file = File::create(path).expect("failed to create file");
    let header = PcapHeader::with_datalink(DataLink::ETHERNET);
    PcapWriter::with_header(header, file).expect("failed to create pcap writer")
}

fn test46(name: &str) {
    let pcap_in = open_pcap_in(&format!("{}_v4.pcap", name));
    let pcap_ans = open_pcap_in(&format!("{}_v6.pcap", name));
    let mut pcap_out = create_pcap_out(&format!("{}_v6.output.pcap", name));
    for (i, (packet_in, packet_ans)) in pcap_in.zip(pcap_ans).enumerate() {
        let packet_in = packet_in.unwrap();
        let packet_ans = packet_ans.unwrap();
        let frame = EthernetFrame::new_unchecked(&packet_in.data);
        assert_eq!(frame.ethertype(), EthernetProtocol::Ipv4);
        let ipv4_buf = frame.payload();
        let mut ipv6_buf = [0; 0x1000];
        let mut out_frame = EthernetFrame::new_unchecked(&mut ipv6_buf[..]);
        out_frame.set_src_addr(frame.src_addr());
        out_frame.set_dst_addr(frame.dst_addr());
        out_frame.set_ethertype(EthernetProtocol::Ipv6);

        let ts = Translator {
            local_prefix: Ipv6Address::new(0x2001, 0xdb8, 0x1, 0x4646, 0, 0, 0, 0),
            remote_prefix: Ipv6Address::new(0x2001, 0xdb8, 0x2, 0x4646, 0, 0, 0, 0),
        };
        let mut len = ts
            .ip_4to6(ipv4_buf, out_frame.payload_mut())
            .expect("failed to construct ipv6");
        len += 14; // ethernet frame header
        pcap_out
            .write_packet(&Packet::new(i as u32, 0, len as u32, &ipv6_buf[..len]))
            .expect("failed to write pcap packet");
        assert_eq!(packet_ans.data.as_ref(), &ipv6_buf[..len]);
    }
}

#[test]
fn nat_arp() {
    test_nat("arp");
}

#[test]
fn nat_ipv4() {
    test_nat("ipv4");
}

fn test_nat(name: &str) {
    let pcap_in = open_pcap_in(&format!("{}.pcap", name));
    let pcap_out = create_pcap_out(&format!("{}.output.pcap", name));
    let hal = TestHAL {
        pcap_in,
        pcap_out,
        arc: Default::default(),
    };
    let mut nat = NAT {
        hal,
        ifaces: [
            IFaceConfig {
                mac: EthernetAddress::from_bytes(b"TWD2_0"),
                ipv4: Ipv4Address::new(10, 0, 1, 1),
                ipv6: Default::default(),
            },
            IFaceConfig {
                mac: EthernetAddress::from_bytes(b"TWD2_1"),
                ipv4: Ipv4Address::new(10, 0, 2, 1),
                ipv6: Default::default(),
            },
            IFaceConfig {
                mac: EthernetAddress::from_bytes(b"TWD2_2"),
                ipv4: Ipv4Address::new(10, 0, 3, 1),
                ipv6: Default::default(),
            },
            IFaceConfig {
                mac: EthernetAddress::from_bytes(b"TWD2_3"),
                ipv4: Ipv4Address::new(10, 0, 4, 1),
                ipv6: Default::default(),
            },
        ],
    };
    assert_eq!(nat.run(), Err(NATError::Hal(HALError::EndOfFile)));
}

struct TestHAL {
    pcap_in: PcapReader<File>,
    pcap_out: PcapWriter<File>,
    arc: BTreeMap<IpAddress, EthernetAddress>,
}

impl HAL for TestHAL {
    fn recv_packet(&mut self, buf: &mut [u8]) -> HALResult<Metadata> {
        let packet = self.pcap_in.next().ok_or(HALError::EndOfFile)?.unwrap();
        assert_eq!(packet.data[14], 0, "packet is not input");
        // copy packet without VLAN tag
        let len = packet.data.len() - 4;
        buf[..12].copy_from_slice(&packet.data[..12]);
        buf[12..len].copy_from_slice(&packet.data[16..]);
        // echo
        self.pcap_out
            .write_packet(&packet)
            .expect("failed to write packet");
        // return metadata
        Ok(Metadata {
            iface_id: get_iface_id(&packet.data),
            len,
        })
    }

    fn send_packet(&mut self, iface_id: usize, buf: &[u8]) -> HALResult<()> {
        let packet = self.pcap_in.next().ok_or(HALError::EndOfFile)?.unwrap();
        let mut out_data = Vec::new();
        out_data.extend(&buf[..12]);
        out_data.extend(&[0x81, 0x00, 0x10, iface_id as u8]);
        out_data.extend(&buf[12..]);
        let out_packet = Packet {
            header: packet.header,
            data: out_data.into(),
        };
        self.pcap_out
            .write_packet(&out_packet)
            .expect("failed to write packet");
        assert_eq!(out_packet.data, packet.data);
        Ok(())
    }

    fn get_time(&self) -> HALResult<Duration> {
        unimplemented!()
    }

    fn get_iface_mac(&self, _iface_id: usize) -> HALResult<EthernetAddress> {
        unimplemented!()
    }

    fn amc_get(&self, _ip: IpAddress) -> HALResult<&IpAddress> {
        unimplemented!()
    }

    fn amc_add(&self, _ip: IpAddress, _new_ip: IpAddress) -> HALResult<()> {
        unimplemented!()
    }

    fn fib_get(&self, _ip: IpAddress) -> HALResult<&IpAddress> {
        unimplemented!()
    }

    fn fib_add(&mut self, _ip: IpAddress, _next_hop: IpAddress) -> HALResult<()> {
        unimplemented!()
    }

    fn arc_get_mac(&self, ip: &IpAddress) -> HALResult<&EthernetAddress> {
        let mac = self.arc.get(ip).ok_or(HALError::NotFound)?;
        Ok(mac)
    }

    fn arc_add_mac(&mut self, ip: IpAddress, mac: EthernetAddress) -> HALResult<()> {
        self.arc.insert(ip, mac);
        Ok(())
    }
}

fn get_iface_id(packet: &[u8]) -> usize {
    // we use VLAN tag to store iface id
    u16::from_be_bytes(packet[14..16].try_into().unwrap()) as usize
}

#[test]
fn udp46() {
    test46("udp");
}

#[test]
fn tcp46() {
    test46("tcp");
}

#[test]
fn icmp46() {
    test46("icmp");
}

#[test]
fn frag46() {
    test46("frag");
}
