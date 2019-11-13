extern crate std;

use crate::ip464::Translator;
use pcap_file::*;
use smoltcp::wire::*;
use std::convert::TryInto;
use std::format;
use std::fs::File;
use std::path::Path;

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
        assert_eq!(packet_ans.data.as_ref(), &ipv6_buf[..len]);
        pcap_out
            .write_packet(&Packet::new(i as u32, 0, len as u32, &ipv6_buf[..len]))
            .expect("failed to write pcap packet");
    }
}

#[test]
fn udp46() {
    test46("udp");
}

#[test]
fn tcp46() {
    test46("tcp");
}
