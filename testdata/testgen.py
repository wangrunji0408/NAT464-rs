from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def gen_udp():
    ether = Ether(src='54:57:44:32:5f:30', dst='54:57:44:32:5f:31')
    udp = UDP(sport=3333, dport=4444) / b'1234'
    ins = [ether / IP(src='10.0.0.1', dst='10.0.0.2') / udp]
    outs = [ether / IPv6(src='2001:db8:1:4646::10.0.0.1', dst='2001:db8:2:4646::10.0.0.2') / udp]
    wrpcap("udp_v4.pcap", ins)
    wrpcap("udp_v6.pcap", outs)


def gen_tcp():
    ether = Ether(src='54:57:44:32:5f:30', dst='54:57:44:32:5f:31')
    tcp = TCP(sport=3333, dport=4444) / b'1234'
    ins = [ether / IP(src='10.0.0.1', dst='10.0.0.2') / tcp]
    outs = [ether / IPv6(src='2001:db8:1:4646::10.0.0.1', dst='2001:db8:2:4646::10.0.0.2') / tcp]
    wrpcap("tcp_v4.pcap", ins)
    wrpcap("tcp_v6.pcap", outs)


gen_udp()
gen_tcp()
