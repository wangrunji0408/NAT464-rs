#![no_std]
#![feature(lang_items)]

use core::panic::PanicInfo;
use nat464::smoltcp::wire::*;
use nat464::{IFaceConfig, NAT};

mod hal;

#[no_mangle]
pub extern "C" fn eth_entry() {
    let hal = hal::FpgaHal {};
    let mut nat = NAT {
        hal,
        ifaces: [
            IFaceConfig {
                mac: EthernetAddress::from_bytes(b"TWD2_0"),
                ipv4: Ipv4Address::new(10, 0, 1, 1),
                ipv6: Ipv6Address::new(1, 0, 0, 0, 0, 0, 0, 0x10),
            },
            IFaceConfig {
                mac: EthernetAddress::from_bytes(b"TWD2_1"),
                ipv4: Ipv4Address::new(10, 0, 2, 1),
                ipv6: Ipv6Address::new(1, 0, 0, 0, 0, 0, 0, 0x20),
            },
            IFaceConfig {
                mac: EthernetAddress::from_bytes(b"TWD2_2"),
                ipv4: Ipv4Address::new(10, 0, 3, 1),
                ipv6: Ipv6Address::new(1, 0, 0, 0, 0, 0, 0, 0x30),
            },
            IFaceConfig {
                mac: EthernetAddress::from_bytes(b"TWD2_3"),
                ipv4: Ipv4Address::new(10, 0, 4, 1),
                ipv6: Ipv6Address::new(1, 0, 0, 0, 0, 0, 0, 0x40),
            },
        ],
    };
    nat.run();
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

#[lang = "eh_personality"]
fn eh_personality() {}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    panic!("abort");
}
