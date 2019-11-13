/// Calculate the checksum of `data`.
#[inline]
pub fn checksum(mut data: &[u8]) -> u32 {
    let mut s = 0u32;
    while data.len() >= 2 {
        s += ((data[0] as u32) << 8) | data[1] as u32;
        data = &data[2..];
    }
    if data.len() == 1 {
        s += (data[0] as u32) << 8;
    }
    s
}

/// Calculate final result for checksum field
#[inline]
pub fn checksum_final(mut s: u32) -> u16 {
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    !(s as u16)
}
