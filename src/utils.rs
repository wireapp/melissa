pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for b in bytes {
        hex += &format!("{:02X}", *b);
    }
    hex
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        bytes.push(b);
    }
    bytes
}
