// Wire
// Copyright (C) 2018 Wire Swiss GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use sodiumoxide::utils::memzero;

pub fn erase(ptr: &mut [u8]) {
    memzero(ptr);
}

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
