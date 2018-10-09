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

use std::convert::*;

#[derive(Debug)]
pub enum CodecError {
    EncodingError,
    DecodingError,
}

pub struct Cursor {
    buffer: Vec<u8>,
    offset: usize,
}

impl<'a> Cursor {
    pub fn new(bytes: &[u8]) -> Cursor {
        Cursor {
            buffer: bytes.to_vec(),
            offset: 0,
        }
    }

    pub fn take(&mut self, length: usize) -> Result<&[u8], CodecError> {
        if self.unread_bytes() < length {
            return Err(CodecError::DecodingError);
        }

        let current = self.offset;
        self.offset += length;
        Ok(&self.buffer[current..current + length])
    }

    pub fn sub_cursor(&mut self, length: usize) -> Result<Cursor, CodecError> {
        self.take(length).and_then(|buffer| Ok(Cursor::new(buffer)))
    }

    pub fn unread_bytes(&self) -> usize {
        self.buffer.len() - self.offset
    }

    pub fn read_to_end(&mut self) -> &[u8] {
        let ret = &self.buffer[self.offset..];
        self.offset = self.buffer.len();
        ret
    }

    pub fn position(&self) -> usize {
        self.offset
    }

    pub fn is_empty(&self) -> bool {
        self.offset >= self.buffer.len()
    }

    pub fn has_more(&self) -> bool {
        !self.is_empty()
    }
}

pub trait Codec: Sized {
    fn encode(&self, buffer: &mut Vec<u8>);

    fn decode(&mut Cursor) -> Result<Self, CodecError>;

    fn encode_detached(&self) -> Vec<u8> {
        let mut buffer = vec![];
        self.encode(&mut buffer);
        buffer
    }

    fn decode_detached(buffer: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(buffer);
        Self::decode(&mut cursor)
    }
}

impl Codec for u8 {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self as u8);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let byte_option = cursor.take(1);
        match byte_option {
            Ok(bytes) => Ok(bytes[0]),
            Err(e) => Err(e),
        }
    }
}

impl Codec for u16 {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [0u8; 2];
        bytes[0] = (*self >> 8) as u8;
        bytes[1] = *self as u8;
        buffer.extend_from_slice(&bytes[..]);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes_option = cursor.take(2);
        match bytes_option {
            Ok(bytes) => Ok((u16::from(bytes[0]) << 8) | u16::from(bytes[1])),
            Err(e) => Err(e),
        }
    }
}

impl Codec for u32 {
    fn encode(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [0u8; 4];
        bytes[0] = (*self >> 24) as u8;
        bytes[1] = (*self >> 16) as u8;
        bytes[2] = (*self >> 8) as u8;
        bytes[3] = *self as u8;
        buffer.extend_from_slice(&bytes[..]);
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes_option = cursor.take(2);
        match bytes_option {
            Ok(bytes) => Ok((u32::from(bytes[0]) << 24)
                | (u32::from(bytes[1]) << 16)
                | (u32::from(bytes[2]) << 8)
                | u32::from(bytes[3])),
            Err(e) => Err(e),
        }
    }
}

pub fn encode_vec_u8<T: Codec>(bytes: &mut Vec<u8>, slice: &[T]) {
    let mut sub_cursor: Vec<u8> = Vec::new();
    slice.iter().for_each(|e| e.encode(&mut sub_cursor));

    assert!(sub_cursor.len() <= u8::max_value() as usize);
    (sub_cursor.len() as u8).encode(bytes);
    bytes.append(&mut sub_cursor);
}

pub fn encode_vec_u16<T: Codec>(bytes: &mut Vec<u8>, slice: &[T]) {
    let mut sub_cursor: Vec<u8> = Vec::new();
    slice.iter().for_each(|e| e.encode(&mut sub_cursor));

    assert!(sub_cursor.len() <= u16::max_value() as usize);
    (sub_cursor.len() as u16).encode(bytes);
    bytes.append(&mut sub_cursor);
}

pub fn encode_vec_u32<T: Codec>(bytes: &mut Vec<u8>, slice: &[T]) {
    let mut sub_cursor: Vec<u8> = Vec::new();
    slice.iter().for_each(|e| e.encode(&mut sub_cursor));

    assert!(sub_cursor.len() <= u32::max_value() as usize);
    (sub_cursor.len() as u32).encode(bytes);
    bytes.append(&mut sub_cursor);
}

pub fn decode_vec_u8<T: Codec>(r: &mut Cursor) -> Result<Vec<T>, CodecError> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u8::decode(r)?);
    let mut sub = r.sub_cursor(len)?;

    while sub.has_more() {
        ret.push(T::decode(&mut sub)?);
    }

    Ok(ret)
}

pub fn decode_vec_u16<T: Codec>(r: &mut Cursor) -> Result<Vec<T>, CodecError> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u16::decode(r)?);
    let mut sub = r.sub_cursor(len)?;

    while sub.has_more() {
        ret.push(T::decode(&mut sub)?);
    }

    Ok(ret)
}

pub fn decode_vec_u32<T: Codec>(r: &mut Cursor) -> Result<Vec<T>, CodecError> {
    let mut ret: Vec<T> = Vec::new();
    let len = u32::decode(r)? as usize;
    let mut sub = r.sub_cursor(len)?;

    while sub.has_more() {
        ret.push(T::decode(&mut sub)?);
    }

    Ok(ret)
}
