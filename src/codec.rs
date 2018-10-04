use std::convert::*;

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

    pub fn take(&mut self, length: usize) -> Option<&[u8]> {
        if self.unread_bytes() < length {
            return None;
        }

        let current = self.offset;
        self.offset += length;
        Some(&self.buffer[current..current + length])
    }

    pub fn sub_cursor(&mut self, length: usize) -> Option<Cursor> {
        self.take(length)
            .and_then(|buffer| Some(Cursor::new(buffer)))
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

    fn decode(&mut Cursor) -> Option<Self>;

    fn encode_detached(&self) -> Vec<u8> {
        let mut buffer = vec![];
        self.encode(&mut buffer);
        buffer
    }

    fn decode_detached(buffer: &[u8]) -> Option<Self> {
        let mut cursor = Cursor::new(buffer);
        Self::decode(&mut cursor)
    }
}

impl Codec for u8 {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self as u8);
    }

    fn decode(cursor: &mut Cursor) -> Option<Self> {
        let byte_option = cursor.take(1);
        match byte_option {
            Some(bytes) => Some(u8::from(bytes[0])),
            None => None,
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

    fn decode(cursor: &mut Cursor) -> Option<Self> {
        let bytes_option = cursor.take(2);
        match bytes_option {
            Some(bytes) => Some((u16::from(bytes[0]) << 8) | u16::from(bytes[1])),
            None => None,
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

pub fn decode_vec_u8<T: Codec>(r: &mut Cursor) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u8::decode(r)?);
    let mut sub = r.sub_cursor(len)?;

    while sub.has_more() {
        ret.push(T::decode(&mut sub)?);
    }

    Some(ret)
}

pub fn decode_vec_u16<T: Codec>(r: &mut Cursor) -> Option<Vec<T>> {
    let mut ret: Vec<T> = Vec::new();
    let len = usize::from(u16::decode(r)?);
    let mut sub = r.sub_cursor(len)?;

    while sub.has_more() {
        ret.push(T::decode(&mut sub)?);
    }

    Some(ret)
}
