use codec::*;
use group::*;

pub struct HkdfLabel {
    length: usize,
    label: String,
    group_state: Vec<u8>,
}

impl HkdfLabel {
    pub fn new(group: &Group, label: &str) -> Self {
        let full_label = "mls10 ".to_owned() + label;
        let mut buffer = Vec::new();
        group.encode_group_state(&mut buffer);

        HkdfLabel {
            length: 32,
            label: full_label,
            group_state: buffer,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        (self.length as u32).encode(&mut buffer);
        encode_vec_u8(&mut buffer, self.label.as_bytes());
        encode_vec_u32(&mut buffer, &self.group_state);
        buffer
    }
}
