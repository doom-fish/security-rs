use crate::error::{Result, SecurityError};

pub(crate) fn decode_base64(input: &[u8]) -> Result<Vec<u8>> {
    let invalid = || SecurityError::InvalidArgument("invalid base64 data".to_owned());
    if input.len() % 4 != 0 {
        return Err(invalid());
    }
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    for (index, chunk) in input.chunks_exact(4).enumerate() {
        let a = base64_digit(chunk[0]).ok_or_else(invalid)?;
        let b = base64_digit(chunk[1]).ok_or_else(invalid)?;
        let last = index == input.len() / 4 - 1;
        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || b & 0x0f != 0 {
                return Err(invalid());
            }
            output.push((a << 2) | (b >> 4));
        } else {
            let c = base64_digit(chunk[2]).ok_or_else(invalid)?;
            output.push((a << 2) | (b >> 4));
            output.push((b << 4) | (c >> 2));
            if chunk[3] == b'=' {
                if !last || c & 0x03 != 0 {
                    return Err(invalid());
                }
            } else {
                let d = base64_digit(chunk[3]).ok_or_else(invalid)?;
                output.push((c << 6) | d);
            }
        }
    }
    Ok(output)
}

fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
