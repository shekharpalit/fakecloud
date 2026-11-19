//! `application/vnd.amazon.eventstream` frames for `InvokeCodeInterpreter`'s
//! `stream`: prelude, string headers, JSON payload and CRC32s, big-endian.

const HEADER_TYPE_STRING: u8 = 7;

fn encode_frame(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut header_bytes = Vec::new();
    for (name, value) in headers {
        header_bytes.push(name.len() as u8);
        header_bytes.extend_from_slice(name.as_bytes());
        header_bytes.push(HEADER_TYPE_STRING);
        header_bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        header_bytes.extend_from_slice(value.as_bytes());
    }
    let total = 12 + header_bytes.len() + payload.len() + 4;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    let prelude_crc = crc32fast::hash(&out[..8]);
    out.extend_from_slice(&prelude_crc.to_be_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(payload);
    let message_crc = crc32fast::hash(&out);
    out.extend_from_slice(&message_crc.to_be_bytes());
    out
}

/// One `result` event of a `CodeInterpreterStreamOutput`.
pub(crate) fn result_frame(payload: &[u8]) -> Vec<u8> {
    encode_frame(
        &[
            (":event-type", "result"),
            (":content-type", "application/json"),
            (":message-type", "event"),
        ],
        payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_result_frame_carries_its_length_and_both_checksums() {
        let frame = result_frame(br#"{"isError":false}"#);
        let total = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        let end = frame.len();
        assert_eq!(
            (
                total,
                u32::from_be_bytes(frame[8..12].try_into().unwrap()),
                u32::from_be_bytes(frame[end - 4..].try_into().unwrap())
            ),
            (
                end,
                crc32fast::hash(&frame[..8]),
                crc32fast::hash(&frame[..end - 4])
            )
        );
    }
}
