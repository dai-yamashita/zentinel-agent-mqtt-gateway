//! MQTT packet parsing
//!
//! Wraps the mqttrs crate to provide a higher-level interface for parsing
//! MQTT packets from WebSocket binary frames.

use anyhow::{anyhow, bail, Context, Result};
use mqttrs::{decode_slice, Packet, Protocol, QoS};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Parsed MQTT packet with extracted fields for security checks
#[derive(Debug, Clone)]
pub enum MqttPacket {
    Connect(ParsedConnect),
    Publish(ParsedPublish),
    Subscribe(ParsedSubscribe),
    Unsubscribe(ParsedUnsubscribe),
    PingReq,
    PingResp,
    Disconnect,
    Other(MqttPacketType),
}

/// MQTT packet type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttPacketType {
    Connect,
    Connack,
    Publish,
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
    Auth, // MQTT 5.0
}

impl MqttPacketType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Connack => "CONNACK",
            Self::Publish => "PUBLISH",
            Self::Puback => "PUBACK",
            Self::Pubrec => "PUBREC",
            Self::Pubrel => "PUBREL",
            Self::Pubcomp => "PUBCOMP",
            Self::Subscribe => "SUBSCRIBE",
            Self::Suback => "SUBACK",
            Self::Unsubscribe => "UNSUBSCRIBE",
            Self::Unsuback => "UNSUBACK",
            Self::Pingreq => "PINGREQ",
            Self::Pingresp => "PINGRESP",
            Self::Disconnect => "DISCONNECT",
            Self::Auth => "AUTH",
        }
    }
}

/// Parsed CONNECT packet
#[derive(Debug, Clone)]
pub struct ParsedConnect {
    /// Protocol version (3 = 3.1, 4 = 3.1.1, 5 = 5.0)
    pub protocol_version: u8,
    /// Client identifier
    pub client_id: String,
    /// Clean session flag (v3.1.1) or clean start (v5.0)
    pub clean_session: bool,
    /// Keep alive interval in seconds
    pub keep_alive: u16,
    /// Username if provided
    pub username: Option<String>,
    /// Password if provided (stored as bytes for non-UTF8 passwords)
    pub password: Option<Vec<u8>>,
    /// Will topic if will message is set
    pub will_topic: Option<String>,
    /// Will message payload
    pub will_payload: Option<Vec<u8>>,
    /// Will QoS level
    pub will_qos: u8,
    /// Will retain flag
    pub will_retain: bool,
}

/// Parsed PUBLISH packet
#[derive(Debug, Clone)]
pub struct ParsedPublish {
    /// Topic name
    pub topic: String,
    /// Message payload
    pub payload: Vec<u8>,
    /// QoS level (0, 1, or 2)
    pub qos: u8,
    /// Retain flag
    pub retain: bool,
    /// Duplicate delivery flag
    pub dup: bool,
    /// Packet identifier (for QoS > 0)
    pub packet_id: Option<u16>,
}

/// Parsed SUBSCRIBE packet
#[derive(Debug, Clone)]
pub struct ParsedSubscribe {
    /// Packet identifier
    pub packet_id: u16,
    /// Topic filters with requested QoS
    pub subscriptions: Vec<Subscription>,
}

/// A single subscription in a SUBSCRIBE packet
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Topic filter (may contain + and # wildcards)
    pub topic_filter: String,
    /// Requested QoS level
    pub qos: u8,
}

/// Parsed UNSUBSCRIBE packet
#[derive(Debug, Clone)]
pub struct ParsedUnsubscribe {
    /// Packet identifier
    pub packet_id: u16,
    /// Topic filters to unsubscribe from
    pub topics: Vec<String>,
}

/// Decode the packet at the start of `data`. Bytes after it are ignored.
///
/// mqttrs 0.4.1 indexes past the end of a packet whose remaining length is
/// shorter than its fields, and panics. Such a packet is treated as one that
/// does not decode.
fn decode(data: &[u8]) -> Result<Packet<'_>> {
    catch_unwind(AssertUnwindSafe(|| decode_slice(data)))
        .map_err(|_| anyhow!("MQTT packet is shorter than its fields"))?
        .context("Failed to decode MQTT packet")?
        .context("Incomplete MQTT packet")
}

/// Length in bytes of the packet at the start of `data`: the fixed header
/// (type byte and 1 to 4 bytes of remaining length) plus the remaining length.
fn first_packet_len(data: &[u8]) -> Result<usize> {
    let mut remaining = 0usize;
    for i in 0..4 {
        let byte = *data.get(1 + i).context("Incomplete MQTT packet")?;
        remaining += usize::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            let len = 2 + i + remaining;
            if data.len() < len {
                bail!("Incomplete MQTT packet");
            }
            return Ok(len);
        }
    }
    bail!("Invalid MQTT remaining length")
}

/// Iterator over the packets in a buffer, as returned by [`split_packets`].
///
/// Yields each packet's bytes, header included. After the first error, which
/// is yielded in place of the packet that could not be delimited, it ends.
pub(crate) struct Packets<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Packets<'a> {
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match first_packet_len(self.rest) {
            Ok(len) => {
                let (packet, rest) = self.rest.split_at(len);
                self.rest = rest;
                Some(Ok(packet))
            }
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}

/// Split a buffer into the MQTT packets it holds, in order.
///
/// A WebSocket frame may carry several packets back to back (MQTT 3.1.1,
/// section 6). Packets are delimited by their remaining length alone; each
/// one still has to be decoded with [`parse_packet`].
pub(crate) fn split_packets(data: &[u8]) -> Packets<'_> {
    Packets { rest: data }
}

/// Check that a buffer holds whole, readable MQTT packets and nothing else.
/// Nothing is kept: the packets are decoded one at a time and dropped, so the
/// memory used does not grow with the number of packets.
///
/// # Errors
///
/// Returns an error if a packet is cut off at the end of the buffer, its
/// remaining length is malformed, or it cannot be decoded.
pub(crate) fn check_packets(data: &[u8]) -> Result<()> {
    for packet in split_packets(data) {
        decode(packet?)?;
    }
    Ok(())
}

/// Parse the MQTT packet at the start of a buffer. Bytes after it are
/// ignored, so a buffer that holds several packets has to be split first.
///
/// # Errors
///
/// Returns an error if the packet is incomplete or does not decode.
pub fn parse_packet(data: &[u8]) -> Result<MqttPacket> {
    let packet = decode(data)?;

    match packet {
        Packet::Connect(connect) => {
            let protocol_version = match connect.protocol {
                Protocol::MQTT311 => 4,
                Protocol::MQIsdp => 3,
            };

            Ok(MqttPacket::Connect(ParsedConnect {
                protocol_version,
                client_id: connect.client_id.to_string(),
                clean_session: connect.clean_session,
                keep_alive: connect.keep_alive,
                username: connect.username.map(|s| s.to_string()),
                password: connect.password.map(|p| p.to_vec()),
                will_topic: connect.last_will.as_ref().map(|w| w.topic.to_string()),
                will_payload: connect.last_will.as_ref().map(|w| w.message.to_vec()),
                will_qos: connect
                    .last_will
                    .as_ref()
                    .map(|w| qos_to_u8(w.qos))
                    .unwrap_or(0),
                will_retain: connect
                    .last_will
                    .as_ref()
                    .map(|w| w.retain)
                    .unwrap_or(false),
            }))
        }

        Packet::Publish(publish) => {
            // mqttrs uses QosPid enum to combine QoS and packet ID
            let (qos, packet_id) = match publish.qospid {
                mqttrs::QosPid::AtMostOnce => (0, None),
                mqttrs::QosPid::AtLeastOnce(pid) => (1, Some(pid.get())),
                mqttrs::QosPid::ExactlyOnce(pid) => (2, Some(pid.get())),
            };

            Ok(MqttPacket::Publish(ParsedPublish {
                topic: publish.topic_name.to_string(),
                payload: publish.payload.to_vec(),
                qos,
                retain: publish.retain,
                dup: publish.dup,
                packet_id,
            }))
        }

        Packet::Subscribe(subscribe) => {
            let subscriptions = subscribe
                .topics
                .iter()
                .map(|t| Subscription {
                    topic_filter: t.topic_path.to_string(),
                    qos: qos_to_u8(t.qos),
                })
                .collect();

            Ok(MqttPacket::Subscribe(ParsedSubscribe {
                packet_id: subscribe.pid.get(),
                subscriptions,
            }))
        }

        Packet::Unsubscribe(unsub) => Ok(MqttPacket::Unsubscribe(ParsedUnsubscribe {
            packet_id: unsub.pid.get(),
            topics: unsub.topics.iter().map(|t| t.to_string()).collect(),
        })),

        Packet::Pingreq => Ok(MqttPacket::PingReq),
        Packet::Pingresp => Ok(MqttPacket::PingResp),
        Packet::Disconnect => Ok(MqttPacket::Disconnect),

        Packet::Connack(_) => Ok(MqttPacket::Other(MqttPacketType::Connack)),
        Packet::Puback(_) => Ok(MqttPacket::Other(MqttPacketType::Puback)),
        Packet::Pubrec(_) => Ok(MqttPacket::Other(MqttPacketType::Pubrec)),
        Packet::Pubrel(_) => Ok(MqttPacket::Other(MqttPacketType::Pubrel)),
        Packet::Pubcomp(_) => Ok(MqttPacket::Other(MqttPacketType::Pubcomp)),
        Packet::Suback(_) => Ok(MqttPacket::Other(MqttPacketType::Suback)),
        Packet::Unsuback(_) => Ok(MqttPacket::Other(MqttPacketType::Unsuback)),
    }
}

fn qos_to_u8(qos: QoS) -> u8 {
    match qos {
        QoS::AtMostOnce => 0,
        QoS::AtLeastOnce => 1,
        QoS::ExactlyOnce => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_packet() {
        // MQTT CONNECT packet bytes (minimal)
        let connect_bytes = [
            0x10, 0x10, // Fixed header: CONNECT, remaining length 16
            0x00, 0x04, b'M', b'Q', b'T', b'T', // Protocol name "MQTT"
            0x04, // Protocol level (3.1.1)
            0x02, // Connect flags: clean session
            0x00, 0x3C, // Keep alive: 60 seconds
            0x00, 0x04, b't', b'e', b's', b't', // Client ID: "test"
        ];

        let packet = parse_packet(&connect_bytes).expect("Failed to parse CONNECT");
        match packet {
            MqttPacket::Connect(connect) => {
                assert_eq!(connect.client_id, "test");
                assert_eq!(connect.protocol_version, 4);
                assert!(connect.clean_session);
                assert_eq!(connect.keep_alive, 60);
            }
            _ => panic!("Expected CONNECT packet"),
        }
    }

    fn encoded(packet: Packet) -> Vec<u8> {
        let mut buf = vec![0u8; 32 * 1024];
        let len = mqttrs::encode_slice(&packet, &mut buf).unwrap();
        buf.truncate(len);
        buf
    }

    fn publish(topic: &str, payload: &[u8]) -> Vec<u8> {
        encoded(Packet::Publish(mqttrs::Publish {
            dup: false,
            qospid: mqttrs::QosPid::AtMostOnce,
            retain: false,
            topic_name: topic,
            payload,
        }))
    }

    fn split(data: &[u8]) -> Vec<Vec<u8>> {
        split_packets(data)
            .map(|packet| packet.unwrap().to_vec())
            .collect()
    }

    /// Split and parse a whole buffer, as the agent does with a frame.
    fn parse_all(data: &[u8]) -> Result<Vec<MqttPacket>> {
        split_packets(data)
            .map(|b| b.and_then(parse_packet))
            .collect()
    }

    #[test]
    fn split_packets_yields_nothing_for_an_empty_buffer() {
        assert_eq!(split_packets(&[]).count(), 0);
        assert!(parse_all(&[]).unwrap().is_empty());
        check_packets(&[]).unwrap();
    }

    #[test]
    fn split_packets_separates_packets_in_order() {
        let first = publish("a/b", b"one");
        let second = encoded(Packet::Pingreq);
        let third = encoded(Packet::Disconnect);
        let data = [first.clone(), second.clone(), third.clone()].concat();

        assert_eq!(split(&data), vec![first, second, third]);
        assert_eq!(parse_all(&data).unwrap().len(), 3);
        check_packets(&data).unwrap();
    }

    #[test]
    fn first_packet_len_matches_the_encoder_at_remaining_length_boundaries() {
        // A QoS 0 PUBLISH to "a/b" has a remaining length of 5 plus the
        // payload; the length takes one byte up to 127, two up to 16383 and
        // three beyond.
        for (remaining, length_bytes) in [(127, 1), (128, 2), (16_383, 2), (16_384, 3)] {
            let packet = publish("a/b", &vec![b'x'; remaining - 5]);
            assert_eq!(packet.len(), 1 + length_bytes + remaining);

            assert_eq!(first_packet_len(&packet).unwrap(), packet.len());
            let followed = [packet.clone(), vec![0xFF]].concat();
            assert_eq!(first_packet_len(&followed).unwrap(), packet.len());
            assert_eq!(split(&packet), vec![packet.clone()]);
        }
    }

    #[test]
    fn split_packets_agrees_with_the_decoder_on_where_a_packet_ends() {
        let packet = publish("a/b", b"one");
        let data = [packet.clone(), publish("c/d", b"two")].concat();

        let first = split_packets(&data).next().unwrap().unwrap();

        assert_eq!(first, packet.as_slice());
        match parse_packet(first).unwrap() {
            MqttPacket::Publish(publish) => assert_eq!(publish.payload, b"one"),
            _ => panic!("Expected PUBLISH packet"),
        }
    }

    #[test]
    fn split_packets_reports_a_packet_cut_off_at_the_end() {
        let whole = publish("a/b", b"one");
        let mut cut = publish("c/d", b"two");
        cut.pop();
        for tail in [cut, vec![0x30, 0x05, 0x00]] {
            let data = [whole.clone(), tail.clone()].concat();
            let mut packets = split_packets(&data);

            assert_eq!(packets.next().unwrap().unwrap(), whole.as_slice());
            assert!(packets.next().unwrap().is_err(), "tail {tail:?}");
            assert!(packets.next().is_none(), "ends after the error");
            assert!(parse_all(&data).is_err(), "tail {tail:?}");
            assert!(check_packets(&data).is_err(), "tail {tail:?}");
        }
    }

    #[test]
    fn split_packets_reports_a_remaining_length_cut_off() {
        for data in [
            vec![0x30],
            vec![0x30, 0x80],
            vec![0x30, 0xFF, 0xFF],
            vec![0x30, 0xFF, 0xFF, 0xFF],
        ] {
            assert!(first_packet_len(&data).is_err(), "bytes {data:?}");
            assert!(parse_all(&data).is_err(), "bytes {data:?}");
            assert!(check_packets(&data).is_err(), "bytes {data:?}");
        }
    }

    #[test]
    fn split_packets_rejects_a_remaining_length_of_more_than_four_bytes() {
        let data = [0x30, 0x80, 0x80, 0x80, 0x80, 0x01];

        assert!(split_packets(&data).next().unwrap().is_err());
        assert!(parse_all(&data).is_err());
        assert!(check_packets(&data).is_err());
    }

    #[test]
    fn parse_all_rejects_a_packet_that_does_not_decode() {
        // Type 0 and type 15 are not MQTT packets; a PUBREL needs flags 0b0010.
        // A remaining length of 0 spelled with two bytes is delimited, but it
        // holds no topic.
        for bad in [
            vec![0x00, 0x00],
            vec![0xF0, 0x00],
            vec![0x60, 0x00],
            vec![0x30, 0x80, 0x00],
        ] {
            let data = [publish("a/b", b"one"), bad.clone()].concat();

            assert!(parse_all(&data).is_err(), "bytes {bad:?}");
            assert!(check_packets(&data).is_err(), "bytes {bad:?}");
            assert!(split_packets(&data).all(|packet| packet.is_ok()));
        }
    }

    /// Packets that make mqttrs index past their end.
    fn packets_shorter_than_their_fields() -> Vec<Vec<u8>> {
        vec![
            vec![0x10, 0x06, 0x00, 0x04, b'M', b'Q', b'T', b'T'],
            vec![0x10, 0x07, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04],
            vec![0x10, 0x08, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02],
            vec![0x20, 0x00],
            vec![0x40, 0x00],
            vec![0x82, 0x00],
            vec![0xA2, 0x00],
        ]
    }

    #[test]
    fn packets_shorter_than_their_fields_do_not_decode() {
        for data in packets_shorter_than_their_fields() {
            assert!(parse_packet(&data).is_err(), "bytes {data:?}");
        }
    }

    #[test]
    fn packets_shorter_than_their_fields_do_not_decode_in_a_buffer() {
        for short in packets_shorter_than_their_fields() {
            let data = [publish("a/b", b"one"), short.clone()].concat();

            assert!(parse_all(&data).is_err(), "bytes {short:?}");
            assert!(check_packets(&data).is_err(), "bytes {short:?}");
        }
    }

    #[test]
    fn parse_packet_ignores_bytes_after_the_first_packet() {
        let data = [publish("a/b", b"one"), vec![0x00]].concat();

        assert!(matches!(parse_packet(&data), Ok(MqttPacket::Publish(_))));
    }

    #[test]
    fn test_parse_publish_packet() {
        // MQTT PUBLISH packet bytes (QoS 0)
        // Remaining length = 2 (topic len) + 5 (topic) + 5 (payload) = 12 = 0x0C
        let publish_bytes = [
            0x30, 0x0C, // Fixed header: PUBLISH QoS 0, remaining length 12
            0x00, 0x05, b't', b'e', b's', b't', b'/', // Topic length + "test/"
            b'h', b'e', b'l', b'l', b'o', // Payload: "hello"
        ];

        let packet = parse_packet(&publish_bytes).expect("Failed to parse PUBLISH");
        match packet {
            MqttPacket::Publish(publish) => {
                assert_eq!(publish.topic, "test/");
                assert_eq!(publish.payload, b"hello");
                assert_eq!(publish.qos, 0);
                assert!(!publish.retain);
            }
            _ => panic!("Expected PUBLISH packet"),
        }
    }
}
