use crate::types::PacketData;
use etherparse::{SlicedPacket, NetSlice, TransportSlice};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: u32,
    pub payload_peek: Vec<u8>,
    pub timestamp_sec: i64,
    pub timestamp_usec: i64,
}

pub fn parse_packet(data: PacketData) -> Option<ParsedPacket> {
    let sliced = SlicedPacket::from_ethernet(&data.payload).ok()?;

    let (src_ip, dst_ip, mut payload) = if let Some(net) = &sliced.net {
        match net {
            NetSlice::Ipv4(s) => (
                IpAddr::V4(s.header().source_addr()).to_string(),
                IpAddr::V4(s.header().destination_addr()).to_string(),
                s.payload().payload,
            ),
            NetSlice::Ipv6(s) => (
                IpAddr::V6(s.header().source_addr()).to_string(),
                IpAddr::V6(s.header().destination_addr()).to_string(),
                s.payload().payload,
            ),
        }
    } else {
        return None;
    };

    let mut protocol = String::from("UNKNOWN");
    let mut src_port = 0;
    let mut dst_port = 0;

    // Parse Transport layer
    if let Some(transport) = &sliced.transport {
        match transport {
            TransportSlice::Tcp(s) => {
                protocol = String::from("TCP");
                src_port = s.source_port();
                dst_port = s.destination_port();
                payload = s.payload();
            }
            TransportSlice::Udp(s) => {
                protocol = String::from("UDP");
                src_port = s.source_port();
                dst_port = s.destination_port();
                payload = s.payload();
            }
            TransportSlice::Icmpv4(s) => {
                protocol = String::from("ICMPv4");
                payload = s.payload();
            }
            TransportSlice::Icmpv6(s) => {
                protocol = String::from("ICMPv6");
                payload = s.payload();
            }
        }
    }

    // first 64 bytes of actual payload
    let payload_peek = payload.iter().take(64).cloned().collect();

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        length: data.length,
        payload_peek,
        timestamp_sec: data.timestamp_sec,
        timestamp_usec: data.timestamp_usec,
    })
}
