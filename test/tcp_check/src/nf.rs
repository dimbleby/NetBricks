use e2d2::headers::*;
use e2d2::operators::*;
use e2d2::scheduler::*;

use std::fmt;
use std::mem;
use std::net::Ipv4Addr;

use futures::sync::mpsc;

#[derive(Debug, Default)]
#[repr(C, packed)]
struct ArpHeader {
    htype: u16,
    ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    oper: u16,
    sha: [u8; 6],
    spa: u32,
    tha: [u8; 6],
    tpa: u32,
}

impl fmt::Display for ArpHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Hardware addresses are very likely to be MAC addresses.
        let sha = if self.htype() == 0x0001 {
            format!("{}", MacAddress::new_from_slice(self.sha()))
        } else {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.sha[0], self.sha[1], self.sha[2],
                self.sha[3], self.sha[4], self.sha[5],
            )
        };
        let tha = if self.htype() == 0x0001 {
            format!("{}", MacAddress::new_from_slice(self.tha()))
        } else {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.tha[0], self.tha[1], self.tha[2],
                self.tha[3], self.tha[4], self.tha[5],
            )
        };

        // Protocol addresses are very likely to be IPv4.
        let spa = if self.ptype() == 0x0800 {
            format!("{}", Ipv4Addr::from(self.spa()))
        } else {
            format!("{}", self.spa())
        };
        let tpa = if self.ptype() == 0x0800 {
            format!("{}", Ipv4Addr::from(self.tpa()))
        } else {
            format!("{}", self.tpa())
        };

        write!(
            f,
            "{} > {} oper: {}, spa: {} tpa: {}",
            sha,
            tha,
            self.oper(),
            spa,
            tpa,
        )
    }
}

impl ArpHeader {
    #[inline]
    pub fn htype(&self) -> u16 {
        u16::from_be(self.htype)
    }

    #[inline]
    pub fn ptype(&self) -> u16 {
        u16::from_be(self.ptype)
    }

    #[inline]
    pub fn oper(&self) -> u16 {
        u16::from_be(self.oper)
    }

    #[inline]
    pub fn set_oper(&mut self, oper: u16) {
        self.oper = u16::to_be(oper)
    }

    #[inline]
    pub fn sha(&self) -> &[u8; 6] {
        &self.sha
    }

    #[inline]
    pub fn spa(&self) -> u32 {
        u32::from_be(self.spa)
    }

    #[inline]
    pub fn tha(&self) -> &[u8; 6] {
        &self.tha
    }

    #[inline]
    pub fn tpa(&self) -> u32 {
        u32::from_be(self.tpa)
    }
}

impl EndOffset for ArpHeader {
    type PreviousHeader = MacHeader;

    #[inline]
    fn offset(&self) -> usize { 28 }

    #[inline]
    fn size() -> usize { 28 }

    #[inline]
    fn payload_size(&self, hint: usize) -> usize { hint - 28 }

    #[inline]
    fn check_correct(&self, _: &Self::PreviousHeader) -> bool { true }
}

#[inline]
pub fn tcp_nf<T: 'static + Batch<Header = NullHeader>, S: Scheduler>(parent: T, sched: &mut S, mut stream: mpsc::Sender<Vec<u8>>) -> CompositionBatch {
    let mut groups = parent
        .parse::<MacHeader>()
        .map(box |pkt| {
            println!("MAC header: {} (len: {})", pkt.get_header(), pkt.get_payload().len());
        })
        .group_by(3, box |pkt| {
            match pkt.get_header().etype() {
                0x0800 => 0, // IPv4
                0x0806 => 1, // ARP
                _ => 2, // ???
            }
        }, sched);

    let udp = groups.get_group(0).unwrap()
        .parse::<IpHeader>()
        .map(box |pkt| {
            let hdr = pkt.get_header();
            println!("IP header: {}", hdr);
        })
        .filter(box |pkt| {
            pkt.get_header().protocol() == 17 // UDP
        })
        .parse::<UdpHeader>()
        .map(box move |pkt| {
            println!("UDP header: {}", pkt.get_header());
            stream.try_send(pkt.get_payload().to_vec()).unwrap_or_else(|e| println!("Failed to pass to userspace: {}", e));
        })
        .compose();

    let arp = groups.get_group(1).unwrap()
        .parse::<ArpHeader>()
        .map(box |pkt| {
            println!("ARP: {}", pkt.get_header());
        })
        .filter(box |pkt| {
            let hdr = pkt.get_header();
            hdr.oper() == 1 && hdr.tpa() == 0x0afe1803 // Request(1) && 10.254.24.3
        })
        .transform(box |pkt| {
            let hdr = pkt.get_mut_header();
            hdr.set_oper(2);
            mem::swap(&mut hdr.sha, &mut hdr.tha);
            mem::swap(&mut hdr.spa, &mut hdr.tpa);
            hdr.sha = [0xfa, 0x16, 0x3e, 0xfa, 0xc8, 0xfd];
            println!("ARP Response: {}", hdr);
        })
        .compose();

    merge(vec![udp, arp, groups.get_group(2).unwrap().compose()]).compose()
}
