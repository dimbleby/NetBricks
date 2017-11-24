use e2d2::headers::*;
use e2d2::operators::*;
use e2d2::scheduler::*;

use std::mem;

use futures::sync::mpsc;

#[derive(Debug, Default)]
#[repr(C, packed)]
struct ArpHeader {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: u16,
    pub smac: MacAddress,
    pub saddr: u32,
    pub tmac: MacAddress,
    pub taddr: u32,
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
            println!("ARP: {:#?}", pkt.get_header());
        })
        .filter(box |pkt| {
            let hdr = pkt.get_header();
            hdr.oper == 256 && hdr.taddr == 16843018 // Request(1) && 10.1.1.1
        })
        .transform(box |pkt| {
            let hdr = pkt.get_mut_header();
            hdr.oper = 512;
            mem::swap(&mut hdr.smac, &mut hdr.tmac);
            mem::swap(&mut hdr.saddr, &mut hdr.taddr);
            hdr.smac = MacAddress::new_from_slice(&[1,2,3,4,5,6,7,8]);
            println!("ARP Response: {:#?}", hdr);
        })
        .compose();

    merge(vec![udp, arp, groups.get_group(2).unwrap().compose()]).compose()
}
