use anyhow::Context as _;
use nix::sys::socket::{recvmsg, send, MsgFlags};
use smoltcp::wire::{ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol};

// libc stuff that [libc] doesn't provide
/// to all
const PACKET_BROADCAST: libc::c_int = 1;

/// [libc::ETH_P_ARP] in network [u16] byteorder
const ETH_P_ARP_NL: u16 = (libc::ETH_P_ARP as u16).to_be();

pub struct Socket {
    fd: libc::c_int,
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl Socket {
    pub fn open() -> anyhow::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ARP_NL.into()) };
        if fd < 0 {
            anyhow::bail!("can't create socket: {}", std::io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    pub fn bind(&mut self, interface_name: &str) -> anyhow::Result<smoltcp::wire::EthernetAddress> {
        let mut sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: ETH_P_ARP_NL,
            sll_ifindex: crate::interface::ifindex_for(self.fd, interface_name)?,
            sll_hatype: libc::ARPHRD_ETHER,
            sll_pkttype: PACKET_BROADCAST as u8,
            sll_halen: libc::ETH_ALEN as u8,
            sll_addr: [0; 8],
        };

        let ifhwaddr = crate::interface::ifhwaddr_for(self.fd, interface_name)?;
        for (dst, src) in sockaddr
            .sll_addr
            .iter_mut()
            .zip(ifhwaddr.sa_data[0..8].iter())
        {
            *dst = *src as u8;
        }

        let ethernet_addr = smoltcp::wire::EthernetAddress(
            sockaddr.sll_addr[..libc::ETH_ALEN as usize]
                .try_into()
                .context("ethernet address lengths don't match")?,
        );

        let res = unsafe {
            libc::bind(
                self.fd,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if res != 0 {
            anyhow::bail!("can't bind socket: {}", std::io::Error::last_os_error());
        }

        Ok(ethernet_addr)
    }

    pub fn read(
        &mut self,
    ) -> anyhow::Result<(smoltcp::wire::EthernetRepr, smoltcp::wire::ArpRepr)> {
        loop {
            let mut buf = [0; 100];
            let mut iov = [std::io::IoSliceMut::new(&mut buf[..])];
            let msg =
                recvmsg::<nix::sys::socket::SockaddrIn>(self.fd, &mut iov, None, MsgFlags::empty())
                    .context("failed to read arp packet")?;
            if msg.flags.contains(MsgFlags::MSG_TRUNC) {
                log::error!("truncated ARP message");
                continue;
            }

            let num = msg.bytes;
            let buf = &buf[..num];
            let ethernet_frame = smoltcp::wire::EthernetFrame::new_checked(buf)?;
            let ethernet_repr = smoltcp::wire::EthernetRepr::parse(&ethernet_frame)?;

            let arp_packet = smoltcp::wire::ArpPacket::new_checked(ethernet_frame.payload())?;
            let arp_repr = smoltcp::wire::ArpRepr::parse(&arp_packet)?;

            return Ok((ethernet_repr, arp_repr));
        }
    }

    pub fn send(&mut self, arp_repr: &ArpRepr) -> anyhow::Result<()> {
        let (target_hardware_addr, source_hardware_addr) = match arp_repr {
            ArpRepr::EthernetIpv4 {
                target_hardware_addr,
                source_hardware_addr,
                ..
            } => (target_hardware_addr, source_hardware_addr),
            other => anyhow::bail!("unsupported arp variant: {:#?}", other),
        };

        let tx_len = EthernetFrame::<&[u8]>::buffer_len(arp_repr.buffer_len());
        let mut buf = vec![0; tx_len];

        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_src_addr(*source_hardware_addr);
        frame.set_dst_addr(*target_hardware_addr);
        frame.set_ethertype(EthernetProtocol::Arp);

        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        arp_repr.emit(&mut packet);

        let num_written =
            send(self.fd, &buf, MsgFlags::empty()).context("failed to send ARP packet")?;
        if num_written != tx_len {
            anyhow::bail!("ARP packet was sent partially");
        }

        Ok(())
    }
}
