mod arp;
mod interface;

use anyhow::Context as _;
use smoltcp::wire::{ArpOperation, ArpRepr};

#[derive(argh::FromArgs)]
/// Reply to ARP requests
struct Args {
    /// network interface name
    #[argh(option, short = 'i')]
    interface: String,

    /// path to the list of IP addresses
    #[argh(
        option,
        short = 'l',
        default = "std::path::PathBuf::from(\"/etc/arp-reply.yaml\")"
    )]
    list_file: std::path::PathBuf,
}

fn load_config<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Vec<std::net::Ipv4Addr>> {
    let file = std::fs::File::open(path).context("can't open IP list file")?;
    let reader = std::io::BufReader::new(file);
    serde_yaml::from_reader(reader).context("failed to parse IP list file")
}

fn main() -> anyhow::Result<()> {
    env_logger::builder().format_timestamp(None).init();

    let args: Args = argh::from_env();
    let our_ips = load_config(&args.list_file)?;

    let mut socket = arp::Socket::open()?;
    let our_ethernet_addr = socket.bind(&args.interface)?;

    loop {
        let (ethernet, arp) = socket.read()?;

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !ethernet.dst_addr.is_broadcast()
            && !ethernet.dst_addr.is_multicast()
            && ethernet.dst_addr != our_ethernet_addr
        {
            continue;
        }

        match arp {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } => {
                // we don't care about replies since we don't try to resolve anything
                if !matches!(operation, ArpOperation::Request) {
                    continue;
                }
                // Discard packets with non-unicast source addresses.
                if !source_protocol_addr.is_unicast() || !source_hardware_addr.is_unicast() {
                    log::debug!("arp: non-unicast source address");
                    continue;
                }
                if source_hardware_addr != ethernet.src_addr {
                    log::error!("arp: ethernet and arp have different source hardware addresses");
                    continue;
                }
                // Only process ARP packets for us.
                if !our_ips.contains(&std::net::Ipv4Addr::from(target_protocol_addr)) {
                    continue;
                }

                log::debug!("{}", arp);

                let reply = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Reply,
                    source_hardware_addr: our_ethernet_addr,
                    source_protocol_addr: target_protocol_addr,
                    target_hardware_addr: source_hardware_addr,
                    target_protocol_addr: source_protocol_addr,
                };
                socket.send(&reply)?;
                log::debug!("{}", reply);
            }
            other => {
                log::error!("unsupported arp variant: {:#?}", other);
                continue;
            }
        }
    }
}
