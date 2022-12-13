# arp-reply

Make a linux machine reply to ARP-requests for addresses that are not assigned
to any of it's interface.

## Motivation
This effectively causes clients to send their traffic for those IPs to the host
that `arp-reply` is running on. Then you can create domains for those IPs in
your routers DNS-server (e.g. `nginx.home.arpa`) and setup DNAT on the
arpreply-host to forward traffic to that IP to an container. With that, you can
make the container look like a host on the physical network without giving that
container access to your whole network. Additionally, all your services can use
the same ports(like 443) so you don't have to use weird port numbers when
accessing these services.
