
# DNSMUS - a multi upstream DNS server

## How does it work

Dnsmus listens on the UDP port given in command line parameter for DNS
queries, takes the nameservers listed in `/etc/resolv.conf.dnsmus`
(resolv.conf format) and echos the query to all of the upstream
nameservers. Then itself responses with the first "good" upstream
response to the client. What is considered "good" is currently defined
as having NOERROR rcode and at least 1 record in the answer section. So
it is not really suitable for recursive nameserver clients (but intended
to use with upstream recursive nameservers and downstream stub resolvers).

## Useful for

It's useful when your network environment has multiple resolvers but not
all of them resolves any domain name, and some of them responses
NXDOMAIN, NODATA, or SERVFAIL on queries which are perfectly resolved by
yet another ones. And the who-resolves-what conundrum is not based on
name suffixes. I use it in VMs in corporate environment with multiple
independent VPNs connected simultaneously, each exclusively wanting to
manage DNS resolution.

If you have nameservers for well defined zones, known suffixes, use
[libnss-resolver](http://git.uucp.hu/sysop/libnss-resolver.git) instead
(not to confure with `libresolv` without "er" at the end). It sends
queries only to the nameservers of the asked domain as it is configured.

## How to run

`perl dnsmus <PORT>` where `PORT` is the udp port it listens on. TCP is
not supproted now. The timeouts are hardcoded now, change if you need
to. Then point your system resolver to the host it is running on port
53. AFAIK libresolv does not support custom port numbers, so if you want
to run it not on localhost (probably you want) besides an other dns
server (supposedly listening on 53 too), then either **(A)** make the
other server not listen on 0.0.0.0 anycast and erect a virtual network
interface (with IP eg. 127.0.0.123) for dnsmus to listen on it on udp/53
(may need to change the listen address in the script) and point
`resolv.conf` to it, or **(B)** point `resolv.conf` to dnsmasq and set
dnsmasq to upstream to dnsmus (`server=127.0.0.1#5553` where dnsmus
listens on udp/5553).

## Why this instead of already existing tools?

Linux standard libresolv can fire queries to multiple nameservers but
not in parallel, AFAIK, and happily returns with any
NODATA/NXDOMAIN/SERVFAIL response, which is totally sane considering
that the DNS database was meant to be globally agreed upon. But in same
"clever" places you have to work around the provided nameservers to get
correct DNS answers.

I have not found other simple tool doing all of this.

## Appendix

### License

AGPLv3.
