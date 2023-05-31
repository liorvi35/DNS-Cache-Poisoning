"""
this file contains the build of DNS request packet

:authors: Lior Vinman & Yoad Tamar

:since: 31/05/2023
"""

import scapy.all as scapy


def generate_request() -> bytes:
    Qdsec = scapy.DNSQR(qname="twysw.example.com")
    dns = scapy.DNS(id=0xAAAA, qr=0, qdcount=1, qd=Qdsec)

    ip = scapy.IP(src="1.2.3.4", dst="10.9.0.53")
    udp = scapy.UDP(sport=62621, dport=53, chksum=0)
    packet = ip / udp / dns

    return bytes(packet)


def main():
    pkt = generate_request()

    with open("dns_req.bin", "wb") as file:
        file.write(pkt)


if __name__ == "__main__":
    main()
