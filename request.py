from scapy.all import *

def main():
    ip = IP(src = '1.1.1.1', dst = '10.9.0.53')

    udp = UDP(sport = 12345, dport = 53, chksum = 0)
    
    Qdsec = DNSQR(qname='twysw.example.com')
    dns = DNS(id = 0xAAAA, qr = 0, qdcount = 1, qd = Qdsec)

    request = ip / udp / dns
   
    with open('request.bin', 'wb') as f:
        f.write(bytes(request))
    
if __name__ == "__main__":
    main()
