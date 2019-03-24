#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <arpa/inet.h>

using namespace std;

//void hexdump(const uint8_t *buf, const uint32_t len) {
//    const uint32_t size = 16;

//    for (uint32_t i = 0; i < len; i += size) {
//        printf("[0x%04x] ", i);
//        for (size_t j = i; j < i + size; ++j) {
//            if (j == i + size/2) putchar(' ');
//            if (j>=len)
//                printf("   ");
//            else
//                printf("%02x ", buf[j]);
//        }
//        putchar(' ');
//        for (uint32_t j = i; j < i + size && j < len; ++j) {
//            if (j == i + size / 2) putchar(' ');
//            if (buf[j] >= 0x20 && buf[j] < 0x80)
//                putchar(buf[j]);
//            else
//                putchar('.');
//        }
//        putchar('\n');
//    }
//    putchar('\n');
//}

struct ether_addr
{
    unsigned char ether_addr_octet[6];
};

struct ether_header
{
    struct  ether_addr ether_dhost;
    struct  ether_addr ether_shost;
    unsigned short ether_type;
};

struct ip_header
{
    unsigned char ip_protocol;
    struct in_addr ip_srcaddr;
    struct in_addr ip_destaddr;
};


struct tcp_header
{
    unsigned short source_port;
    unsigned short dest_port;
};


int print_ether_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
void print_tcp_header(const unsigned char *data);
void print_http_header(const unsigned char *data);

int main(int argc,char **argv){
    if (argc!=2) {
        printf("argc error");
        return -1;
    }

    char *dev = argv[1];
    char *errbuf;
    pcap_t *handle= pcap_open_live(dev,65535,1,1,errbuf);

    while(1){
        struct pcap_pkthdr *header;
        const u_char *data;

        int res = pcap_next_ex(handle,&header,&data);
        printf("%d",res);
        if(res == 0){
            continue;
        }
        if(res==-1 || res==-2){
            break;
        }
        //        hexdump(data,500);

        int eth_res = print_ether_header(data);
        printf("%d", eth_res);
        if (eth_res == 0){
            continue;
        }

        data = data + 22;

//        int pro_res = print_ip_header(data);
//        printf("%d", pro_res);
//        if (pro_res == 0){
//            continue;
//        }
        print_ip_header(data);
        data = data + 12;
        print_tcp_header(data);
        data= data + 20;
        print_http_header(data);
    }
}


int print_ether_header(const unsigned char *data)
{
    struct  ether_header *eh;
    unsigned short ether_type;
    eh = (struct ether_header *)data;
    ether_type=ntohs(eh->ether_type);

    if (ether_type!=0x0800)
    {
        printf("ether type wrong\n");
        return 0;
    }

    printf("\n============ETHERNET HEADER==========\n");
    printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
            eh->ether_dhost.ether_addr_octet[0],
            eh->ether_dhost.ether_addr_octet[1],
            eh->ether_dhost.ether_addr_octet[2],
            eh->ether_dhost.ether_addr_octet[3],
            eh->ether_dhost.ether_addr_octet[4],
            eh->ether_dhost.ether_addr_octet[5]);
    printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
            eh->ether_shost.ether_addr_octet[0],
            eh->ether_shost.ether_addr_octet[1],
            eh->ether_shost.ether_addr_octet[2],
            eh->ether_shost.ether_addr_octet[3],
            eh->ether_shost.ether_addr_octet[4],
            eh->ether_shost.ether_addr_octet[5]);
}

int print_ip_header(const unsigned char *data)
{
   // unsigned char ip_protocol;
    struct  ip_header *ih;
    ih = (struct ip_header *)data;
    printf("\n============IP HEADER============\n");
    printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr) );
    printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr) );

//    if (ip_protocol != 06){
//        printf("TCP is wrong!\n");
//        return 0;
//    }

}

void print_tcp_header(const unsigned char *data)
{
    struct  tcp_header *th;
    th = (struct tcp_header *)data;

    printf("\n============TCP HEADER============\n");
    printf("Src Port Num : %d\n", ntohs(th->source_port) );
    printf("Dest Port Num : %d\n", ntohs(th->dest_port) );

}

void print_http_header(const unsigned char *data)
{
    struct http_header *hh;
    printf("\n============HTTP DATA============\n");
    int i;
    for(i=0; i<=16; i++){
        printf("%c", data[i]);
    }
}


