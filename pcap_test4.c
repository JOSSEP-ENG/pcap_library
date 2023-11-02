#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif // _DEFAULT_SOURCE

#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

typedef struct {
    unsigned char DesMac[6];
    unsigned char SrcMac[6];
    unsigned short Type;
}EthernetH;

void packet_handler(const u_char *packet);

int main(int argc, char* argv[]){

    if(argc!=2){
        printf("Input Interface Name\n");
        printf("ex) ./pcap_test2 enp0s3 \n");
        return 1;
    }

    char *dev=argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle=pcap_open_live(dev,1024,1,1000,errbuf);
    struct pcap_pkthdr* header;
    const u_char* packet;

    if(handle==NULL){
        printf("%s : %s\n",dev,errbuf);
        return 1;
    }

    while(1) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res==0) continue;
        if (res==-1 || res ==-2) return 1;
        packet_handler(packet);
    }

    pcap_close(handle);
    return 0;
}

void packet_handler(const u_char *packet){
        
    struct ether_header *ether_h = (struct ether_header*)packet;
    struct ip *ip_header = (struct ip*)(packet+ETHER_HDR_LEN);
    struct tcphdr *tcp_header = (struct tcphdr*)(packet+ETHER_HDR_LEN+(ip_header->ip_hl<<2));

    if(ip_header->ip_p==6) {
        printf("==============================================================\n");
        printf("Ethernet Header >>> \n");
        printf("\tsrc Mac Address : %s\n", ether_ntoa((struct ether_addr*)&ether_h->ether_shost));
        printf("\tdst Mac Address : %s\n", ether_ntoa((struct ether_addr*)&ether_h->ether_shost));
        printf("\ttype : 0x%04x\n\n",ntohs(ether_h->ether_type));

        printf("IP Header >>> \n");
        printf("\tsrc IP : %s\n",inet_ntoa(ip_header->ip_src));
        printf("\tdst IP : %s\n",inet_ntoa(ip_header->ip_dst));
        printf("\tIP version : %d\n", ip_header->ip_v);
        printf("\tHeader Length : %d bytes \n", ip_header->ip_hl * 4);
        printf("\tTotal Length : %d bytes \n", ntohs(ip_header->ip_len));
        printf("\tProtocol : %d \n", ip_header->ip_p);

        //unsigned int iphdr_len = ip_header->ip_hl * 4;        
        printf("TCP Header >>> \n");
        printf("\tsrc PORT : %d\n", ntohs(tcp_header->th_sport));
        printf("\tdst PORT : %d\n",ntohs(tcp_header->th_dport));
        printf("\tSeq Num : %u\n",ntohl(tcp_header->th_seq));
        printf("\tAck Num : %u\n",ntohl(tcp_header->th_ack));
        printf("\tHeader length : %d bytes\n",(tcp_header->th_off)<<2);
        printf("\tFlags : 0x%02x\n",tcp_header->th_flags);

        printf("PAYLOAD >>> \n");
        printf("test...");
    }   
}