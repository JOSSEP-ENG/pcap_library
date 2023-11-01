#include <stdio.h>
#include <pcap.h>

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
    EthernetH *eh;
    eh=(EthernetH*)packet;
    printf("\n========== Ethernet Header ==========\n");
    printf("Dst Mac : ");
    for(int i=0; i<6; i++) {
        printf("%02x",eh->DesMac[i]);
        if(i==5) printf("\n");
        else printf(":");
    }
    
    printf("Src Mac : ");
    for(int i=0; i<6; i++) {
        printf("%02x",eh->SrcMac[i]);
        if(i==5) printf("\n");
        else printf(":");
    }
}