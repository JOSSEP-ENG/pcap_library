#include <stdio.h>
#include <pcap.h>

typedef struct 
{
	unsigned char DesMac[6];
	unsigned char SrcMac[6];
	unsigned short type;
}EthernetH;

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char * packet) {
	
	printf("\nPacket captured Length: %d bytes\n", pkthdr->len);
	printf("\nTime: %ld seconds\n", pkthdr->ts.tv_sec);

	EthernetH *eh;
	eh=(EthernetH*)packet;
	printf("\n==========Ethernet Header==========\n");	
	printf("Dst Mac : ");
	for(int i=0; i<6; i++){
		printf("%02x",eh->DesMac[i]);
		if(i==6)	printf("\n");
		else printf(":");
	}
	printf("\nSrc Mac : ");
	for(int i=0; i<6; i++){
		printf("%02x",eh->SrcMac[i]);
		if(i==6)	printf("\n");
		else printf(":");
	}	
}

int main() {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	char *dev="enp0s3";

	handle=pcap_create(dev,errbuf);
	if(handle==NULL){
		printf("pcap_create() error : %s\n", errbuf);
		return 1;
	}

	if(pcap_activate(handle)!=0){
		printf("pcap_activate() error : %s\n", pcap_geterr(handle));
		return 1;
	}

	if(pcap_loop(handle, 100, packet_handler, NULL) < 0) {
		printf("pcap_loop() error : %s\n",pcap_geterr(handle));
	}

	pcap_close(handle);
	
	return 0;
}
