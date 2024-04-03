#include <cstdio>
#include <pcap.h>
#include "attack.h"


void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	char my_mac[0x100];
	char my_ip[0x100];

	pcap_t* handle = pcap_open_live(dev, PCAP_ERRBUF_SIZE, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	if(get_my_mac(dev, my_mac, sizeof(my_mac)) != 0) {
		perror("get_my_mac_address");
		return -1;
	}


	if(get_my_ip(dev, my_ip, sizeof(my_ip)) != 0) {
		error("get_my_ip");
		return -1;
	}

	for(int i=2; i < argc; i+=2)
		proc_arp_attack(handle, my_mac, my_ip, argv[i], argv[i+1]);

	pcap_close(handle);
}
