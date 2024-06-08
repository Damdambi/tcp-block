#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
/*MAC address*/
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <malloc.h>

#define MAC_ALEN 6

void usage() {
	printf("syntax: tcp-block <interface> <pattern>\n");
	printf("sample: tcp-block wlan0 ""Host: test.gilgil.net""\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

uint8_t MyMac[6];

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

bool GetMyMac(char* device, uint8_t *mac_addr)
{
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return 1;
	}
	strncpy(ifr.ifr_name, device, IF_NAMESIZE);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCGIFHWADDR) failed - %m\n");
		close(sockfd);
		return 1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

	close(sockfd);
	return 0;
}

bool IsRequestHostName(const u_char* TcpData, int PacketLen, char* hostname){
	const char* Request = "GET";
	const char* Target = "Host: ";
	const char* Delimiter = "\r\n";
	int TargetLen = strlen(Target);
	int DelimiterLen = strlen(Delimiter);
	int Longer;
	bool flag = 0;
	if(strncmp(TcpData, Request, 3)!=0){
		return flag;
	}
	for(int i=0; i<PacketLen-TargetLen; i++){
		/*Find Target*/
		if(memcmp(TcpData + i, Target, TargetLen) == 0){
			/*Until move Delimiter*/
			for(int j=0; j<PacketLen - i - DelimiterLen; j++){
				if(memcmp(TcpData + i + j, Delimiter, DelimiterLen) == 0){
					/*Find longer word due to 3rd paramter in strncmp function*/
					Longer = strlen(hostname) > j ? strlen(hostname) : j;
					if(strncmp(hostname, TcpData+i, Longer)==0){
						flag = 1;
						break;
					}
					else break;
				}
			}
			break;
		}
	}
	return flag;
}

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t calculate_checksum(void *vdata, size_t length) {
    uint16_t *data = (uint16_t *)vdata;
    uint32_t acc = 0;
    // 2byte each other
    for (size_t i = 0; i < length / 2; i++) {
		acc += (data[i]);
        if (acc > 0xFFFF) {
            acc = (acc & 0xFFFF) + 1; // wrap around
        }
    }

    // odd
    if (length & 1) {
        uint16_t last_word = 0;
        memcpy(&last_word, (char *)data + length - 1, 1);
		acc += (last_word);
        // wrap around 처리
        if (acc > 0xFFFF) {
            acc = (acc & 0xFFFF) + 1; // wrap around
        }
    }
    return (~acc);
}

void SendForward(pcap_t* handle, struct pcap_pkthdr* header, uint8_t* MyMac, struct libnet_ethernet_hdr* EthHdr, struct libnet_ipv4_hdr* IpHdr, struct libnet_tcp_hdr* TcpHdr){
	/*Create New packet*/
	int NewPacketLen = LIBNET_ETH_H + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
	u_int8_t* NewPacket = (char*)malloc(NewPacketLen + 1);
	int OriTcpDataLen = IpHdr->ip_len - (IpHdr->ip_hl * 4) - (TcpHdr->th_off * 4);
	if(NewPacket == NULL){
		printf("malloc failed!!!\n");
		return;
	}
	memset(NewPacket, 0, NewPacketLen + 1);

	/*1. Fill ethernet header*/
	struct libnet_ethernet_hdr* NewEth = (struct libnet_ethernet_hdr*) NewPacket;
	
	memcpy(NewEth->ether_shost, MyMac, MAC_ALEN);
	memcpy(NewEth->ether_dhost, EthHdr->ether_dhost, MAC_ALEN);
	NewEth->ether_type = EthHdr->ether_type;

	/*2. Fill IP header*/
	struct libnet_ipv4_hdr* NewIp = (struct libnet_ipv4_hdr*)(NewPacket + LIBNET_ETH_H);
	NewIp->ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
	NewIp->ip_dst = IpHdr->ip_dst;
	NewIp->ip_src = IpHdr->ip_src;
	NewIp->ip_ttl = 128;
	NewIp->ip_p = IPPROTO_TCP;
	NewIp->ip_v = 4;
	NewIp->ip_hl = 5;

	/*3. Fill Tcp header*/
	struct libnet_tcp_hdr* NewTcp = (struct libnet_tcp_hdr*)(NewPacket + LIBNET_ETH_H + sizeof(struct libnet_ipv4_hdr));
	NewTcp->th_sport = TcpHdr->th_sport;
	NewTcp->th_dport = TcpHdr->th_dport;
	NewTcp->th_seq = htonl(ntohl(TcpHdr->th_seq) + OriTcpDataLen);
	NewTcp->th_ack = TcpHdr->th_ack;
	NewTcp->th_off = sizeof(struct libnet_tcp_hdr)/4;
    NewTcp->th_flags = TH_RST | TH_ACK;
	
	/*4.pseudo header initialize*/
	struct pseudo_header* PseudoHeader;
	PseudoHeader = (struct pseudo_header*)malloc(sizeof(struct pseudo_header));
	memset(PseudoHeader, 0, sizeof(struct pseudo_header));
	PseudoHeader->source_address = NewIp->ip_src.s_addr;
	PseudoHeader->dest_address = NewIp->ip_dst.s_addr;
	PseudoHeader->reserved = 0;
	PseudoHeader->protocol = NewIp->ip_p;
	PseudoHeader->tcp_length = htons(sizeof(struct libnet_tcp_hdr));
	/*5. Fill checksum*/
	NewIp->ip_sum = 0; 
	NewTcp->th_sum = 0;
	NewIp->ip_sum = calculate_checksum(NewIp, sizeof(struct libnet_ipv4_hdr));
	uint32_t tmp = calculate_checksum(NewTcp, sizeof(struct libnet_tcp_hdr)) + calculate_checksum(PseudoHeader, sizeof(struct pseudo_header));
	NewTcp->th_sum = tmp > 0xFFFF ? (tmp&0xFFFF)+1 : tmp; //wrap around
	for(int i=0; i<NewPacketLen; i++){
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", *(NewPacket+i));
	}
	printf("\n");
	/*Send packet*/
	if(pcap_sendpacket(handle, NewPacket, NewPacketLen) != 0){
		printf("Send error!!!\n");
		return;
	}
	free(PseudoHeader);
	free(NewPacket);
}

void SendBackward(uint8_t* MyMac, struct libnet_ethernet_hdr* EthHdr, struct libnet_ipv4_hdr* IpHdr, struct libnet_tcp_hdr* TcpHdr){
	int SockFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(SockFd<0){
		printf("Fail to create socket!!!\n");
		return;
	}
	int value = 1;
	const int* val = &value;
    if(setsockopt(SockFd, IPPROTO_IP, IP_HDRINCL, (char *)&val, sizeof(value))<0){
		printf("Fail to setsockpot\n");
		return;
	}

	struct sockaddr_in DstAddr;
	DstAddr.sin_family = AF_INET;
	DstAddr.sin_addr.s_addr = (IpHdr->ip_src.s_addr);
	DstAddr.sin_port = (TcpHdr->th_sport);
	char* Msg = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
	int PacketLen = sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + strlen(Msg);
	u_int8_t* Packet = (uint8_t*)malloc(PacketLen + 1);
	if(Packet == NULL){
		printf("malloc failed!!!\n");
		return;
	}
	memset(Packet, 0, PacketLen + 1);
	struct libnet_ipv4_hdr* NewIp = (struct libnet_ipv4_hdr*)(Packet);
	struct libnet_tcp_hdr* NewTcp = (struct libnet_tcp_hdr*)(Packet + sizeof(struct libnet_ipv4_hdr));
	char* payload = (char*)(Packet + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
	/*1. Fill Ip header*/
	NewIp->ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + strlen(Msg));
	NewIp->ip_ttl = 128;
	NewIp->ip_dst = IpHdr->ip_src;
	NewIp->ip_src = IpHdr->ip_dst;
	NewIp->ip_p = IPPROTO_TCP;
	NewIp->ip_v = 4;
	NewIp->ip_hl = sizeof(struct libnet_ipv4_hdr) / 4;

	/*3. Fill Tcp header*/
	NewTcp->th_sport = TcpHdr->th_dport;
	NewTcp->th_dport = TcpHdr->th_sport;
	NewTcp->th_seq = TcpHdr->th_ack;
	NewTcp->th_ack = htonl(ntohl(TcpHdr->th_seq) + strlen(Msg));
	NewTcp->th_off = sizeof(struct libnet_tcp_hdr)/4;
	NewTcp->th_flags = TH_FIN | TH_ACK;

	/*4. Fill Tcp data*/
	memcpy(payload, Msg, strlen(Msg));

	/*5.pseudo header initialize*/
	struct pseudo_header* PseudoHeader;
	PseudoHeader = (struct pseudo_header*)malloc(sizeof(struct pseudo_header));
	memset(PseudoHeader, 0, sizeof(struct pseudo_header));
	PseudoHeader->source_address = NewIp->ip_src.s_addr;
	PseudoHeader->dest_address = NewIp->ip_dst.s_addr;
	PseudoHeader->reserved = 0;
	PseudoHeader->protocol = NewIp->ip_p;
	PseudoHeader->tcp_length = htons(sizeof(struct libnet_tcp_hdr)+strlen(Msg));

	/*6. Checksum calculate*/
	NewIp->ip_sum = 0;
	NewTcp->th_sum = 0;

	NewIp->ip_sum = calculate_checksum(NewIp, sizeof(struct libnet_ipv4_hdr));
	uint32_t tmp = calculate_checksum(NewTcp, sizeof(struct libnet_tcp_hdr) + strlen(Msg)) + calculate_checksum(PseudoHeader, sizeof(struct pseudo_header));
	NewTcp->th_sum = tmp>0xFFFF ? (tmp&0xFFFF)+1 : tmp;
	for(int i=0; i<PacketLen; i++){
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", *(Packet+i));
	}
	printf("\n");
	printf("%ld\n", strlen(Msg));
	/*Send packet*/
	int ret = sendto(SockFd, Packet, PacketLen, 0, (struct sockaddr*)&DstAddr, (socklen_t)sizeof(DstAddr));

	if(ret<0){
		printf("Send fail!!!\n");
		free(Packet);
		return;
	}
	free(PseudoHeader);
	free(Packet);
}

void FinishPrint(int len){
	printf("%u bytes captured\n", len);
	printf("##################\n");
	printf("-------------------------------------------------------\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	char* Pattern = argv[2];
	GetMyMac(param.dev_, MyMac);

	/*Receive packet code*/
	struct libnet_ethernet_hdr* EthHdr = NULL;
	struct libnet_ipv4_hdr* IpHdr = NULL;
	struct libnet_tcp_hdr* TcpHdr = NULL;
	u_char* TcpData = NULL;
	int TcpDataLen;
	int count=0;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		EthHdr = (struct libnet_ethernet_hdr*)packet;

		IpHdr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
		count++;
		//printf("#%d###############\n",count);
		/*Check TCP packet*/
		if(IpHdr->ip_p != IPPROTO_TCP){
			// printf("Not TCP packet!!!\n");
			// FinishPrint(header->caplen);			
			continue;
		}

		TcpHdr = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + (IpHdr->ip_hl * 4)); //EX) ip_hl=5 -> 5*4 = 20byte
		TcpDataLen = header->caplen - LIBNET_ETH_H - (IpHdr->ip_hl * 4) - (TcpHdr->th_off * 4);
		if(TcpDataLen <= 0){
			// printf("No Tcp data Exist!!!\n");
			// FinishPrint(header->caplen);
			continue;
		}

		TcpData = (u_char*)(packet + LIBNET_ETH_H + (IpHdr->ip_hl * 4) + (TcpHdr->th_off * 4));

		if(IsRequestHostName(TcpData, header->caplen, Pattern)){ /*Detect pattern in Tcp data area.*/
			printf("Detect!\n");
			SendForward(pcap, header, MyMac, EthHdr, IpHdr, TcpHdr);
			SendBackward(MyMac, EthHdr, IpHdr, TcpHdr);
			FinishPrint(header->caplen);
		}
		// printf("Not detect!\n");
		// FinishPrint(header->caplen);
	}

	pcap_close(pcap);
}
