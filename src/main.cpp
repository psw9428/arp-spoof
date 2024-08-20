#include "../include/packet.h"
#include "../include/manager.h"
#include <cstdio>
#include <iostream>

using namespace std;

RootManager& rootManager = RootManager::getInstance();
ReceivedPacket& receivedPacket = ReceivedPacket::getInstance();

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.0.10 192.168.0.1 192.168.0.11 192.168.0.3\n");
}

int main(int argc, char* argv[]) {
	if (argc % 2 || argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	string input;

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	rootManager.init(argc, argv, handle);
	cout << "All Ready Now! Do you want to start? (y/n) ";
	cin >> input;
	if (input == "y") {
		rootManager.start_receive();
	}
	pcap_close(handle);
}
