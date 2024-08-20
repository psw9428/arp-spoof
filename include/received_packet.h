#pragma once

#include "packet.h"
#include "observer.h"
#include <pcap.h>
#include <mutex>
#include <vector>
#include <queue>
#include <any>
#include <cstdio>
#include <functional>

using namespace std;

class ReceivedPacket {
private :
    vector<shared_ptr<Observer>> observers;
    static mutex mtx;

    queue<vector<u_char>> relayPacketQueue;
    mutex relayPacketQueueMtx;
    queue<EthArpPacket> arpPacketQueue;
    mutex arpPacketQueueMtx;

    ReceivedPacket() {}
    ReceivedPacket(const ReceivedPacket&) = delete;
    ReceivedPacket& operator=(const ReceivedPacket&) = delete;
    ~ReceivedPacket() {}

public :
    static ReceivedPacket& getInstance() {
        static ReceivedPacket instance;
        return instance;
    }

    EthArpPacket popArp() {
        lock_guard<mutex> lock(arpPacketQueueMtx);
        if (arpPacketQueue.empty()) return EthArpPacket(0);
        EthArpPacket ret = arpPacketQueue.front();
        arpPacketQueue.pop();
        return ret;
    }

    vector<u_char> popRelay() {
        lock_guard<mutex> lock(relayPacketQueueMtx);
        if (relayPacketQueue.empty()) return vector<u_char>();
        vector<u_char> ret = relayPacketQueue.front();
        relayPacketQueue.pop();
        return ret;
    }

    void attach(const shared_ptr<Observer>& observer) {
        observers.push_back(observer);
    }

    void detach(const shared_ptr<Observer>& observer) {
        observers.erase(remove(observers.begin(), observers.end(), observer), observers.end());
    }

    void notify(uint16_t n) {
        for (const auto& observer : observers) {
            observer->update(n);
        }
    }

    void process_captured_packet(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
        EthHdr receive_eth;
        memcpy(reinterpret_cast<void *>(&receive_eth), packet, sizeof(EthHdr));
        printf("[Receive|%s] : %d byte\n", \
                receive_eth.type() == EthHdr::Arp ? "Arp" : \
                receive_eth.type() == EthHdr::Ip4 ? "Ip4" : \
                receive_eth.type() == EthHdr::Ip6 ? "Ip6" : \
                "etc..", \
                header->caplen);
        if (receive_eth.type() == EthHdr::Arp) {
            lock_guard<mutex> lock(arpPacketQueueMtx);
            arpPacketQueue.push(EthArpPacket((u_char *)packet));
        }
        else {
            vector<u_char> d(packet,packet+header->caplen);
            lock_guard<mutex> lock(relayPacketQueueMtx);
            relayPacketQueue.push(d);
        }
        thread t([this, type = receive_eth.type()]() {
            this->notify(type);
        });
        t.detach();
        receive_eth.type_ = 0;
    }

    static void call_back_for_pcap_loop(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
        ReceivedPacket* instance = &getInstance();
        instance->process_captured_packet(user_data, header, packet);
    }

    void receive_start(pcap_t *handle) {
        pcap_loop(handle, -1, &ReceivedPacket::call_back_for_pcap_loop, NULL);
    }
};
