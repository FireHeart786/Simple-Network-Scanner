#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <tins/tins.h>

using namespace Tins;

struct Client {
    std::string ip;
    std::string mac;
};

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target-ip> <interface> <timeout>" << std::endl;
        return 1;
    }
    std::string target_ip = argv[1];
    std::string interface_name = argv[2];
    int timeout = std::stoi(argv[3]);

    try {
        // Create ARP packet
        ARP arp;
        arp.opcode(ARP::REQUEST);
        arp.target_ip_addr(target_ip);

        // Create the Ether broadcast packet
        EthernetII ether;
        ether.dst_addr("ff:ff:ff:ff:ff:ff");
        ether.src_addr("00:11:22:33:44:55");
        ether.type(PDU::ETHERTYPE_ARP);

        // Stack packets
        PacketSender sender;
        Packet packet = ether / arp;

        // Send and receive packets
        std::vector<Client> clients;
        Sniffer sniffer(interface_name);
        sender.send(packet);
        sniffer.sniff_loop([&](Packet& received_packet) {
            // Check if the packet is an ARP response
            if (received_packet.pdu()->find_pdu<ARP>()) {
                ARP& received_arp = received_packet.pdu()->rfind_pdu<ARP>();
                // Check if the ARP response is from the target IP
                if (received_arp.sender_ip_addr() == target_ip && received_arp.opcode() == ARP::REPLY) {
                    // Add client to the list
                    Client client;
                    client.ip = received_arp.sender_ip_addr().to_string();
                    client.mac = received_arp.sender_hw_addr().to_string();
                    clients.push_back(client);
                }
            }
            // Stop capturing packets if all responses have been received or timeout
            if (clients.size() == 256 || received_packet.timestamp().seconds() > timeout) {
                return false;
            }
            return true;
        });

        // Print clients
        std::cout << "Available devices in the network:" << std::endl;
        std::cout << "IP" << std::string(18, ' ') << "MAC" << std::endl;
        for (const auto& client : clients) {
            std::cout << std::setw(16) << std::left << client.ip << "    " << client.mac << std::endl;
        }

    } catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
