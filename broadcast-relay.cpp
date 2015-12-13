/*
Copyright (c) 2015, John Eaglesham
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <iostream>
#include <vector>
#include <sstream>

#define __USE_BSD

#include <pcap/pcap.h>
#include <arpa/inet.h>

#if defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif

#ifdef __linux
#define ETHERTYPE_IPV6 ETH_P_IPV6
#define __FAVOR_BSD
#endif

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <getopt.h>

#define MAX_PACKET 10240

typedef char EtherMac[6];
typedef std::vector<uint16_t> PortContainer;

bool VERBOSE = false;

class PcapLive {
public:
	PcapLive(const char *dev, int bufsize, int promisc, int to_ms);
	~PcapLive();
    pcap_t *handle;
};

PcapLive::PcapLive(const char *dev, int bufsize, int promisc, int to_ms)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, bufsize, promisc, to_ms, errbuf);
    if (handle == NULL) {
        std::ostringstream msg;
        msg << "Pcap error:" << errbuf;
        throw std::runtime_error(msg.str());
    }
}

PcapLive::~PcapLive()
{
    if (handle != NULL) pcap_close(handle);
}

#ifdef SIOCGIFHWADDR
bool get_interface_mac(std::string dev, EtherMac *out)
{
    int fd;
    struct ifreq ifr;
    if (out == NULL) return false;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) return false;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        return false;
    }
    close(fd);
    memcpy(out, ifr.ifr_hwaddr.sa_data, ETHER_MAC_LEN);
    return true;
}
#elif defined(__FreeBSD__) || (defined(__APPLE__) && defined(__MACH__))
bool get_interface_mac(std::string dev, EtherMac *out)
{
    struct ifaddrs *ifap;

    if (out == NULL) return false;
    if (getifaddrs(&ifap) != 0) return false;

    for (struct ifaddrs *p = ifap; p != NULL; p = p->ifa_next) {
        if ((p->ifa_addr->sa_family == AF_LINK) && (dev.compare(p->ifa_name) == 0)) {
            struct sockaddr_dl* dl = (struct sockaddr_dl *) p->ifa_addr;
            memcpy(out, ((unsigned char *) dl->sdl_data) + dl->sdl_nlen, sizeof(EtherMac));
            freeifaddrs(ifap);
            return true;
        }
    }
    freeifaddrs(ifap);
    return false;
}
#else
#error "Do not know how to get MAC address on this platform."
#endif

void relay_thread(std::string from, std::string to, std::shared_ptr<PortContainer> allowed_ports)
{
    struct bpf_program pcap_filter;
    std::string pcap_filter_eth("broadcast and udp");
    std::string pcap_filter_null("udp");
    std::string pcap_filter_str;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t mask, net;
    struct pcap_pkthdr *packet_header;
    const unsigned char *packet_data;
    int recv_link_type, send_link_type;
    EtherMac send_mac;

    try {
        PcapLive pcap_recv(from.c_str(), 65535, 0, 250);
        recv_link_type = pcap_datalink(pcap_recv.handle);
        PcapLive pcap_send(to.c_str(), 65535, 0, 250);
        send_link_type = pcap_datalink(pcap_send.handle);

        if (pcap_lookupnet(from.c_str(), &net, &mask, errbuf) != 0) {
            std::cout << "Couldn't get netmask for device" << errbuf << std::endl;
            net = 0;
            mask = 0;
        }

        /* Pick a pacp filter */
        switch(recv_link_type) {
            case DLT_NULL: 
            case DLT_RAW:
                pcap_filter_str = pcap_filter_null;
                break;
            default: pcap_filter_str = pcap_filter_eth;
        }

        if (!allowed_ports->empty()) {
            pcap_filter_str += " and (";
            for(auto const &entry : *allowed_ports) {
                pcap_filter_str += "dst port " + std::to_string(entry) + " or ";
            }
            pcap_filter_str.replace(pcap_filter_str.length() - 4, 4, ")");
        }
        /* Testing shows this has to go at the end, for some reason. */
        pcap_filter_str += " and not vlan";

        if (VERBOSE) {
            std::cout << "Using pcap filter: " << pcap_filter_str << std::endl;
        }

        if (send_link_type == DLT_EN10MB) {
            if (!get_interface_mac(to, &send_mac)) {
                std::ostringstream msg;
                msg << "Failed to get mac for: " << to;
                throw std::runtime_error(msg.str());
            }
        }
        if (pcap_compile(pcap_recv.handle, &pcap_filter, pcap_filter_str.c_str(), 0, net) != 0) {
            std::ostringstream msg;
            msg << "Pcap error, couldn't parse filter: " << pcap_geterr(pcap_recv.handle);
            throw std::runtime_error(msg.str());
        }
        if (pcap_setfilter(pcap_recv.handle, &pcap_filter) != 0) {
            std::ostringstream msg;
            msg << "Pcap error, couldn't set filter: " << pcap_geterr(pcap_recv.handle);
            throw std::runtime_error(msg.str());
        }

        while(1) {
            int r = pcap_next_ex(pcap_recv.handle, &packet_header, &packet_data);
            ptrdiff_t ip_offset;
            int packet_protocol;

            if (r < 0 || r > 1) break;
            if (r == 0 || packet_header == NULL || packet_data == NULL) continue;

            switch(recv_link_type) {
                case DLT_EN10MB:
                    ip_offset = 14;
                    break;
                case DLT_NULL:
                    ip_offset = 4;
                    break;
                case DLT_RAW:
                    ip_offset = 0;
                    break;
                case DLT_LINUX_SLL:
                    ip_offset = 16;
                    break;
                default:
                    throw std::runtime_error("Unsupported interface type");
            }

            if (packet_header->caplen < 40
                || ip_offset >= packet_header->caplen
                || packet_header->caplen > MAX_PACKET - sizeof(struct ether_header)
            ) continue;

            switch (packet_data[ip_offset] >> 4) {
            case 4:
                packet_protocol = ETHERTYPE_IP;
                break;
            case 6:
                packet_protocol = ETHERTYPE_IPV6;
                break;
            default:
                if (VERBOSE) {
                    std::cout << "Not relaying unknown protocol (not IP or IPv6?)" << std::endl;
                }
                continue;
            }

            if (VERBOSE) {
                std::cout << "Got a packet to relay on " << from << ", ";
                switch (packet_protocol) {
                case ETHERTYPE_IP:
                    for (int x = 12; x <= 15; x++) {
                        std::cout << ((unsigned int)packet_data[ip_offset + x]) << (x == 15 ? " -> " : "." );
                    }
                    for (int x = 16; x <= 19; x++) {
                        std::cout << ((unsigned int)packet_data[ip_offset + x]) << (x == 19 ? "" : "." );
                    }
                    break;
                case ETHERTYPE_IPV6:
                    std::cout << std::hex;
                    for (int x = 8; x <= 23; x++) {
                        std::cout << ((unsigned int)packet_data[ip_offset + x]) << (x == 23 ? " -> " : ":" );
                    }
                    for (int x = 24; x <= 39; x++) {
                        std::cout << ((unsigned int)packet_data[ip_offset + x]) << (x == 39 ? "" : ":" );
                    }
                    std::cout << std::dec;
                    break;
                default:
                    /* We should never get here. */
                    ;
                }
                std::cout << ", ";
            }

            if (send_link_type == DLT_EN10MB) {
                char obuf[MAX_PACKET];
                struct ether_header *eth = (struct ether_header *) obuf;
                eth->ether_type = htons(packet_protocol);
                memcpy(obuf + sizeof(struct ether_header), packet_data + ip_offset, packet_header->caplen - ip_offset);
                /* FF:FF:FF:FF:FF:FF is the broadcast mac. */
                memset(eth->ether_dhost, 255, sizeof(eth->ether_dhost));
                memcpy(eth->ether_shost, send_mac, sizeof(send_mac));
                pcap_sendpacket(pcap_send.handle, (unsigned char *)obuf, packet_header->caplen - ip_offset + sizeof(struct ether_header));
                if (VERBOSE) std::cout << "sent to " << to << " as Ethernet" << std::endl;
            } else if (send_link_type == DLT_NULL) {
                pcap_sendpacket(pcap_send.handle, packet_data + ip_offset, packet_header->caplen - ip_offset);
                if (VERBOSE) std::cout << "sent to " << to << " as NULL" << std::endl;
            } else {
                throw std::runtime_error("Unsupported interface type");
            }
            
        }
    } catch (const std::exception &e) {
        std::cerr << "Relay thread caught exception: " << e.what() << std::endl;
        return;
    }
}

/* options descriptor */
static struct option longopts[] = {
    { "verbose", no_argument,            NULL,           'v' },
    { "relay",   required_argument,      NULL,           'r' },
    { "port",    required_argument,      NULL,           'p' },
    { NULL,      0,                      NULL,           0   }
};

void usage()
{
    std::cout << "usage: broadcast-relay [-v] -r 'from to' [-p X]\n";
    std::cout << "\nbroadcast-relay relays all UDP broadcast packets received on the 'from'\n";
    std::cout << "interface out the 'to' interface, without changing the source or destination\n";
    std::cout << "IP addresses (the source MAC is changed to be from the 'to' interface).\n\n";
    std::cout << "-v\tVerbose output.\n";
    std::cout << "-r\tRelay interface names 'from' and 'to' separated by a space.\n";
    std::cout << "-p\tOnly relay this destination port. Can be specified multiple times.\n";
    std::cout << "\tIf -p is not specified, all broadcasts will be forwarded.\n";
    std::cout << "\nExample:\n\tbroadcast-relay -r 're0 em0' -p 12345\n";
    std::cout << std::endl;
    exit(1);
}

int main(int argc, char *argv[])
{
    char ch;
    std::string from = "";
    std::string to = "";
    auto allowed_ports = std::make_shared<PortContainer>();

    while ((ch = getopt_long(argc, argv, "vr:p:", longopts, NULL)) != -1) {
        size_t bad_number;
        unsigned long port;
        std::stringstream arg;
        switch (ch) {
        case 'v':
            VERBOSE = true;
            break;
        case 'r':
            arg.clear();
            arg << optarg;
            arg >> std::skipws;
            arg >> from;
            arg >> to;
            if (VERBOSE) std::cout << "Parsed relay flag as from " << from << " to " << to << std::endl;
            break;
        case 'p':
            try {
                port = std::stoul(optarg, &bad_number, 10);
                if (port > 65535 || bad_number != strlen(optarg)) throw std::runtime_error("Invalid port");
            } catch (const std::exception &e) {
                std::cerr << "Invalid parameter: " << e.what() << std::endl;
                exit(1);
            }
            allowed_ports.get()->push_back((uint16_t) port);
            if (VERBOSE) std::cout << "Parsed port as permitting port " << port << std::endl;
            break;
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    if (from.empty() || to.empty()) usage();

    relay_thread(from, to, allowed_ports);
  
    return 0;
}
