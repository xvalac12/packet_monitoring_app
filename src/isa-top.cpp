/*                      C Libraries                       */
#include <stdio.h>              // std c
#include <unistd.h>             // getopt function

/*                      C++ libaries                      */
#include <iostream>             // std c++
#include <string>               // string data type
#include <map>                  // map container
#include <algorithm>            // sort function
#include <vector>               // using vector
#include <iomanip>              // precision set
#include <sstream>

/*                   Networking libraries                  */
#include <pcap.h>               // packet capturing
#include <netinet/ip.h>         // ipv4 header
#include <netinet/ip6.h>        // ipv6 header 
#include <netinet/tcp.h>        // tcp header
#include <netinet/udp.h>        // udp header
#include <netinet/ip_icmp.h>    // icmp header

/*               Libraries for print on terminal            */
#include <ncurses.h>            // printing in terminal
#include <thread>               // ncurses thread for print


using namespace std;

/**
 * @brief struct Packet, which will ne used as template for key of map
 * 
 */
struct Packet
{
    string first_addr;
    string second_addr;
    int first_port;
    int second_port;
    int def_protocol;

    /**
     * @brief Construct a new Packet object
     * 
     * @param src_addr source address of packet
     * @param dst_addr destination address of packet
     * @param src_port source port of packet
     * @param dst_port destination port of packet
     * @param protocol packet protocol
     */
    Packet(string& src_addr, string& dst_addr, int src_port, int dst_port, int protocol) 
    {
        def_protocol = protocol;

        // used for bidirectional communication
        if (src_addr > dst_addr)
        {
            first_addr = src_addr;
            first_port = src_port;
            second_addr = dst_addr;
            second_port = dst_port;
        } 
        else 
        {
            first_addr = dst_addr;
            first_port = dst_port;
            second_addr = src_addr;
            second_port = src_port;
        }
    }
    /**
     * @brief overloading of < operator with function tie for simplification
     * 
     * @param aux reference to object
     * @return true objects are not same
     * @return false it is same object
     */
    bool operator<(const Packet& aux) const 
    {
        return 
        tie(first_addr, second_addr, first_port, second_port, def_protocol) < 
        tie(aux.first_addr, aux.second_addr, aux.first_port, aux.second_port, aux.def_protocol);
    }
};
/**
 * @brief map, where Packet is key and nested pair is value, it is used for storing communication to refresh
 * 
 */
map<Packet, pair<pair<int,int>, pair<int,int>>> communication;

/**
 * @brief function called by pcap_loop() everytime packet is captured on interface
 * 
 * @param args special pointer for user defined data (last parameter of pcap_loop())
 * @param header struct with metadata of packet (timestamp, packet lenght, lenght of packet before capture)
 * @param packet pointer to packet data
 */
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *ethernet_header = (struct ip*)(packet + 14); // lenght of ethernet header
    uint16_t ether_type = ntohs(*(uint16_t*)(packet + 12)); // EtherType from ethernet frame
    
    int data_size = header->len;    // full lenght of packet before capturing
    int src_port = 0, dst_port = 0, protocol = 0;
    string src_addr, dst_addr; 

    // ntohs() - network to host short, because of endians - used for port convering

    if (ether_type == 0x0800)   // ipv4 packet
    {
        protocol = ethernet_header->ip_p;
        src_addr = inet_ntoa(ethernet_header->ip_src);
        dst_addr = inet_ntoa(ethernet_header->ip_dst);
    
        if (ethernet_header->ip_p == 6) // tcp
        {
            struct tcphdr *tcp = (struct tcphdr*)(packet + 14 + ethernet_header->ip_hl * 4);
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
        } 
        else if (ethernet_header->ip_p == 17) //udp
        {
            struct udphdr *udp = (struct udphdr*)(packet + 14 + ethernet_header->ip_hl * 4);
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
        }
    }
    else if (ether_type == 0x86DD)  // ipv6 packet 
    { 
        struct ip6_hdr *ipv6_header = (struct ip6_hdr*)(packet + 14);
        char readable_src_ip[46];
        char readable_dst_ip[46];

        inet_ntop(AF_INET6, &(ipv6_header->ip6_src), readable_src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), readable_dst_ip, INET6_ADDRSTRLEN);

        src_addr = readable_src_ip;
        dst_addr = readable_dst_ip;
        protocol = ipv6_header->ip6_nxt;

        if (protocol == 6) // tcp
        {
            struct tcphdr *tcp = (struct tcphdr*)(packet + 14 + sizeof(struct ip6_hdr));
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
        } 
        else if (protocol == 17) // udp
        {
            struct udphdr *udp = (struct udphdr*)(packet + 14 + sizeof(struct ip6_hdr));
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
        }
    }

    // skip protocol 128
    if (protocol == 128) return;

    Packet new_packet(src_addr, dst_addr, src_port, dst_port, protocol);

    // data and packets to RX
    if (src_addr == new_packet.first_addr && dst_addr == new_packet.second_addr)
    {
        communication[new_packet].first.first += data_size;
        communication[new_packet].first.second += 1;
    }
    else // data and packets to TX
    {
        communication[new_packet].second.first += data_size;
        communication[new_packet].second.second += 1;
    }
}

/**
 * @brief aux function for sorting vector with communication by data size
 * 
 * @param first_pair first communication
 * @param second_pair second communicatiom
 * @return true if is first communication bigger
 * @return false if the first communication isn't bigger
 */
bool sort_by_data_size(pair<Packet, pair<pair<int, int>, pair<int, int>>>& first_pair, pair<Packet, pair<pair<int, int>, pair<int, int>>>& second_pair) 
{
    return (first_pair.second.first.first + first_pair.second.second.first) > (second_pair.second.first.first + second_pair.second.second.first);
}

/**
 * @brief aux function for sorting vector with communication by number of packets
 * 
 * @param first_pair first communication
 * @param second_pair second communication
 * @return true if is first communication has more packets
 * @return false if the first communication hasn't more packets
 */
bool sort_by_packet_count(pair<Packet, pair<pair<int, int>, pair<int, int>>>& first_pair, pair<Packet, pair<pair<int, int>, pair<int, int>>>& second_pair) 
{
    return (first_pair.second.first.second + first_pair.second.second.second) > (second_pair.second.first.second + second_pair.second.second.second);
}

/**
 * @brief convert bandwidth to correct value with unit 
 * 
 * @param value full integer value
 * @return string converted value with unit
 */
string convert_bandwidth(float value) 
{
    ostringstream stream; 
    stream << fixed << setprecision(1);

    if (value >= 1000000000) 
    {
        stream << value / 1000000000 << + "G";
    }
    else if (value >= 1000000) 
    {
        stream << value / 1000000 << + "M";
    }
    else if (value >= 1000) 
    {
        stream << value / 1000 << + "k";
    }
    else
    {
        return to_string(int(value)); 
    }

    return stream.str();
}    

/**
 * @brief covert IANA protocol number to protocol keyword name
 * 
 * @param value IANA protocol number 
 * @return string with protocol keyword name
 */
string convert_protocol(int value)
{
    switch (value)
    {
        case 6:
            return "TCP";
            break;
        case 17:
            return "UDP";
            break;
        case 1:
            return "ICMP";
            break;
        default:
            return "ERR";
            break;
    }
}

/**
 * @brief print static header of communication statistics
 * 
 */
void print_head()
{
    mvprintw(0, 0, "Src IP:port");
    mvprintw(0, 45, "Dst IP:port");
    mvprintw(0, 90, "Proto");
    mvprintw(0, 100, "Rx");
    mvprintw(0, 115, "Tx");   
    mvprintw(1, 100, "b/s     p/s");
    mvprintw(1, 115, "b/s     p/s");
}

/**
 * @brief function for printing communication statistics using ncurses
 * 
 * @param sort_by_size bool value to determinate order of statistic
 */
void print_stats(bool sort_by_size) 
{
    // aux vector for copy content of the map
    
    vector<pair<Packet, pair<pair<int, int>, pair<int, int>>>> sorted_vector(communication.begin(), communication.end());
    communication.clear(); // clear content of map


    if (sort_by_size)
    {
        sort(sorted_vector.begin(), sorted_vector.end(), sort_by_data_size);
    }
    else
    {
        sort(sorted_vector.begin(), sorted_vector.end(), sort_by_packet_count);
    }
    
    for (size_t cnt = 0; cnt < min(sorted_vector.size(), size_t(10)); ++cnt) 
    {
        auto &entry = sorted_vector[cnt];

        // icmp has no port number, so we skip printing it
        if (convert_protocol(entry.first.def_protocol) == "ICMP")
        {
            mvprintw(2 + cnt, 0 , "%s", entry.first.first_addr.c_str());
            mvprintw(2 + cnt, 45 , "%s", entry.first.second_addr.c_str());
        }
        else // tcp and udp have port number
        {
            mvprintw(2 + cnt, 0 , "%s:%d", entry.first.first_addr.c_str(), entry.first.first_port);
            mvprintw(2 + cnt, 45 , "%s:%d", entry.first.second_addr.c_str(), entry.first.second_port);
        }
        mvprintw(2 + cnt, 90 , "%s", convert_protocol(entry.first.def_protocol).c_str());
        mvprintw(2 + cnt, 100 , "%s", convert_bandwidth(entry.second.first.first).c_str());
        mvprintw(2 + cnt, 108 , "%s", convert_bandwidth(entry.second.first.second).c_str());
        mvprintw(2 + cnt, 115 , "%s", convert_bandwidth(entry.second.second.first).c_str());
        mvprintw(2 + cnt, 123 , "%s", convert_bandwidth(entry.second.second.second).c_str());
    }
    refresh();
}


/**
 * @brief Main function of program
 * 
 * @param argc number of program arguments
 * @param argv array of program arguments
 * @return int integer number in case of error
 */
int main(int argc, char *argv[])
{


    int option;
    string interface;
    int time_interval = 1;
    bool sort_by_size = true;

    // cli arguments parsing
    while ((option = getopt(argc, argv, "i:s:t:h")) != -1) 
    {
        switch (option) 
        {
            case 'i':
                interface = optarg;
                break;
            case 's':
                if (optarg[0] == 'b')
                {
                    sort_by_size = true;
                } 
                else if (optarg[0] == 'p')
                {
                    sort_by_size = false;
                }
                else
                {
                    cerr << "Invalid value for -s. Print usage with ./isa-top -h"  << endl;;
                    return 1;
                }
                break;
            case 't':
                try 
                {
                    time_interval = stoi(optarg);
                } 
                catch (invalid_argument& e) 
                {
                    cerr << "Invalid value for -t. It must be a unsigned integer number."  << endl;;
                    return 1;
                }
                break;
            case 'h': // Handle unknown options
                cerr << "Usage: ./isa-top -i <interface> [-s b|p] [-t <time>]" << endl;
                return -1;
            default:
                cerr << "Unknown option " << static_cast<char>(optopt) << endl;
                return 1;
        }
    }

    // interval must be at least 1
    if (time_interval < 1)
    {
        cerr << "Invalid value for -t. It must be a unsigned integer number."  << endl;
        return 1;    
    }

    // no interface name entered
    if (interface.empty()) 
    {
        cerr << "Error: The -i option (interface) is required. Print usage with ./isa-top -h" << endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];	
    string ruleset = "udp or tcp or icmp"; // filter for packet capturing
    struct bpf_program filter;
    auto filter_err = 0;
    pcap_t *handler;

    bpf_u_int32 mask;
    bpf_u_int32 address;


    if (pcap_lookupnet(interface.c_str(), &address, &mask, errbuf) == -1)
    {
        cerr << "No netmask for interface" << endl;
        address = 0, mask = 0;
    }

    // device name, maximum number of bytes to capture, promisc. mode, timeout in ms, string for error
    handler = pcap_open_live(interface.c_str(), BUFSIZ, true, 1000, errbuf);
	if (handler == NULL)
    {
        cerr << "Error in opening device " << errbuf << endl;
        pcap_freecode(&filter);
        return(-2);
    }
   
    // handler, struct of filter, string with rules, is optimized, address of interface
    filter_err = pcap_compile(handler, &filter, ruleset.c_str(), 0, address);
    
    // handler, struct of filter
    filter_err = pcap_setfilter(handler, &filter);

    if (filter_err == -1)
    {
        cerr << "Error in setting filter: "<< pcap_geterr(handler) << endl;
        pcap_freecode(&filter);
        return(-2);
    }

    // init od ncurses window    
    initscr();	
        
    // thread for capturing packets
    thread pcap_thread([&] 
    {
        pcap_loop(handler, 0, callback, NULL);
    });


    // infinite loop for ncurses printing
    while (true) 
    {
        print_head();
        print_stats(sort_by_size);
        this_thread::sleep_for(chrono::seconds(time_interval));
        clear();
    }

    endwin();
    pcap_thread.join();
    pcap_freecode(&filter);    
    pcap_close(handler);
}