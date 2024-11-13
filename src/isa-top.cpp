#include <stdio.h>              // std c

#include <iostream>             // std c++
#include <string>               // string data type
#include <map>                  // map container
//#include <tuple>
#include <algorithm>            // sort function
#include <vector>               // using vector
#include <iomanip>              // precision set
#include <sstream>

#include <pcap.h>               // packet capturing
#include <netinet/ip.h>         // ip header
#include <netinet/tcp.h>        // tcp header
#include <netinet/udp.h>        // udp header
#include <netinet/ip_icmp.h>    // icmp header
 
#include <ncurses.h>            // 
#include <thread>               // ncurses thread for print

using namespace std;


struct Packet
{
    string first_addr;
    string second_addr;
    int def_protocol;

    Packet(string& src_addr, string& dst_addr, int protocol) 
    {
        if (src_addr > dst_addr) {
            first_addr = src_addr;
            second_addr = dst_addr;
        } 
        else 
        {
            first_addr = dst_addr;
            second_addr = src_addr;
        }
        def_protocol = protocol;
    }

    bool operator<(const Packet& other) const 
    {
        return 
        tie(first_addr, second_addr, def_protocol) < 
        tie(other.first_addr, other.second_addr, other.def_protocol);
    }
};

map<Packet, pair<pair<int,int>, pair<int,int>>> communication;

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *ipv4_header = (struct ip*)(packet + 14);
    
    string src_addr = inet_ntoa(ipv4_header->ip_src);
    string dst_addr = inet_ntoa(ipv4_header->ip_dst);
    int protocol = ipv4_header->ip_p;
    int data_size = header->len;
    
    if (protocol == 128) return;

    Packet new_packet(src_addr, dst_addr, protocol);

    if (src_addr == new_packet.first_addr && dst_addr == new_packet.second_addr)
    {
        communication[new_packet].first.first += data_size;
        communication[new_packet].first.second += 1;
    }
    else
    {
        communication[new_packet].second.first += data_size;
        communication[new_packet].second.second += 1;
    }
}

bool sort_by_data_size(pair<Packet, pair<pair<int, int>, pair<int, int>>>& first_pair, pair<Packet, pair<pair<int, int>, pair<int, int>>>& second_pair) 
{
    return (first_pair.second.first.first + first_pair.second.second.first) > (second_pair.second.first.first + second_pair.second.second.first);
}

bool sort_by_packet_count(pair<Packet, pair<pair<int, int>, pair<int, int>>>& first_pair, pair<Packet, pair<pair<int, int>, pair<int, int>>>& second_pair) 
{
    return (first_pair.second.first.second + first_pair.second.second.second) > (second_pair.second.first.second + second_pair.second.second.second);
}


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

void print_head()
{
    mvprintw(0, 0, "Src IP:port");
    mvprintw(0, 20, "Dst IP:port");
    mvprintw(0, 40, "Proto");
    mvprintw(0, 50, "Rx");
    mvprintw(0, 65, "Tx");   
    mvprintw(1, 50, "b/s     p/s");
    mvprintw(1, 65, "b/s     p/s");
}

void print_stats() 
{
    vector<pair<Packet, pair<pair<int, int>, pair<int, int>>>> sorted_vector(communication.begin(), communication.end());
    communication.clear();
    sort(sorted_vector.begin(), sorted_vector.end(), sort_by_data_size);
    // sort(sorted_vector.begin(), sorted_vector.end(), sort_by_packet_count);

    for (size_t cnt = 0; cnt < min(sorted_vector.size(), size_t(10)); ++cnt) 
    {
        auto &entry = sorted_vector[cnt];
        mvprintw(cnt + 2, 0 , "%s", entry.first.first_addr.c_str());
        mvprintw(cnt + 2, 20 , "%s", entry.first.second_addr.c_str());
        mvprintw(cnt + 2, 40 , "%s", convert_protocol(entry.first.def_protocol).c_str());
        mvprintw(cnt + 2, 50 , "%s", convert_bandwidth(entry.second.first.first).c_str());
        mvprintw(cnt + 2, 58 , "%s", convert_bandwidth(entry.second.first.second).c_str());
        mvprintw(cnt + 2, 65 , "%s", convert_bandwidth(entry.second.second.first).c_str());
        mvprintw(cnt + 2, 73 , "%s", convert_bandwidth(entry.second.second.second).c_str());
    }
    refresh();
}


int main(int argc, char *argv[])
{
    // enp4s0
    char errbuf[PCAP_ERRBUF_SIZE];

	const string device = "enp4s0";
    const string ruleset = "udp or tcp or icmp";
    struct bpf_program filter;
    auto filter_err = 0;
    pcap_t *handler;

    bpf_u_int32 mask;
    bpf_u_int32 address;


    if (pcap_lookupnet(device.c_str(), &address, &mask, errbuf) == -1)
    {
        cerr << "No netmask for interface" << endl;
        address = 0, mask = 0;
    }

    // device name, maximum number of bytes to capture, promisc. mode, timeout in ms, string for error
    handler = pcap_open_live(device.c_str(), BUFSIZ, true, 1000, errbuf);
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
        
    initscr();	
        
    thread pcap_thread([&] 
    {
        pcap_loop(handler, 0, callback, NULL);
    });

    while (true) 
    {
        print_head();
        print_stats();
        this_thread::sleep_for(chrono::seconds(1));
        clear();
    }

    endwin();
    pcap_thread.join();
    pcap_freecode(&filter);    
    pcap_close(handler);
}