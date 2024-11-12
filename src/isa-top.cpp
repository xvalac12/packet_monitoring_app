#include <stdio.h>              // std c

#include <iostream>             // std c++
#include <string>               // string data type
#include <map>                  // map container

#include <pcap.h>               // packet capturing
#include <netinet/ip.h>         // ip header
#include <netinet/tcp.h>        // tcp header
#include <netinet/udp.h>        // udp header
#include <netinet/ip_icmp.h>    // icmp header

using namespace std;


struct Packet
{
    string src_addr;
    string dst_addr;
    int protocol;
    int size;
};

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *ipv4_header = (struct ip*)(packet + 14);
    
    Packet new_packet;
    new_packet.src_addr = inet_ntoa(ipv4_header->ip_src);
    new_packet.dst_addr = inet_ntoa(ipv4_header->ip_src);
    new_packet.protocol = ipv4_header->ip_p;
    new_packet.size = header->len;

    cout << new_packet.src_addr << " | "
    << new_packet.dst_addr << " |    "
    << new_packet.protocol << "    | "
    << new_packet.size  << " b"<< endl;  
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
    }
    // handler, struct of filter, string with rules, is optimized, address of interface
    filter_err = pcap_compile(handler, &filter, ruleset.c_str(), 0, address);
    // handler, struct of filter
    filter_err = pcap_setfilter(handler, &filter);

    if (filter_err == -1)
    {
        cerr << "Error in setting filter: "<< pcap_geterr(handler) << endl;
        return(-2);
    }
    

    cout << "Source IP       | Destination IP  | Protocol | Packet Size" << endl;

    pcap_loop(handler, 10, callback, NULL);
    
	pcap_freecode(&filter);
    pcap_close(handler);
}