#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <string>


using namespace std;

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    return;
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
    
    pcap_loop(handler, 1, callback, NULL);
    
	pcap_freecode(&filter);
    pcap_close(handler);
}