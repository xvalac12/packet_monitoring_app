#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <string>

using namespace std;

int main(int argc, char *argv[])
{
    // enp4s0
    char errbuf[PCAP_ERRBUF_SIZE];

	const string device = "enp4s0";
    pcap_t *handler;

    // cout << device << endl;

    // 1. say device we want to sniff
    // 2. make ruleset (filter), which protocols, ports, etc. (string)
    // 3. enter sniffing loop


    // device name, maximum number of bytes to capture, promisc. mode, timeout in ms, string for error
    handler = pcap_open_live(device.c_str(), BUFSIZ, true, 1000, errbuf);
	if (handler == NULL)
    {
        cerr << "Error in opening device " << errbuf << endl; 
    }
    

}