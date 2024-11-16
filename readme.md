# ISA Project 2: Application for obtaining statistics of network traffic

## About me

- Martin Valach `xvalac12`
- 14.11.2024

## Submitted files

- /src/isa-top.cpp
- /src/Makefile
- readme.md
- documentation.pdf

## Description of the implementation

The application is implemented in the C/C++ programming language using standard C and C++ libraries  and libraries for handling packets.  
The compilation is done using a **Makefile**  and the `make` command . It has been tested to run on Ubuntu 24 and Linux Mint 22 Cinnamon and Windows 11. 
Note that this application requires root privileges to capture network traffic.

### Requirements

To use this application, you will need the following:`

- g++ compiler

- libpcap library [1]

### Command Line Arguments

`./isa-top -i interface [-s b|p] [-t time] [-h]`

`-i interface`: interface to sniff
<!---
, if this parameter is not specified or name of interface is not specified, list of available interfaces is printed
-->
`-s b|p`: sort statistics by number of bytes (b) or number of packets
`-t time`: refresh time of statistics

`-h`: print usage and exit application

Arguments can be in any order. If argument -s is not specified, traffic is  sorted by number of bytes. If argument -t is not specified, default value is 1 (1 second).

### Program

The user provides a network interface name and optional parameters for sorting and refresh interval. The program sets up the capturing handler, applying filters `(tcp or udp or icmp)` to capture defined packets.
Then separate thread runs `pcap_loop()` function to capture packets and calls `callback()` funtion for each packet.
The callback() function extracts key information from each packet and updates the `map` with communications.
The main thread uses `ncurses` library to periodically print formatted communication statistics.
The statistics are sorted based on either data size or packet count, as specified by the user.
At the end, program cleans up resources from packet capturing, join sniffing thread back to main thread and ends `ncurses` window when the program is terminated `(ctrl+c)`.


### Implemented features

- working command line arguments
- working communication statistics print for maximum of 10 communications
- receiving and transmitting communication is print as bidirectional communication
- working sorting by size/packets
- packets and packet size is print with correct unit
- default refresh rate is 1 second
- additionally, user can entered custom refresh rate
- IPv4 and IPv6 are supported
- TCP, UDP and ICMP protocols are supported


## Structure of packets

### TCP packet header structure [2]

| Field | Length | Description |
|-----------------------|-----------|---------------------------------------------------------------------------------------|
| Source Port | 2 bytes | The port number on the sender's device |
| Destination Port | 2 bytes | The port number on the recipient's device |
| Sequence Number | 4 bytes | Used to keep track of the order of data packets sent between the sender and recipient |
| Acknowledgment Number | 4 bytes | Used to acknowledge receipt of data packets by the recipient |
| Data Offset | 4 bits | Size of the TCP header |
| Reserved | 6 bits | These bits are reserved for future use |
| Flags | 6 bits | This field contains several flags that control the behavior |
| Window Size | 2 bytes | The number of bytes the sender is willing to receive before it expects an ACK |
| Checksum | 2 bytes | This is used to detect errors |
| Urgent Pointer | 2 bytes | This is used to indicate the location of urgent data |
| Options | variable | Additional TCP options |

### UDP packet header structure [3]

| Field | Length | Description |
|-------------------|-----------|-------------------------------------------|
| Source Port | 2 bytes | The port number on the sender's device |
| Destination Port | 2 bytes | The port number on the recipient's device |
| Length | 2 bytes | The length of the entire UDP packet |
| Checksum | 2 bytes | This is used to detect errors |

### ICMP packet header structure [4]

| Field | Length | Description |
|-----------|-----------|-------------------------------------------|
| Type | 1 byte | The port number on the sender's device |
| Code | 1 byte | The port number on the recipient's device |
| Checksum | 2 bytes | The length of the entire UDP packet |

## Bibliography

- [1][libpcap](https://www.tcpdump.org/) - _The Tcpdump Group_. Accessed 14 Nov. 2024.

- [2][Transmission Control Protocol (TCP)](https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp#:~:text=Packet%20format&text=The%20IP%20data%20section%20is,size%20of%20the%20options%20field) - _Khan Academy_. Accessed 14 Nov. 2024.

- [3][UDP Protocol | User Datagram Protocol](https://www.javatpoint.com/udp-protocol#:~:text=UDP%20Header%20Format,would%20be%2065%2C535%20minus%2020) - _Javatpoint_. Accessed 14 Nov. 2024.

- [4][What Is ICMP Protocol.](https://www.tutorialspoint.com/what-is-icmp-protocol#:~:text=ICMP%20Message%20Format,255%20are%20the%20data%20messages) - _Online Courses and EBooks Library_. Accessed 14 Nov. 2024.
<!---
`- [7][Internet Control Message Protocol Version 6 (ICMPv6) Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml) - _Internet Assigned Numbers Authority_. Accessed 17 Apr. 2023.`

`- [NESFIT/IPK-Projekty - IPK-Projekty - FIT - VUT Brno - Git.](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master) _FIT - VUT Brno - Git_. Accessed 21 Mar. 2023.`
-->
