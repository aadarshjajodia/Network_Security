Steps on running the program
Unzip the archive. It contains 2 files.
1. mysniffer.c
2. Makefile
3. This readme File

Run make on the folder extracted from the zip archive to build the program. 
It will create an executable mysniffer which will be our executable.

How to run the program

sudo ./mysniffer [-i interface] [-r file] [-s string] expression

-i  Listen on network device <interface>. If not specified, mydump
    will select a default interface to listen on.

-r  Read packets from <file>

-s  Keeps only packets that contain <string> in their payload.

<expression> is a BPF filter that specifies which packets will be dumped. If no
filter is given, all packets seen on the interface (or contained in the trace)
will be dumped. Otherwise, only packets matching <expression> will be dumped.

Implementation:

We first use check whether an interface has been provided using the "-i" argument. If no argument is provided we use the function
char *pcap_lookupdev(char *errbuf) 
which returns a pointer to a string containing the name of the first network device suitable for packet capture; on error, it returns NULL (like other libpcap functions). The errbuf is a user-supplied buffer for storing an error message in case of an error

we now call the function pcap_lookupnet - which finds the IPv4 network number and netmask for a device

Now in case user has specified a pcap file to read from in the -r option then we use the function 
pcap_open_offline - which opens a captured file for reading else we use the function 
pcap_open_live which opens the device found previously for reading. 

We then use the function 
pcap_datalink - to get the link-layer header type

Following which now we use pcap_compile to compiler our filter using the filter expression provided as an input argument
and then we use pcap_setfilter to apply the filter. In case the filter argument from input is empty no filter would be applied and all the packets would be printed. 

We now use the function int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) to collect the packets and process them. It will return when cnt number of packets have been captured. Here we provide its value as 0, to keep on capturing tha packets till the user terminates the program. A callback function is used to handle captured packets

The following types of packets have been captured. 
Witihin IP - TCP, UDP, ICMP. For any other types of IP packets the ethernet and ip header information is printed along with the term OTHER to denote it is not of the above packets. 

If packet is not an IP packet, the MAC address along with the term "OTHER" is output. 

Sample output for this command 

sudo ./mysniffer -r hw1.pcap icmp | less

2013-01-14 12:42:31.752299 c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e ethertype IPv4 (0x800) length 90 ICMP Payload (48 bytes):
00000   45 00 00 30 00 00 40 00  2e 06 6a 5a c0 a8 00 c8    E..0..@...jZ....
00016   01 ea 1f 14 00 50 7b 81  bd cd 09 c6 3a 35 22 b0    .....P{.....:5".
00032   70 12 39 08 11 ab 00 00  02 04 05 b4 01 01 04 02    p.9.............

Reference:
http://www.tcpdump.org/pcap.html
