Steps on running the program
Unzip the archive. It contains 4 files.
1. dnsinject.cpp
2. dnsdetect.cpp
3. Makefile
4. This readme File

Run make on the folder extracted from the zip archive to build the program. 
It will create an executable named "dnsinject" and dnsdetect"

How to run the program

sudo dnsinject [-i interface] [-f hostnames] expression

sudo ./mysniffer [-i interface] "udp and dst port domain"
sudo ./mysniffer [-i interface] [-r file] [-s string] expression

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    dnsinject should select a default interface to listen on. The same
    interface should be used for packet injection.

-f  Read a list of IP address and hostname pairs specifying the hostnames to
    be hijacked. If '-f' is not specified, dnsinject should forge replies for
    all observed requests with the local machine's IP address as an answer.

<expression> is a BPF filter that specifies which packets will be dumped. If no
filter is given, all packets seen on the interface (or contained in the trace)
will be dumped. Otherwise, only packets matching <expression> will be dumped.

The <hostnames> file should contain one IP and hostname pair per line,
separated by whitespace. For example:
10.6.6.6      foo.example.com
10.6.6.6      bar.example.com
192.168.66.6  www.cs.stonybrook.edu

In case there is no filename specified using the -f option, then the attacker's IP address
is chosen to be the IP address sent in the DNS spoofed packet.

Assumptions:
The file entered by the user using the -f option is of the correct format

b) Using dns detect

dnsdetect [-i interface] [-r tracefile] expression

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    the program should select a default interface to listen on.

-r  Read packets from <tracefile> (tcpdump format). Useful for detecting
    DNS poisoning attacks in existing network traces.

<expression> is a BPF filter that specifies a subset of the traffic to be
monitored.

Once an attack is detected, dnsdetect should print to stdout a detailed alert
containing a printout of both the spoofed and legitimate responses. You can
format the output in any way you like. Output must contain the detected DNS
transaction ID, attacked domain name, and the original and malicious IP
addresses - for example:

20160406-15:08:49.205618  DNS poisoning attempt
TXID 0x5cce Request www.example.com
Answer1 [List of IP addresses]
Answer2 [List of IP addresses]

Implementation(DNS INJECT):
We maintain a C++ map of the domain name as the key and IP address as the value which we read from the file.
We also store the attacker's machine ip address which might be used in case the dnsinject command was run without 
specifing the -f options.

We first use check whether an interface has been provided using the "-i" argument. If no argument is provided we use the function
char *pcap_lookupdev(char *errbuf) which returns a pointer to a string containing the name of the first network device suitable for packet capture;

we now call the function pcap_lookupnet - which finds the IPv4 network number and netmask for a device

We check for packets which are UDP and which have the destination port as 53
We specify a BPF filter while compiling the pcap_filter namely "udp and dst port domain". This filter makes sure
that we get callbacks for only DNS requests. Once we get a DNS request, we try to construct a DNS Forged Response.
We first fill the IP Header(We make sure to swap the souce and destination IP address), then UDP Header, then DNS Header.
We then extract the domain name from the DNS Query Part, to check if the domain is present in our pre constructed map,
if the domain is present we take the IP address corresponding to this domain and fill it in the DNS Answer Section(Rdata).
In case the dnsinject command was run without the -f option then we will the DNS Answer section with the attacker machine's IP address.
We make sure that while constructing the DNS Forged Response we will correct values as should be filled for a correctly formatted DNS Response.
Once the DNS Response is constructed we create a raw socket and send the forged DNS Response to the source IP address present in the DNS Query Request

Sample Output:

Forged Response
aadarsh-victim@aadarshvictim-virtual-machine:~$ nslookup www.hdfcbank.com 8.8.4.4
Server:		8.8.4.4
Address:	8.8.4.4#53

Non-authoritative answer:
Name:	www.hdfcbank.com
Address: 172.16.241.157

Original Response
aadarsh-victim@aadarshvictim-virtual-machine:~$ nslookup www.hdfcbank.com 8.8.4.4
Server:		8.8.4.4
Address:	8.8.4.4#53

Non-authoritative answer:
Name:	www.hdfcbank.com
Address: 104.16.56.15
Name:	www.hdfcbank.com
Address: 104.16.57.15

Implementation(DNS DETECT):
We maintain a C++ map of the DNS Txn ID, vs a vector of IP addresses.

Now in case user has specified a pcap file to read from in the -r option then we use the function 
pcap_open_offline - which opens a captured file for reading else we use the function 
pcap_open_live which opens the device found previously for reading. 

We again check for packets which are UDP and but now which have the source port as 53
We specify a BPF filter while compiling the pcap_filter namely "udp and src port domain". This filter makes sure
that we get callbacks for only DNS responses. Once we get a DNS Response(could be a forged or an actual response)
we make an entry in our map with the key as the transaction id, and the value as a vector of strings with the 
IP addresses present in the DNS Answer Section. As soon as we detect that for a particular DNS Transaction ID,
we already have an entry in the map, we consider a DNS Poisoning Attack to have taken place and we store this DNS
Reponses IP address as well in the vector and print out all the IP address which are present in the vector

Sample Output:
DNS poisoning attempt
TXID cf7b Request www.hdfcbank.com
Answer 1 104.16.57.15
Answer 2 104.16.56.15
Answer 3 172.16.241.157

Reference:
http://www.tcpdump.org/pcap.html
http://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux