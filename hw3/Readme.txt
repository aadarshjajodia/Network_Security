In this assignment you will develop a "plugboard" proxy for adding an extra 
layer of protection to publicly accessible network services.
Instead of connecting directly to the service, clients connect to pbproxy
(running on the same server), which then relays all traffic to the actual service.
Before relaying the traffic, pbproxy decrypts it using a static symmetric key.

Please note i have run this on a Mac machine and i had to install openssl using the following command
sudo brew install openssl -devel
Also in case the program in unable to locate the headers for openssl i have included the location of the headers
as -I option in my Makefile 

How to build the code.
Simply run make in the folder, it should generate a file pbproxy which is our executable

Dependencies:
-- Openssl library

How to run the pbproxy
1. Running PBProxy on the server.

pbproxy -l <port> -k keyfile destination port
  -l  Reverse-proxy mode: listen for inbound connections on <port> and relay
      them to <destination>:<port>

  -k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)

2. Running PBProxy on the client.
	pbproxy -k keyfile destination port

Testing the code.
1. 
	On the server side
	./pbproxy -l 2222 -k key localhost 22
	On the client side
	ssh -o "ProxyCommand ./pbproxy -k key localhost 2222" localhost
2. 
	On the server.
	First we run nc.
	nc -l 12345
	./pbproxy -l 2222 -k key localhost 12345

	On the client
	./pbproxy -k key localhost 2222

	Now anything we write on the client is echoed back to the server using netcat.


Working:
The programs runs in either server mode or client mode depending on the input provided by the user.
If the user provides with a -l option, the program runs in server mode listening on the port provided
as part of the -l argument. For every client that connects to the server a new thread is created on
the server to maintain that particular session.

Encryption and Decryption are done using AES in CTR mode. IV is used here and the bytes of IV are generated randomly.

At client mode, in an infinite loop (while (1)) we try to read data from STDIN, encrypt the data and
write it to the socket to send to the server and we also read any data present on the socket, decrypt
the data and write it to STDOUT to be displayed at the client side.
We set stdin and socket to non-blocking mode to avoid blocking forever

At server side, in each thread which serves the client, data is read from the socket which is established with pbproxy,
decrypted and written to ther server, and data from the server is encrypted and written back to pbproxy.
Similarly on the server we set pbproxy socket and server socket to non-blocking mode to avoid blocking forever.

References.

http://stackoverflow.com/questions/29441005/aes-ctr-encryption-and-decryption
http://stackoverflow.com/questions/2029103/correct-way-to-read-a-text-file-into-a-buffer-in-c