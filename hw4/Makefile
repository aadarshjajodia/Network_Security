# the compiler: gcc for C program
CC = gcc
CPLUSPLUS = g++ 

# the build target executable:
TARGET = mysniffer dnsdetect

all: dnsdetect mysniffer

dnsdetect: dnsdetect.cpp
	$(CPLUSPLUS) -o dnsdetect dnsdetect.cpp -lpcap

mysniffer: mysniffer.c
	$(CC) -o mysniffer mysniffer.c -lpcap

clean:
	$(RM) $(TARGET)
