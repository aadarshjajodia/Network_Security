# the compiler: gcc for C program
CC = gcc
CPLUSPLUS = g++ 

# the build target executable:
TARGET = mysniffer dnsdetect dnsinject

all: dnsdetect mysniffer dnsinject

dnsdetect: dnsdetect.cpp
	$(CPLUSPLUS) -o dnsdetect dnsdetect.cpp -lpcap

mysniffer: mysniffer.c
	$(CC) -o mysniffer mysniffer.c -lpcap

dnsinject: dnsinject.cpp
	$(CPLUSPLUS) -o dnsinject dnsinject.cpp -lpcap	
clean:
	$(RM) $(TARGET)
