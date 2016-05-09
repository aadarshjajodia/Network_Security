# the compiler: gcc for C program
CPLUSPLUS = g++ 

# the build target executable:
TARGET = dnsdetect dnsinject

all: dnsdetect dnsinject

dnsdetect: dnsdetect.cpp
	$(CPLUSPLUS) -o dnsdetect dnsdetect.cpp -lpcap

dnsinject: dnsinject.cpp
	$(CPLUSPLUS) -o dnsinject dnsinject.cpp -lpcap	
clean:
	$(RM) $(TARGET)
