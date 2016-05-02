# the compiler: gcc for C program
CC = gcc

# the build target executable:
TARGET = mysniffer

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c -lpcap

clean:
	$(RM) $(TARGET)