# Compiler settings
CC ?= $(CROSS_COMPILE)gcc

# Add debugging information and enable compiler warnings
CFLAGS  = -g -Wall -Werror

# Set the target name
TARGET = aesdsocket

.PHONY: default all clean

default: $(TARGET)

all: $(TARGET)

$(TARGET): $(TARGET).o
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).o -lpthread

$(TARGET).o: $(TARGET).c
	$(CC) $(CFLAGS) -c $(TARGET).c

# Remove the aesdsocket application and all .o files
clean:
	$(RM) $(TARGET) *.o
