# Compiler settings
CC = gcc
CROSS_COMPILE ?=

# Add debugging information and enable compiler warnings
CFLAGS  = -g -Wall -Werror

# Set the target name
TARGET = aesdsocket

.PHONY: all clean

# Default build
all: $(TARGET)

$(TARGET): $(TARGET).o
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).o

$(TARGET).o: $(TARGET).c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c $(TARGET).c

# Remove the aesdsocket application and all .o files
clean:
	$(RM) $(TARGET) *.o
