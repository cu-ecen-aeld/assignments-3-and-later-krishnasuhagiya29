# Compiler settings
CC = gcc
CROSS_COMPILE ?=

# Add debugging information and enable compiler warnings
CFLAGS  = -g -Wall

# Set the target name
TARGET = writer

# Default build
all: $(TARGET)

$(TARGET): $(TARGET).o
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).o

$(TARGET).o: $(TARGET).c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c $(TARGET).c

clean:
	$(RM) $(TARGET) $(TARGET).o
