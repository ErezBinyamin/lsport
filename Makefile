# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Target executable
TARGET = lsport

# Source files
SRCS = src/lsport.c

# Object files
OBJS = $(SRCS:.c=.o)

# Default rule to build the executable
all: $(TARGET)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link object files into the final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

# Clean up generated files
clean:
	rm -f $(OBJS) $(TARGET)

# Display help message
help:
	@echo "Makefile for lsport"
	@echo "Targets:"
	@echo "  all     - Build the lsport executable"
	@echo "  clean   - Remove compiled files"
	@echo "  help    - Display this help message"

