# LDLIBS=-lpcap
# INCLUDE=./include


# all: send-arp-test

# main.o: ./include/mac.h main.cpp

# arphdr.o: ./include/mac.h ./include/ip.h ./include/arphdr.h arphdr.cpp

# ethhdr.o: mac.h ethhdr.h ethhdr.cpp

# util.o: util.h util.cpp

# ip.o: ip.h ip.cpp

# mac.o : mac.h mac.cpp

# send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o util.o
# 	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

# clean:
# 	rm -f send-arp-test *.o

# Variables
CXX = g++
LDLIBS = -lpcap
INCLUDE_DIR = ./include
SRC_DIR = ./src
OBJ_DIR = ./obj
INCLUDES = -I$(INCLUDE_DIR)

# Source files
SRC_FILES = $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_FILES))

# Target executable
TARGET = send-arp-test

# Default target
all: $(TARGET)

# Linking
$(TARGET): $(OBJ_FILES)
	$(CXX) $(OBJ_FILES) $(LDLIBS) -o $@

# Compile each source file into an object file
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp $(INCLUDE_DIR)/%.h
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(INCLUDES) -c $< -o $@

# Clean
clean:
	rm -rf $(OBJ_DIR) $(TARGET)
