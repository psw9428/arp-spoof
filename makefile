CXX = g++
LDLIBS = -lpcap
INCLUDE_DIR = ./include
SRC_DIR = ./src
OBJ_DIR = ./obj
INCLUDES = -I$(INCLUDE_DIR)

SRC_FILES = $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_FILES))

TARGET = arp-spoof

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(CXX) $(OBJ_FILES) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp $(INCLUDE_DIR)/%.h
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

re:
	make clean
	make all
