CXX      = g++
CXXFLAGS = -std=c++17 -O3 -march=native -flto=auto -pthread -Wall -Wextra
LDFLAGS  = -lssl -lcrypto
 
TARGET  = dark_nexus
SRC_DIR = src
INC_DIR = include
 
SRCS = $(SRC_DIR)/globals.cpp \
       $(SRC_DIR)/proc.cpp \
       $(SRC_DIR)/utils.cpp \
       $(SRC_DIR)/ui.cpp \
       $(SRC_DIR)/port_scan.cpp \
       $(SRC_DIR)/os_detect.cpp \
       $(SRC_DIR)/ip_intel.cpp \
       $(SRC_DIR)/dns.cpp \
       $(SRC_DIR)/osint.cpp \
       $(SRC_DIR)/traceroute.cpp \
       $(SRC_DIR)/subdomain.cpp \
       $(SRC_DIR)/main.cpp
 
OBJS = $(SRCS:.cpp=.o)
 
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
 
$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -I$(INC_DIR) -c -o $@ $<
 
clean:
	rm -f $(SRC_DIR)/*.o $(TARGET)
 
.PHONY: clean
