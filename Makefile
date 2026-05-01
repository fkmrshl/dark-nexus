CXX      = g++
CXXFLAGS = -std=c++17 -O3 -march=native -flto=auto -pthread -Wall -Wextra
LDFLAGS  = -lssl -lcrypto -lcares -lcurl -luring

TARGET  = dark_nexus
SRC_DIR = src
INC_DIR = include

WORDLIST_URl = 
wordlist:
	@if [ ! -f ./best-dns-wordlist.txt ]; then \
		echo "Downloading DNS wordlist..."; \
		curl -sSL $(WORDLIST_URL) -o ./best-dns-wordlist.txt; \
		echo "Wordlist downloaded successfully."; \
	else \
		echo "Wordlist already exists."; \
	fi

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
       $(SRC_DIR)/dns_engine.cpp \
       $(SRC_DIR)/main.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET) wordlist

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -I$(INC_DIR) -c -o $@ $<

wordlist:
	@mkdir -p $(WORDLIST_DIR)
	@if [ ! -f $(WORDLIST_DIR)/subdomains.txt ]; then \
		echo "Downloading subdomain wordlist..."; \
		curl -sSL $(WORDLIST_URL) -o $(WORDLIST_DIR)/subdomains.txt; \
		echo "Wordlist downloaded to $(WORDLIST_DIR)/subdomains.txt"; \
	else \
		echo "Wordlist already exists in $(WORDLIST_DIR)/"; \
	fi

	rm -f $(SRC_DIR)/*.o $(TARGET)
	rm -rf $(WORDLIST_DIR)

.PHONY: all clean wordlist
