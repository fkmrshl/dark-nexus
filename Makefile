CXX      = g++

CXXFLAGS = -std=c++17 -O3 -march=native -flto=auto -pthread \
           -pipe -fno-plt -Wall -Wextra

LDFLAGS  = -Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now \
           -lssl -lcrypto -lcares -lcurl -luring

TARGET  = dark_nexus
SRC_DIR = src
INC_DIR = include

WORDLIST_URL = https://raw.githubusercontent.com/fkmrshl/dark-nexus/refs/heads/main/best-dns-wordlist.txt 

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
	@if [ ! -f ./best-dns-wordlist.txt ]; then \
		echo "Downloading DNS wordlist..."; \
		curl -sSL $(WORDLIST_URL) -o ./best-dns-wordlist.txt; \
		echo "Wordlist downloaded successfully."; \
	else \
		echo "Wordlist already exists."; \
	fi

clean:
	rm -f $(SRC_DIR)/*.o $(TARGET)

.PHONY: clean all wordlist
