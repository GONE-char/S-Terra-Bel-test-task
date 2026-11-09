CXX = g++
CC  = gcc

CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Werror
CFLAGS   = -std=c99   -O2 -Wall -Wextra -Werror

COMMON_SRC = src/protocol.cpp src/sha256.cpp src/hmac.cpp src/common.cpp
HEADERS    = src/protocol.h src/sha256.h src/hmac.h src/common.h src/secure_zero.h

.PHONY: all test clean

all: server client

# secure_zero — чистый C, собирается именно C-компилятором.
secure_zero.o: src/secure_zero.c src/secure_zero.h
	$(CC) $(CFLAGS) -c src/secure_zero.c -o $@

server: src/server.cpp $(COMMON_SRC) $(HEADERS) secure_zero.o
	$(CXX) $(CXXFLAGS) -Isrc src/server.cpp $(COMMON_SRC) secure_zero.o -o $@

client: src/client.cpp $(COMMON_SRC) $(HEADERS) secure_zero.o
	$(CXX) $(CXXFLAGS) -Isrc src/client.cpp $(COMMON_SRC) secure_zero.o -o $@

unit_tests: tests/tests.cpp $(COMMON_SRC) $(HEADERS) secure_zero.o
	$(CXX) $(CXXFLAGS) -Isrc tests/tests.cpp $(COMMON_SRC) secure_zero.o -o $@

test: unit_tests
	./unit_tests

clean:
	rm -f server client unit_tests secure_zero.o
