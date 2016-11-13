CXX = g++
CC = $(CXX)
CXXFLAGS = -std=gnu++11 -Wall -Werror -O3
CFLAGS = $(CXXFLAGS)

all: sha.o main.o
	$(CXX) $(CXXFLAGS) sha.o main.o -o sha256

.PHONY: clean

clean:
	rm -f ./*.o ./sha256