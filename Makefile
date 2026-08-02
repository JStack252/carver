CXX = g++
CXXFLAGS = -Wall -g
LDLIBS = -ltsk -lmagic

carver: main.cpp
	$(CXX) $(CXXFLAGS) -o carver main.cpp $(LDLIBS)

clean:
	rm -f carver