CXX=c++
CXXFLAGS+=-std=c++11 -Wall
LDLIBS=-lpthread -lpcap
SRCS=broadcast-relay.cpp
OBJS=$(SRCS:%.cpp=%.o)
TARGET=broadcast-relay

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LDLIBS) 

$(OBJS): $(SRCS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -- $(OBJS)

dist-clean: clean
	rm -- $(TARGET)
