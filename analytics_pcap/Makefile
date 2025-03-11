CXX_TIMESTAMP_SRCS = stats/timestamp_helper.cpp main.cpp
CXX_MAKE_TIMESTAMP_OBJS = $(CXX_TIMESTAMP_SRCS:%.cpp=%.o)
CXX_USE_TIMESTAMP_OBJS = timestamp_helper.o main.o

CXX_CONVBYTE_SRCS = stats/conversation_stats_helper.cpp utils/utils.cpp main.cpp
CXX_MAKE_CONVBYTE_OBJS = $(CXX_CONVBYTE_SRCS:%.cpp=%.o)
CXX_USE_CONVBYTE_OBJS = conversation_stats_helper.o utils.o main.o

CXX_DNS_SRCS = dns_main.cpp utils/utils.cpp stats/dns_stats_helper.cpp
CXX_MAKE_DNS_OBJS = $(CXX_DNS_SRCS:%.cpp=%.o)
CXX_USE_DNS_OBJS = dns_main.o utils.o dns_stats_helper.o

CXX = g++
CXXFLAGS = -g -Wall -std=c++17

%.o : %.cpp
	$(CXX) $(CXXFLAGS) -c $

all : convbyte

timestamp: $(CXX_MAKE_TIMESTAMP_OBJS)
	$(CXX) -o $@ $(CXX_USE_TIMESTAMP_OBJS)

convbyte: $(CXX_MAKE_CONVBYTE_OBJS)
	$(CXX) -o $@ $(CXX_USE_CONVBYTE_OBJS) -lpcap

dns: $(CXX_MAKE_DNS_OBJS)
	$(CXX) -o $@ $(CXX_USE_DNS_OBJS) -lpcap

clean :
	rm -f *.o main timestamp convbyte dns depend.mak perf.*

depend :
	$(CXX) $(CXXFLAGS) -M $(CXX_SRCS) >> depend.mak

depend.mak :
	touch $@

include depend.mak