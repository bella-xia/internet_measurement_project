# C++ compiler
CXX = g++
CXXSTD = -g -std=c++17

# Linker
LD = ld

# Libraries to link with (include '-l')
LIBS = -lpcap -lpthread

# Compiler and linker flags (warning levels, optimisation level, 
# include debugging symbols, add include search path, add library search path)
CXXFLAGS = -I/usr/include
LDFLAGS = -L/usr/lib/x86_64-linux-gnu

# Source and object files
STREAM_SRC = main.cpp stream_analysis.cpp
STREAM_OBJ = $(STREAM_SRC:.cpp=.o)
STREAM_TARGET = stream

# Executable name
# Default target
all: $(STREAM_TARGET)

# Rule to build the target
$(STREAM_TARGET): $(STREAM_OBJ)
	$(CXX) $(CXXSTD) $(STREAM_OBJ) -o $(STREAM_TARGET) $(LDFLAGS) $(LIBS)

# Rule to build object file
%.o: %.cpp
	$(CXX) $(CXXSTD) $(CXXFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -f *.o $(STREAM_TARGET) depend.mak 

depend :
	$(CXX) $(CXXFLAGS) -M $(CXX_SRCS) >> depend.mak

depend.mak :
	touch $@

include depend.mak