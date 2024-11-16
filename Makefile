# Compiler and flags
CXX = g++
CXXFLAGS = -Wall

# Libraries to link with
LIBS = -lpcap -lncurses

# Target executable name
TARGET = isa-top

# Source files
SRCS = isa-top.cpp

# Object files (derived from source files)
OBJS = $(SRCS:.cpp=.o)

# Default target
all: $(TARGET)

# Linking the target executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# Compiling source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean