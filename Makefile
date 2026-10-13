CXX      = c++
CXXFLAGS = -std=c++20 -I./include/botan-3 -Wall
LDFLAGS  = -L./lib -lbotan-3 -Wl,-rpath,$(PWD)/lib

# Auto-discover every lesson: any NN_*.cpp file becomes a target
LESSONS := $(patsubst %.cpp,%,$(wildcard [0-9][0-9]*.cpp))

.PHONY: all setup clean

all: $(LESSONS)

%: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

debug-%: %.cpp
	$(CXX) $(CXXFLAGS) -g -O0 $< -o $* $(LDFLAGS)

# build Botan from submodule and install into this directory
setup:
	cd botan-src && \
	./configure.py --prefix=$(PWD) --debug-mode && \
	make -j$(shell sysctl -n hw.logicalcpu) && \
	make install && \
	cd .. && \
	codesign --force --sign - lib/libbotan-3.dylib

clean:
	rm -f $(LESSONS) rng_test
