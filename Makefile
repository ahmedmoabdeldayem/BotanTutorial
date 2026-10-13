CXX      = c++
CXXFLAGS = -std=c++20 -I./include/botan-3 -Wall
LDFLAGS  = -L./lib -lbotan-3 -Wl,-rpath,$(PWD)/lib

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
	rm -f 01_hashing 02_aes_gcm 02b_aes_cbc 03_asymmetric_keys \
	      04_rsa_encrypt 04b_ecdh 05_signatures 06_certificates \
	      06b_cert_chain 07_tls 08_password_hashing rng_test
