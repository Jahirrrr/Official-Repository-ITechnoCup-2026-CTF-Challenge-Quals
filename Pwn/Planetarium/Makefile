CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -pipe -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now

.PHONY: all clean dist

all: planetarium

planetarium: src/planetarium.cc
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f planetarium
	rm -rf dist/*

dist: planetarium HANDOUT.md
	rm -rf dist
	mkdir -p dist
	cp planetarium dist/
	cp HANDOUT.md dist/README.md
	strip dist/planetarium
