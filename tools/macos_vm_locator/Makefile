CXX ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra

macos_vm_locator: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f macos_vm_locator

.PHONY: clean
