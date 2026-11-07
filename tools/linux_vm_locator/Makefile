CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -fno-omit-frame-pointer -g
# -rdynamic 让 qq_magic_napi_register 桩在全局作用域可见，wrapper.node 才能解析它。
LDFLAGS ?= -rdynamic

linux_vm_locator: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f linux_vm_locator

.PHONY: clean
