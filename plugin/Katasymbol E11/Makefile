CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wformat-security -Werror=format -Werror=implicit-function-declaration -Werror=incompatible-pointer-types
HARDENING_FLAGS = -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fvisibility=hidden -fcf-protection=full -fstack-clash-protection
PKGS := gtk+-3.0 gio-2.0 gmodule-2.0 pangocairo liblzma libsodium
PKG_CFLAGS := $(shell pkg-config --cflags $(PKGS))
PKG_LIBS := $(shell pkg-config --libs $(PKGS))
TARGET := e11_printer.so

all: $(TARGET)

$(TARGET): e11_plugin.c diskpass.h
	$(CC) -std=c11 $(CFLAGS) $(HARDENING_FLAGS) $(PKG_CFLAGS) -shared e11_plugin.c -o $@ $(PKG_LIBS) -Wl,-z,relro,-z,now,-z,noexecstack

install: $(TARGET)
	python3 install_plugin.py $(TARGET)

uninstall:
	python3 install_plugin.py $(TARGET) --remove

clean:
	rm -f $(TARGET)

.PHONY: all install uninstall clean
