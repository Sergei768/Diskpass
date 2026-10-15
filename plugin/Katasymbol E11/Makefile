CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
PKGS := gtk+-3.0 gio-2.0 gmodule-2.0 pangocairo liblzma
PKG_CFLAGS := $(shell pkg-config --cflags $(PKGS))
PKG_LIBS := $(shell pkg-config --libs $(PKGS))
TARGET := e11_printer.so

all: $(TARGET)

$(TARGET): e11_plugin.c diskpass.h
	$(CC) -std=c11 $(CFLAGS) $(PKG_CFLAGS) -shared e11_plugin.c -o $@ $(PKG_LIBS) -Wl,-z,relro,-z,now

install: $(TARGET)
	install -d -m 700 "$(HOME)/.diskpass/plugins"
	install -m 755 $(TARGET) "$(HOME)/.diskpass/plugins/$(TARGET)"

uninstall:
	rm -f "$(HOME)/.diskpass/plugins/$(TARGET)"

clean:
	rm -f $(TARGET)

.PHONY: all install uninstall clean
