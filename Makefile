CC ?= gcc
PKGS = gtk+-3.0 gio-2.0 gmodule-2.0 gpgme libsodium libcjson
CPPFLAGS += $(shell pkg-config --cflags $(PKGS))
LDLIBS += $(shell pkg-config --libs $(PKGS)) -lm
SRC = diskpass_main.c diskpass.h diskpass_i18n.c diskpass_core.c diskpass_crypto_tags.c diskpass_ui.c
RELEASE_CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
RELEASE_LDFLAGS = -Wl,-z,relro,-z,now,-z,noexecstack -pie
DEBUG_CFLAGS = -std=c11 -O1 -g3 -Wall -Wextra -Wpedantic -Wformat=2 -fno-omit-frame-pointer -fsanitize=address,undefined
DEBUG_LDFLAGS = -fsanitize=address,undefined

all: diskpass

diskpass: $(SRC)
	$(CC) $(CPPFLAGS) $(RELEASE_CFLAGS) diskpass_main.c -o $@ $(LDLIBS) $(RELEASE_LDFLAGS)

debug: $(SRC)
	$(CC) $(CPPFLAGS) $(DEBUG_CFLAGS) diskpass_main.c -o diskpass_debug $(LDLIBS) $(DEBUG_LDFLAGS)

clean:
	rm -f diskpass diskpass_debug

.PHONY: all debug clean
