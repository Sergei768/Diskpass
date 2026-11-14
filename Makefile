CC ?= gcc
PKGS = gtk+-3.0 gio-2.0 gmodule-2.0 gpgme libsodium libcjson libjpeg libwebp
GPGME_MIN_VERSION = 1.24.1
ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifneq ($(shell pkg-config --atleast-version=$(GPGME_MIN_VERSION) gpgme && echo ok),ok)
$(error gpgme >= $(GPGME_MIN_VERSION) is required (ML-KEM/Kyber); found $(shell pkg-config --modversion gpgme))
endif
endif
CPPFLAGS += $(shell pkg-config --cflags $(PKGS))
LDLIBS += $(shell pkg-config --libs $(PKGS)) -lm
CALC_SRC = calculator/diskpass_icon.c calculator/diskpass_calculator.c calculator/calculator-widget.c calculator/calc-eval.c calculator/calc-units.c
SRC = $(CALC_SRC) calculator/diskpass_icon.h diskpass_main.c diskpass.h diskpass_i18n.c diskpass_core.c diskpass_stego_lossy.c diskpass_crypto_tags.c diskpass_ui.c


RELEASE_CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wformat-security -Werror=format -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -fvisibility=hidden -fcf-protection=full -fstack-clash-protection
RELEASE_LDFLAGS = -Wl,-z,relro,-z,now,-z,noexecstack -pie
DEBUG_CFLAGS = -std=c11 -O1 -g3 -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -fno-omit-frame-pointer -fsanitize=address,undefined
DEBUG_LDFLAGS = -fsanitize=address,undefined

all: diskpass

diskpass: $(SRC)
	$(CC) $(CPPFLAGS) $(RELEASE_CFLAGS) diskpass_main.c $(CALC_SRC) -o $@ $(LDLIBS) $(RELEASE_LDFLAGS)

debug: $(SRC)
	$(CC) $(CPPFLAGS) $(DEBUG_CFLAGS) diskpass_main.c $(CALC_SRC) -o diskpass_debug $(LDLIBS) $(DEBUG_LDFLAGS)

clean:
	rm -f diskpass diskpass_debug

.PHONY: all debug clean
