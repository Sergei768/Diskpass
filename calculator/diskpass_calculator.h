/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DISKPASS_CALCULATOR_H
#define DISKPASS_CALCULATOR_H
#include <glib.h>
#include <sodium.h>
/* Called after the calculator window is destroyed. FALSE means it was closed
 * without an unlock; TRUE means the correct code was entered. */
typedef void (*DiskpassCalculatorFinished)(gboolean unlocked, gpointer user_data);

/* Show the calculator without a nested GTK main loop, for use when the main
 * application window already exists. Callback runs on the GTK main thread. */
gboolean diskpass_calculator_show_async(const char *unlock_hash,
                                        const unsigned char salt[crypto_pwhash_SALTBYTES],
                                        unsigned char out_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES],
                                        DiskpassCalculatorFinished on_finished,
                                        gpointer user_data);

/* Runs the supplied GNOME-style calculator until the numeric access code is
 * entered and '=' is pressed (TRUE), or its window is closed (FALSE).
 * The caller must already have initialized GTK and libsodium. */
gboolean diskpass_calculator_run(const char *unlock_hash,
                                  const unsigned char salt[crypto_pwhash_SALTBYTES],
                                  unsigned char out_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]);
#endif
