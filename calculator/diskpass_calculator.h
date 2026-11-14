/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DISKPASS_CALCULATOR_H
#define DISKPASS_CALCULATOR_H
#include <glib.h>
#include <sodium.h>
 

typedef void (*DiskpassCalculatorFinished)(gboolean unlocked, gpointer user_data);

 



gboolean diskpass_calculator_show_async(const char *unlock_hash,
                                        const unsigned char salt[crypto_pwhash_SALTBYTES],
                                        unsigned char out_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES],
                                        DiskpassCalculatorFinished on_finished,
                                        gpointer user_data);

 


gboolean diskpass_calculator_run(const char *unlock_hash,
                                  const unsigned char salt[crypto_pwhash_SALTBYTES],
                                  unsigned char out_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]);
#endif
