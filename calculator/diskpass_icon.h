/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DISKPASS_CALCULATOR_ICON_H
#define DISKPASS_CALCULATOR_ICON_H

#include <gtk/gtk.h>

/* Uses GTK's currently selected icon theme and inherits its fallback chain. */
const char *diskpass_calculator_icon_name(void);

/* Updates Icon= and NoDisplay= in a per-user launcher, restoring both
 * when calculator mode is disabled. The executable and files remain visible
 * to OS inventory and filesystem searches. Never changes system files. */
gboolean diskpass_sync_launcher_icon(gboolean calculator_mode);

#endif
