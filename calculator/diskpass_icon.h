/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DISKPASS_CALCULATOR_ICON_H
#define DISKPASS_CALCULATOR_ICON_H

#include <gtk/gtk.h>

 
const char *diskpass_calculator_icon_name(void);

 
void diskpass_set_default_icon(gboolean calculator_mode);
void diskpass_set_window_icon(GtkWindow *window, gboolean calculator_mode);
 
void diskpass_bind_window_launcher(GtkWindow *window);

 


gboolean diskpass_sync_launcher_icon(gboolean calculator_mode);

#endif
