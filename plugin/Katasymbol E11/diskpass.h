#ifndef DISKPASS_H
#define DISKPASS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <glib.h>
#include <gmodule.h>

#ifdef DISKPASS_HOST_BUILD
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <locale.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <glib/gstdio.h>
#include <glib-unix.h>
#include <gio/gio.h>
#include <gtk/gtk.h>
#include <gpgme.h>
#include <sodium.h>
#include <cjson/cJSON.h>
#endif

#define DISKPASS_PLUGIN_ABI_VERSION 1u
#define DISKPASS_PLUGIN_INIT_SYMBOL "diskpass_plugin_init"
#define DISKPASS_PLUGIN_SHUTDOWN_SYMBOL "diskpass_plugin_shutdown"

typedef void (*DiskPassPluginActionCallback)(gpointer user_data);

typedef struct {
    guint abi_version;           
    const char *id;              
    const char *name;            
    const char *version;         
} DiskPassPluginInfo;

typedef struct {
    guint abi_version;
    const char *app_version;
    const char *(*get_language)(void); 

    gboolean (*register_action)(
        const char *action_id,
        const char *label,
        DiskPassPluginActionCallback callback,
        gpointer user_data,
        GDestroyNotify destroy_notify);

    void (*show_message)(const char *title, const char *message);

    char *(*dup_selected_disk_label)(void);

    void (*set_status)(const char *text, guint timeout_ms);

    const char *(*translate)(const char *key);
} DiskPassPluginHost;

typedef gboolean (*DiskPassPluginInitFunc)(
    const DiskPassPluginHost *host,
    DiskPassPluginInfo *info,
    GError **error);
typedef void (*DiskPassPluginShutdownFunc)(void);

#ifdef DISKPASS_HOST_BUILD

GtkWidget *diskpass_plugins_create_button(void);
void diskpass_plugins_set_parent(GtkWindow *window);
void diskpass_plugins_init(void);
void diskpass_plugins_load_all(void);
void diskpass_plugins_shutdown(void);

char *diskpass_ui_dup_selected_disk_label(void);
void diskpass_ui_set_plugin_status(const char *text, guint timeout_ms);
#endif

#endif 
