/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef CALC_UNITS_H
#define CALC_UNITS_H
#include <glib.h>
G_BEGIN_DECLS
guint calc_units_n_categories(void);
const char *calc_units_category_name(guint cat);
guint calc_units_n(guint cat);
const char *calc_units_name(guint cat, guint unit);
 
double calc_units_convert(guint cat, guint from, guint to, double value);
G_END_DECLS
#endif
