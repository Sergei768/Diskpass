/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef CALCULATOR_WIDGET_H
#define CALCULATOR_WIDGET_H
#include <gtk/gtk.h>
G_BEGIN_DECLS
#define CALCULATOR_TYPE_WIDGET (calculator_widget_get_type())
G_DECLARE_FINAL_TYPE(CalculatorWidget, calculator_widget, CALCULATOR, WIDGET, GtkBox)
 




GtkWidget *calculator_widget_new(void);    
 
GtkWidget *calculator_widget_new_for_mode(const gchar *mode);
const gchar *calculator_widget_get_number_mode(CalculatorWidget *self);
 
gboolean calculator_widget_get_inverse(CalculatorWidget *self);
 
GtkWidget *calculator_widget_get_button(CalculatorWidget *self, const gchar *action, const gchar *target);
 
void calculator_widget_set_button_label(CalculatorWidget *self, const gchar *action, const gchar *label);
 
void calculator_widget_set_base(CalculatorWidget *self, gint base);
G_END_DECLS
#endif
