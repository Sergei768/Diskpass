/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef CALCULATOR_WIDGET_H
#define CALCULATOR_WIDGET_H
#include <gtk/gtk.h>
G_BEGIN_DECLS
#define CALCULATOR_TYPE_WIDGET (calculator_widget_get_type())
G_DECLARE_FINAL_TYPE(CalculatorWidget, calculator_widget, CALCULATOR, WIDGET, GtkBox)
/* Floating reference, like other GTK widgets. GTK main thread only.
 * Signal: action (const gchar *name, const gchar *target).
 * Strings are borrowed for the duration of the callback; copy if retained.
 * No evaluation/backend is supplied. The host owns expression and results.
 */
GtkWidget *calculator_widget_new(void);   /* базовая панель */
/* mode: "basic", "advanced", "financial", "programming" или "conversion" */
GtkWidget *calculator_widget_new_for_mode(const gchar *mode);
const gchar *calculator_widget_get_number_mode(CalculatorWidget *self);
/* Состояние переключателя ⇧⁻¹ (обратные функции). */
gboolean calculator_widget_get_inverse(CalculatorWidget *self);
/* Кнопка по имени действия (и цели, если target != NULL); NULL, если нет. */
GtkWidget *calculator_widget_get_button(CalculatorWidget *self, const gchar *action, const gchar *target);
/* Сменить подпись кнопки (Deg/Rad/Grad, «Десятичный», «64-бита»). */
void calculator_widget_set_button_label(CalculatorWidget *self, const gchar *action, const gchar *label);
/* Блокирует цифры, недопустимые в системе счисления base (2…16). */
void calculator_widget_set_base(CalculatorWidget *self, gint base);
G_END_DECLS
#endif
