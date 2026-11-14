/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "calc-units.h"

 
typedef struct { const char *name; double factor; } Unit;
typedef struct { const char *name; const Unit *units; guint n; gboolean temperature; } Category;

static const Unit angle[] = {
    {"Градусы (десятичные)", 1}, {"Радианы", 180 / G_PI}, {"Грады", 0.9}, {"Обороты", 360},
    {"Угловые минуты", 1.0 / 60}, {"Угловые секунды", 1.0 / 3600},
};
static const Unit length[] = {
    {"Метры", 1}, {"Километры", 1000}, {"Сантиметры", 0.01}, {"Миллиметры", 0.001},
    {"Мили", 1609.344}, {"Ярды", 0.9144}, {"Футы", 0.3048}, {"Дюймы", 0.0254}, {"Морские мили", 1852},
};
static const Unit area[] = {
    {"Квадратные метры", 1}, {"Квадратные километры", 1e6}, {"Квадратные сантиметры", 1e-4},
    {"Гектары", 1e4}, {"Акры", 4046.8564224}, {"Квадратные футы", 0.09290304}, {"Квадратные дюймы", 0.00064516},
};
static const Unit volume[] = {
    {"Литры", 1}, {"Миллилитры", 0.001}, {"Кубические метры", 1000}, {"Галлоны (США)", 3.785411784},
    {"Кварты (США)", 0.946352946}, {"Пинты (США)", 0.473176473}, {"Кубические футы", 28.316846592},
};
static const Unit weight[] = {
    {"Килограммы", 1}, {"Граммы", 0.001}, {"Миллиграммы", 1e-6}, {"Тонны", 1000},
    {"Фунты", 0.45359237}, {"Унции", 0.028349523125},
};
static const Unit duration[] = {
    {"Секунды", 1}, {"Миллисекунды", 0.001}, {"Минуты", 60}, {"Часы", 3600}, {"Дни", 86400},
    {"Недели", 604800}, {"Годы", 31557600},
};
static const Unit speed[] = {
    {"Метры в секунду", 1}, {"Километры в час", 1 / 3.6}, {"Мили в час", 0.44704}, {"Узлы", 1852 / 3600.0},
};
static const Unit temp[] = { {"Градусы Цельсия", 1}, {"Градусы Фаренгейта", 1}, {"Кельвины", 1} };

#define CAT(n, a, t) { n, a, G_N_ELEMENTS(a), t }
static const Category cats[] = {
    CAT("Угол", angle, FALSE), CAT("Длина", length, FALSE), CAT("Площадь", area, FALSE),
    CAT("Объём", volume, FALSE), CAT("Вес", weight, FALSE), CAT("Время", duration, FALSE),
    CAT("Скорость", speed, FALSE), CAT("Температура", temp, TRUE),
};

guint calc_units_n_categories(void) { return G_N_ELEMENTS(cats); }
const char *calc_units_category_name(guint c) { return cats[c].name; }
guint calc_units_n(guint c) { return cats[c].n; }
const char *calc_units_name(guint c, guint u) { return cats[c].units[u].name; }

static double to_celsius(guint u, double v) { return u == 0 ? v : u == 1 ? (v - 32) * 5 / 9 : v - 273.15; }
static double from_celsius(guint u, double v) { return u == 0 ? v : u == 1 ? v * 9 / 5 + 32 : v + 273.15; }

double calc_units_convert(guint c, guint from, guint to, double value)
{
    if (cats[c].temperature) return from_celsius(to, to_celsius(from, value));
    return value * cats[c].units[from].factor / cats[c].units[to].factor;
}
