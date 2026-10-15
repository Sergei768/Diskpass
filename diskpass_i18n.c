#include "diskpass.h"
typedef struct { const char *key; const char *ru; const char *en; const char *uk; const char *be; const char *kk; } i18n_entry_t;
typedef struct { char *code; char *name; char *fallback; GHashTable *strings; } user_language_t;
static const i18n_entry_t I18N[] = {
    {"app_desc","Безопасное хранилище паролей для дисков","Secure password storage for disks","Безпечне сховище паролів для дисків","Бяспечнае сховішча пароляў для дыскаў","Дискілерге арналған қауіпсіз құпиясөз қоймасы"},
    {"open_db","Открыть базу","Open Database","Відкрити базу","Адкрыць базу","Дерекқорды ашу"},
    {"create_db","Создать новую базу","Create New Database","Створити нову базу","Стварыць новую базу","Жаңа дерекқор жасау"},
    {"setup_title","Настройка шифрования","Encryption Setup","Налаштування шифрування","Наладжванне шыфравання","Шифрлауды баптау"},
    {"db_file","Файл базы:","Database File:","Файл бази:","Файл базы:","Дерекқор файлы:"},
    {"not_selected","не выбран","not selected","не вибрано","не выбраны","таңдалмаған"},
    {"pgp_key","Ключ OpenPGP:","OpenPGP Key:","Ключ OpenPGP:","Ключ OpenPGP:","OpenPGP кілті:"},
    {"language","Язык:","Language:","Мова:","Мова:","Тіл:"},
    {"back","Назад","Back","Назад","Назад","Артқа"},
    {"create_btn","Создать базу","Create Database","Створити базу","Стварыць базу","Дерекқор жасау"},
    {"no_keys","Подходящие OpenPGP ключи не найдены.","No suitable OpenPGP keys found.","Відповідні ключі OpenPGP не знайдено.","Прыдатныя ключы OpenPGP не знойдзены.","Сәйкес OpenPGP кілттері табылмады."},
    {"gpg_err","Ошибка GPG: ","GPG Error: ","Помилка GPG: ","Памылка GPG: ","GPG қатесі: "},
    {"locked_title","База заблокирована","Database Locked","Базу заблоковано","База заблакіравана","Дерекқор құлыпталған"},
    {"file","Файл:","File:","Файл:","Файл:","Файл:"},
    {"unlock_btn","Разблокировать","Unlock","Розблокувати","Разблакіраваць","Құлыпты ашу"},
    {"lock_db","Заблокировать базу","Lock Database","Заблокувати базу","Заблакіраваць базу","Дерекқорды құлыптау"},
    {"add_entry","Добавить запись","Add Entry","Додати запис","Дадаць запіс","Жазба қосу"},
    {"edit_entry","Изменить запись","Edit Entry","Змінити запис","Змяніць запіс","Жазбаны өзгерту"},
    {"del_entry","Удалить запись","Delete Entry","Видалити запис","Выдаліць запіс","Жазбаны жою"},
    {"show_schema","Показать схему меток","Show Label Schema","Показати схему міток","Паказаць схему метак","Белгі схемасын көрсету"},
    {"search","Поиск...","Search...","Пошук...","Пошук...","Іздеу..."},
    {"select_entry","Выберите запись","Select an entry","Виберіть запис","Выберыце запіс","Жазбаны таңдаңыз"},
    {"copy_label","Копировать метку","Copy Label","Копіювати мітку","Капіяваць метку","Белгіні көшіру"},
    {"copy_pass","Копировать пароль","Copy Password","Копіювати пароль","Капіяваць пароль","Құпиясөзді көшіру"},
    {"full_tag","Полный тег","Full Tag","Повний тег","Поўны тэг","Толық тег"},
    {"password","Пароль","Password","Пароль","Пароль","Құпиясөз"},
    {"notes","Заметки","Notes","Нотатки","Нататкі","Ескертпелер"},
    {"delete_msg","Удалить?","Delete?","Видалити?","Выдаліць?","Жою керек пе?"},
    {"schema_title","Схема меток","Label Schema","Схема міток","Схема метак","Белгі схемасы"},
    {"block","Блок","Block","Блок","Блок","Блок"},
    {"val","Значение","Value","Значення","Значэнне","Мән"},
    {"chk","Соль","Salt","Сіль","Соль","Тұз"},
    {"schema_footer","Последний символ блока — соль-символ.","The last character of the block is a salt character.","Останній символ блоку — символ солі.","Апошні сімвал блока — сімвал солі.","Блоктың соңғы таңбасы — тұз таңбасы."},
    {"size_hint_title","Расшифровка кодов объёма","Size Code Reference","Розшифрування кодів обсягу","Расшыфроўка кодаў аб’ёму","Көлем кодтарының түсіндірмесі"},
    {"cancel","Отмена","Cancel","Скасувати","Скасаваць","Бас тарту"},
    {"create","Создать","Create","Створити","Стварыць","Жасау"},
    {"save","Сохранить","Save","Зберегти","Захаваць","Сақтау"},
    {"media_type","Тип носителя","Media Type","Тип носія","Тып носьбіта","Тасымалдағыш түрі"},
    {"size","Объём","Size","Обсяг","Аб’ём","Көлем"},
    {"cipher","Шифр","Cipher","Шифр","Шыфр","Шифр"},
    {"tag_min","Тег (мин. 2 симв.)","Tag (min. 2 chars)","Тег (мін. 2 симв.)","Тэг (мін. 2 сімв.)","Тег (кемінде 2 таңба)"},
    {"salt","Соль","Salt","Сіль","Соль","Тұз"},
    {"generate","Сгенерировать","Generate","Згенерувати","Згенераваць","Жасау"},
    {"label","Метка","Label","Мітка","Метка","Белгі"},
    {"block_err","Ошибка в блоке","Error in block","Помилка в блоці","Памылка ў блоку","Блоктағы қате"},
    {"block_len_err","Неверная длина блока","Invalid block length","Неправильна довжина блоку","Няправільная даўжыня блока","Блок ұзындығы дұрыс емес"},
    {"label_err","Метка: должно быть 5 блоков","Label: must be 5 blocks","Мітка: має бути 5 блоків","Метка: павінна быць 5 блокаў","Белгі: 5 блок болуы керек"},
    {"invalid_label","Неверная метка","Invalid label","Неправильна мітка","Няправільная метка","Белгі дұрыс емес"},
    {"type","Тип","Type","Тип","Тып","Түр"},
    {"content_tag","Содержимое","Content","Вміст","Змесціва","Мазмұн"},
    {"dsalt","Соль","Salt","Сіль","Соль","Тұз"},
    {"close","Закрыть","Close","Закрити","Закрыць","Жабу"},
    {"key_mismatch","Выбранный ключ не подходит для этой базы.","The selected key does not match this database.","Вибраний ключ не підходить для цієї бази.","Выбраны ключ не падыходзіць для гэтай базы.","Таңдалған кілт бұл дерекқорға сәйкес келмейді."},
    {"alias","Название (для себя)","Name (for yourself)","Назва (для себе)","Назва (для сябе)","Атауы (өзіңіз үшін)"},
    {"alias_placeholder","необязательно","optional","необов’язково","неабавязкова","міндетті емес"},
    {"file_corrupted","Файл повреждён","File corrupted","Файл пошкоджено","Файл пашкоджаны","Файл бүлінген"},
    {"no_recipient","Не выбран GPG сертификат","No GPG certificate selected","Не вибрано сертифікат GPG","Не выбраны сертыфікат GPG","GPG сертификаты таңдалмаған"},
    {"snapshot_btn","Слепок папки диска","Folder snapshot","Знімок папки диска","Здымак папкі дыска","Диск қалтасының суреті"},
    {"snapshot_title","Выберите корень диска (точку монтирования)","Choose disk root (mount point)","Виберіть корінь диска (точку монтування)","Выберыце корань дыска (пункт мантавання)","Диск түбірін (монтаж нүктесін) таңдаңыз"},
    {"scan","Сканировать","Scan","Сканувати","Сканаваць","Сканерлеу"},
    {"scanning","Сканирование...","Scanning...","Сканування...","Сканаванне...","Сканерленуде..."},
    {"indexed_files","Проиндексировано файлов","Indexed files","Проіндексовано файлів","Праіндэксавана файлаў","Индекстелген файлдар"},
    {"find_btn","Глобальный поиск файлов","Global file search","Глобальний пошук файлів","Глабальны пошук файлаў","Файлдарды жалпы іздеу"},
    {"find_title","Поиск по всем дискам","Search across all disks","Пошук на всіх дисках","Пошук па ўсіх дысках","Барлық дискілерден іздеу"},
    {"find_hint","Имя файла или фрагмент пути...","File name or path fragment...","Ім’я файлу або фрагмент шляху...","Імя файла або фрагмент шляху...","Файл атауы немесе жол бөлігі..."},
    {"matches","совпадений","matches","збігів","супадзенняў","сәйкестік"},
    {"files_on_disk","Файлы на диске","Files on disk","Файли на диску","Файлы на дыску","Дискідегі файлдар"},
    {"no_results","Ничего не найдено","No results","Нічого не знайдено","Нічога не знойдзена","Ештеңе табылмады"},
    {"files_found","файлов","files","файлів","файлаў","файл"},
    {"disks_found","дисков","disks","дисків","дыскаў","диск"},
    {"copy_path","Копировать путь","Copy path","Копіювати шлях","Капіяваць шлях","Жолды көшіру"},
    {"copy_name","Копировать имя","Copy name","Копіювати ім’я","Капіяваць імя","Атауды көшіру"},
    {"empty_index","Нет дисков с индексом. Сделайте слепок диска.","No disks with file index. Create a disk snapshot.","Немає дисків з індексом. Створіть знімок диска.","Няма дыскаў з індэксам. Стварыце здымак дыска.","Индексі бар дискілер жоқ. Диск суретін жасаңыз."},
    {"disks_with_index","дисков с индексом","disks with index","дисків з індексом","дыскаў з індэксам","индексі бар диск"},
    {"no_index_yet","Индекс не создан","No index yet","Індекс не створено","Індэкс не створаны","Индекс жасалмаған"},
    {"filter_add","Добавить фильтр","Add filter","Додати фільтр","Дадаць фільтр","Сүзгі қосу"},
    {"filter_name","Имя фильтра:","Filter name:","Назва фільтра:","Назва фільтра:","Сүзгі атауы:"},
    {"filter_exts","Расширения (через запятую):","Extensions (comma-separated):","Розширення (через кому):","Пашырэнні (праз коску):","Кеңейтімдер (үтірмен):"},
    {"filter_delete","Удалить фильтр","Delete filter","Видалити фільтр","Выдаліць фільтр","Сүзгіні жою"},
    {"smart_model","Модель","Model","Модель","Мадэль","Модель"},
    {"smart_serial","Серийный номер","Serial","Серійний номер","Серыйны нумар","Сериялық нөмір"},
    {"smart_capacity","Объём","Capacity","Обсяг","Аб’ём","Көлем"},
    {"smart_temp","Температура","Temperature","Температура","Тэмпература","Температура"},
    {"smart_hours","Наработка","Power-on hours","Напрацювання","Напрацоўка","Жұмыс уақыты"},
    {"smart_realloc","Переназнач. секторов","Reallocated sectors","Перепризначені сектори","Пераразмеркаваныя сектары","Қайта бөлінген секторлар"},
    {"smart_wear","Износ","Wear level","Зношення","Знос","Тозу"},
    {"smart_crc","Ошибки CRC","CRC errors","Помилки CRC","Памылкі CRC","CRC қателері"},
    {"smart_unavailable","SMART недоступен для этого устройства","SMART not available for this device","SMART недоступний для цього пристрою","SMART недаступны для гэтай прылады","Бұл құрылғы үшін SMART қолжетімсіз"},
    {"save_error","Ошибка сохранения","Save error","Помилка збереження","Памылка захавання","Сақтау қатесі"},
    {"signed_ok","Подпись БД верна","Database signature verified","Підпис БД правильний","Подпіс базы правераны","Дерекқор қолтаңбасы тексерілді"},
    {"unsigned_warn","БД без подписи — открытие запрещено","Unsigned database — opening is blocked","БД без підпису — відкриття заборонено","База без подпісу — адкрыццё забаронена","Қолтаңбасыз дерекқор — ашуға тыйым салынған"},
    {"unsigned_err","База не имеет обязательной цифровой подписи.","Database is missing the required digital signature.","База не має обов’язкового цифрового підпису.","У базы няма абавязковага лічбавага подпісу.","Дерекқорда міндетті цифрлық қолтаңба жоқ."},
    {"sig_mismatch","Подпись БД сделана чужим ключом","Database signature was made by a foreign key","Підпис БД зроблено іншим ключем","Подпіс базы зроблены іншым ключом","Дерекқорға басқа кілтпен қол қойылған"},
    {"add_auto","Выбрать подключённый диск","Select connected disk","Вибрати підключений диск","Выбраць падключаны дыск","Қосылған дискіні таңдау"},
    {"add_manual","Создать вручную","Create manually","Створити вручну","Стварыць уручную","Қолмен жасау"},
    {"uuid","UUID","UUID","UUID","UUID","UUID"},
    {"connected_yes","Подключён","Connected","Підключено","Падключаны","Қосылған"},
    {"connected_no","Не подключён","Disconnected","Не підключено","Не падключаны","Қосылмаған"},
    {"disk_detected","Диск подключён","Disk connected","Диск підключено","Дыск падключаны","Диск қосылды"},
    {"last_snapshot","Последний слепок","Last snapshot","Останній знімок","Апошні здымак","Соңғы сурет"},
    {"today","сегодня","today","сьогодні","сёння","бүгін"},
    {"yesterday","вчера","yesterday","вчора","учора","кеше"},
    {"days_ago","дн. назад","days ago","дн. тому","дзён таму","күн бұрын"},
    {"batch_reindex","Обновить все подключённые","Refresh all connected","Оновити всі підключені","Абнавіць усе падключаныя","Барлық қосылғандарды жаңарту"},
    {"batch_title","Обновление слепков","Batch reindex","Оновлення знімків","Абнаўленне здымкаў","Суреттерді жаңарту"},
    {"batch_progress","%d из %d…","%d of %d...","%d з %d…","%d з %d…","%d / %d…"},
    {"batch_done","Обновлено: %d, пропущено: %d, ошибок: %d","Done: %d, skipped: %d, errors: %d","Оновлено: %d, пропущено: %d, помилок: %d","Абноўлена: %d, прапушчана: %d, памылак: %d","Жаңартылды: %d, өткізіліп жіберілді: %d, қате: %d"},
    {"also_on","Также на:","Also on:","Також на:","Таксама на:","Сондай-ақ:"},
    {"no_connected","Нет подключённых дисков с сохранённым UUID","No connected disks with saved UUID","Немає підключених дисків зі збереженим UUID","Няма падключаных дыскаў з захаваным UUID","Сақталған UUID бар қосылған дискілер жоқ"},
    {"refresh_connections","Обновить статус дисков","Refresh disk status","Оновити стан дисків","Абнавіць стан дыскаў","Диск күйін жаңарту"},
    {"smart_refresh","Обновить SMART выбранного диска","Refresh SMART for selected disk","Оновити SMART вибраного диска","Абнавіць SMART выбранага дыска","Таңдалған дискінің SMART деректерін жаңарту"},
    {"smart_firmware","Прошивка","Firmware","Прошивка","Прашыўка","Микробағдарлама"},
    {"smart_cycles","Циклы включения","Power cycles","Цикли ввімкнення","Цыклы ўключэння","Қосу циклдері"},
    {"smart_media_errors","Ошибки носителя","Media errors","Помилки носія","Памылкі носьбіта","Тасымалдағыш қателері"},
    {"smart_unsafe_shutdowns","Аварийные выключения","Unsafe shutdowns","Аварійні вимкнення","Аварыйныя выключэнні","Апаттық өшірулер"},
    {"smart_spare","Резерв NVMe","NVMe available spare","Резерв NVMe","Рэзерв NVMe","NVMe бос қоры"},
    {"smart_critical","Критические флаги","Critical warning flags","Критичні прапорці","Крытычныя сцягі","Критикалық жалаушалар"},
    {"change_key","Сменить ключ шифрования","Change encryption key","Змінити ключ шифрування","Змяніць ключ шыфравання","Шифрлау кілтін өзгерту"},
    {"change_key_title","Смена ключа OpenPGP","Change OpenPGP key","Зміна ключа OpenPGP","Змена ключа OpenPGP","OpenPGP кілтін өзгерту"},
    {"change_key_current","Текущий ключ:","Current key:","Поточний ключ:","Бягучы ключ:","Ағымдағы кілт:"},
    {"change_key_new","Новый ключ:","New key:","Новий ключ:","Новы ключ:","Жаңа кілт:"},
    {"change_key_done","Ключ базы успешно изменён","Database key changed successfully","Ключ бази успішно змінено","Ключ базы паспяхова зменены","Дерекқор кілті сәтті өзгертілді"},
    {"create_key","Создать ключ OpenPGP","Create OpenPGP key","Створити ключ OpenPGP","Стварыць ключ OpenPGP","OpenPGP кілтін жасау"},
    {"plugins","Плагины","Plugins","Плагіни","Плагіны","Плагиндер"},
    {"create_key_title","Создание ключа OpenPGP","Create OpenPGP key","Створення ключа OpenPGP","Стварэнне ключа OpenPGP","OpenPGP кілтін жасау"},
    {"key_name","Имя:","Name:","Ім’я:","Імя:","Аты:"},
    {"key_email","E-mail:","E-mail:","E-mail:","E-mail:","E-mail:"},
    {"key_type","Тип ключа:","Key type:","Тип ключа:","Тып ключа:","Кілт түрі:"},
    {"key_expiry","Срок действия:","Expiration:","Строк дії:","Тэрмін дзеяння:","Жарамдылық мерзімі:"},
    {"key_type_pqc","PQC / ML-KEM (рекомендуется)","PQC / ML-KEM (recommended)","PQC / ML-KEM (рекомендовано)","PQC / ML-KEM (рэкамендуецца)","PQC / ML-KEM (ұсынылады)"},
    {"key_type_classic","Обычный OpenPGP","Classic OpenPGP","Звичайний OpenPGP","Звычайны OpenPGP","Кәдімгі OpenPGP"},
    {"key_expiry_1y","1 год","1 year","1 рік","1 год","1 жыл"},
    {"key_expiry_2y","2 года","2 years","2 роки","2 гады","2 жыл"},
    {"key_expiry_5y","5 лет","5 years","5 років","5 гадоў","5 жыл"},
    {"key_expiry_never","Без срока","Never","Без строку","Без тэрміну","Мерзімсіз"},
    {"key_pinentry_note","Пароль нового ключа запросит системное окно GnuPG Pinentry.","The new key passphrase will be requested by the system GnuPG Pinentry dialog.","Пароль нового ключа запросить системне вікно GnuPG Pinentry.","Пароль новага ключа запытае сістэмнае акно GnuPG Pinentry.","Жаңа кілттің құпиясөзін жүйелік GnuPG Pinentry терезесі сұрайды."},
    {"key_created","Ключ успешно создан. Список ключей обновлён.","Key created successfully. The key list has been refreshed.","Ключ успішно створено. Список ключів оновлено.","Ключ паспяхова створаны. Спіс ключоў абноўлены.","Кілт сәтті жасалды. Кілттер тізімі жаңартылды."},
    {"key_create_failed","Не удалось создать ключ","Could not create key","Не вдалося створити ключ","Не ўдалося стварыць ключ","Кілт жасау мүмкін болмады"},
    {"key_name_required","Введите имя для ключа.","Enter a name for the key.","Введіть ім’я для ключа.","Увядзіце імя для ключа.","Кілт үшін атау енгізіңіз."},
    {"security_pqc","PQC / ML-KEM","PQC / ML-KEM","PQC / ML-KEM","PQC / ML-KEM","PQC / ML-KEM"},
    {"security_classic","OpenPGP · без PQC","OpenPGP · no PQC","OpenPGP · без PQC","OpenPGP · без PQC","OpenPGP · PQC жоқ"},
    {"security_locked","Заблокировано","Locked","Заблоковано","Заблакіравана","Құлыпталған"},
    {"smart_refresh_done","SMART обновлён","SMART data refreshed","SMART оновлено","SMART абноўлены","SMART жаңартылды"},
    {"no_quantum_mark","[без квантовой защиты]","[no quantum protection]","[без квантового захисту]","[без квантавай абароны]","[кванттық қорғаныссыз]"},
    {"rekey_pqc_done","Ключ изменён. База защищена PQC / ML-KEM.","Key changed. Database is protected with PQC / ML-KEM.","Ключ змінено. Базу захищено PQC / ML-KEM.","Ключ зменены. База абаронена PQC / ML-KEM.","Кілт өзгертілді. Дерекқор PQC / ML-KEM арқылы қорғалған."},
    {"rekey_classic_done","Ключ изменён. У нового ключа нет квантовой защиты.","Key changed. This key has no quantum protection.","Ключ змінено. Новий ключ не має квантового захисту.","Ключ зменены. У новага ключа няма квантавай абароны.","Кілт өзгертілді. Жаңа кілтте кванттық қорғаныс жоқ."},
    {"legacy_upgrade_msg","Старая база открыта. При следующем сохранении она будет переведена на PQC / ML-KEM.","Legacy database opened. The next save will upgrade it to PQC / ML-KEM.","Стару базу відкрито. Під час наступного збереження її буде переведено на PQC / ML-KEM.","Старая база адкрыта. Пры наступным захаванні яна будзе пераведзена на PQC / ML-KEM.","Ескі дерекқор ашылды. Келесі сақтауда ол PQC / ML-KEM-ге ауыстырылады."},
    {"legacy_classic_msg","Старая база открыта с полным доступом. Сохранение работает через обычный OpenPGP, но без PQC / ML-KEM.","Legacy database opened with full access. Saves remain protected by classical OpenPGP, but without PQC / ML-KEM.","Стару базу відкрито з повним доступом. Збереження захищене звичайним OpenPGP, але без PQC / ML-KEM.","Старая база адкрыта з поўным доступам. Захаванне працуе праз звычайны OpenPGP, але без PQC / ML-KEM.","Ескі дерекқор толық қолжетімділікпен ашылды. Сақтау кәдімгі OpenPGP арқылы орындалады, бірақ PQC / ML-KEM жоқ."},
    {"no_connected_disks","— нет подключённых дисков —","— no connected disks —","— немає підключених дисків —","— няма падключаных дыскаў —","— қосылған дискілер жоқ —"},
    {"minimize","Свернуть","Minimize","Згорнути","Згарнуць","Жинау"},
    {"maximize","Развернуть","Maximize","Розгорнути","Разгарнуць","Жаю"},
    {"close_window","Закрыть","Close","Закрити","Закрыць","Жабу"},
    {"gpg_engine_missing","Движок GnuPG OpenPGP не найден","GnuPG OpenPGP engine not found","Рушій GnuPG OpenPGP не знайдено","Рухавік GnuPG OpenPGP не знойдзены","GnuPG OpenPGP қозғалтқышы табылмады"},
    {"selected_key_invalid","Выбранный ключ должен иметь действующий ключ шифрования и закрытый ключ подписи","Selected key must have a valid encryption key and a private signing key","Вибраний ключ повинен мати чинний ключ шифрування та закритий ключ підпису","Выбраны ключ павінен мець сапраўдны ключ шыфравання і закрыты ключ подпісу","Таңдалған кілтте жарамды шифрлау кілті және жеке қол қою кілті болуы керек"},
    {"smart_no_device","Для записи не найден подключённый диск с сохранённым UUID","No connected disk with a saved UUID was found for this entry","Для запису не знайдено підключений диск зі збереженим UUID","Для запісу не знойдзены падключаны дыск з захаваным UUID","Бұл жазба үшін сақталған UUID бар қосылған диск табылмады"},
    {"plugins_open_folder","Открыть папку плагинов","Open plugins folder","Відкрити папку плагінів","Адкрыць папку плагінаў","Плагиндер қалтасын ашу"},
    {"plugins_none_active","Нет активных плагинов","No active plugins","Немає активних плагінів","Няма актыўных плагінаў","Белсенді плагиндер жоқ"},
    {"e11_action_print","Печать на Katasymbol E11","Print on Katasymbol E11","Друк на Katasymbol E11","Друк на Katasymbol E11","Katasymbol E11 арқылы басып шығару"},
    {"e11_action_disk_label","Печать метки выбранного диска","Print selected disk label","Друк мітки вибраного диска","Друк меткі выбранага дыска","Таңдалған диск белгісін басып шығару"},
    {"e11_error_title","Ошибка E11","E11 error","Помилка E11","Памылка E11","E11 қатесі"},
    {"e11_print_running","Печать уже выполняется.","A print job is already running.","Друк уже виконується.","Друк ужо выконваецца.","Басып шығару орындалып жатыр."},
    {"e11_job_started","E11: задание запущено…","E11: print job started…","E11: завдання друку запущено…","E11: заданне друку запушчана…","E11: басып шығару тапсырмасы басталды…"},
    {"e11_preparing","E11: подготовка метки…","E11: preparing label…","E11: підготовка мітки…","E11: падрыхтоўка меткі…","E11: белгі дайындалуда…"},
    {"e11_connecting_to","подключение к","connecting to","підключення до","падключэнне да","қосылу"},
    {"e11_searching","E11: поиск принтера…","E11: searching for printer…","E11: пошук принтера…","E11: пошук прынтара…","E11: принтер ізделуде…"},
    {"e11_printing","E11: печать…","E11: printing…","E11: друк…","E11: друк…","E11: басып шығарылуда…"},
    {"e11_done_addr","E11: печать завершена · %s","E11: printing completed · %s","E11: друк завершено · %s","E11: друк завершаны · %s","E11: басып шығару аяқталды · %s"},
    {"e11_done","E11: печать завершена","E11: printing completed","E11: друк завершено","E11: друк завершаны","E11: басып шығару аяқталды"},
    {"e11_select_disk","Сначала выберите диск/запись в DiskPass.","Select a disk/entry in DiskPass first.","Спочатку виберіть диск/запис у DiskPass.","Спачатку выберыце дыск/запіс у DiskPass.","Алдымен DiskPass ішінде диск/жазбаны таңдаңыз."},
    {"e11_title","Печать Katasymbol E11","Print with Katasymbol E11","Друк Katasymbol E11","Друк Katasymbol E11","Katasymbol E11 арқылы басып шығару"},
    {"e11_print","Печать","Print","Друкувати","Друкаваць","Басып шығару"},
    {"e11_hint","Нативный C-драйвер E11 через BlueZ. MAC может определяться автоматически и сохраняется после успешного обнаружения.","Native C E11 driver using BlueZ. The MAC can be detected automatically and is saved after successful discovery.","Нативний C-драйвер E11 через BlueZ. MAC може визначатися автоматично та зберігається після успішного виявлення.","Натыўны C-драйвер E11 праз BlueZ. MAC можа вызначацца аўтаматычна і захоўваецца пасля паспяховага выяўлення.","BlueZ арқылы жұмыс істейтін E11-дің жергілікті C драйвері. MAC автоматты түрде анықталып, сәтті табылғаннан кейін сақталады."},
    {"e11_mac","MAC-адрес","MAC address","MAC-адреса","MAC-адрас","MAC мекенжайы"},
    {"e11_auto_detect","Автоматически найти E11, если MAC не задан или устройство недоступно","Automatically find E11 if the MAC is empty or the saved device is unavailable","Автоматично знайти E11, якщо MAC не задано або збережений пристрій недоступний","Аўтаматычна знайсці E11, калі MAC не зададзены або захаваная прылада недаступная","MAC көрсетілмесе немесе сақталған құрылғы қолжетімсіз болса, E11-ді автоматты түрде табу"},
    {"e11_font_size","Размер шрифта","Font size","Розмір шрифту","Памер шрыфту","Қаріп өлшемі"},
    {"e11_tape_width","Ширина ленты, мм","Tape width, mm","Ширина стрічки, мм","Шырыня стужкі, мм","Таспа ені, мм"},
    {"e11_label_length","Длина этикетки, мм","Label length, mm","Довжина етикетки, мм","Даўжыня этыкеткі, мм","Жапсырма ұзындығы, мм"},
    {"e11_density","Плотность","Density","Щільність","Шчыльнасць","Қоюлық"},
    {"e11_speed","Скорость","Speed","Швидкість","Хуткасць","Жылдамдық"},
    {"e11_text","Текст","Text","Текст","Тэкст","Мәтін"},
    {"e11_use_selected","Вставить метку выбранного диска","Use selected disk label","Вставити мітку вибраного диска","Уставіць метку выбранага дыска","Таңдалған диск белгісін қою"},
    {"e11_invalid_mac","Некорректный MAC-адрес. Введите MAC или включите автоопределение.","Invalid MAC address. Enter a MAC or enable automatic detection.","Некоректна MAC-адреса. Введіть MAC або увімкніть автовизначення.","Няправільны MAC-адрас. Увядзіце MAC або ўключыце аўтавызначэнне.","MAC мекенжайы дұрыс емес. MAC енгізіңіз немесе автоматты анықтауды қосыңыз."},
    {"e11_enter_text","Введите текст для печати.","Enter text to print.","Введіть текст для друку.","Увядзіце тэкст для друку.","Басып шығарылатын мәтінді енгізіңіз."},
    {"e11_text_too_long","Текст слишком длинный.","Text is too long.","Текст надто довгий.","Тэкст занадта доўгі.","Мәтін тым ұзын."},
    {"e11_shutting_down","Плагин завершает работу.","Plugin is shutting down.","Плагін завершує роботу.","Плагін завяршае працу.","Плагин жұмысын аяқтап жатыр."},
    {"e11_thread_fail","Не удалось создать поток печати E11.","Could not create the E11 print worker.","Не вдалося створити потік друку E11.","Не ўдалося стварыць паток друку E11.","E11 басып шығару ағынын жасау мүмкін болмады."},
};
static const int I18N_N = (int)(sizeof(I18N) / sizeof(I18N[0]));
static char g_lang[32] = "ru";
static GPtrArray *g_user_languages = NULL;

static gboolean i18n_language_code_valid(const char *code) {
    if (!code) return FALSE;
    size_t n = strlen(code);
    if (n < 2 || n > 15) return FALSE;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)code[i];
        if (!(g_ascii_isalnum(c) || c == '_' || c == '-')) return FALSE;
    }
    return TRUE;
}

static const char *builtin_language_name(const char *code) {
    if (!code) return NULL;
    if (strcmp(code, "ru") == 0) return "Русский";
    if (strcmp(code, "en") == 0) return "English";
    if (strcmp(code, "uk") == 0) return "Українська";
    if (strcmp(code, "be") == 0) return "Беларуская";
    if (strcmp(code, "kk") == 0) return "Қазақша";
    return NULL;
}

static const i18n_entry_t *i18n_find_builtin(const char *key) {
    if (!key) return NULL;
    for (int i = 0; i < I18N_N; i++)
        if (strcmp(I18N[i].key, key) == 0) return &I18N[i];
    return NULL;
}

static const char *i18n_builtin_value(const i18n_entry_t *e, const char *code) {
    if (!e) return NULL;
    if (code && strcmp(code, "ru") == 0) return e->ru;
    if (code && strcmp(code, "uk") == 0) return e->uk;
    if (code && strcmp(code, "be") == 0) return e->be;
    if (code && strcmp(code, "kk") == 0) return e->kk;
    return e->en;
}

static user_language_t *i18n_find_user_language(const char *code) {
    if (!g_user_languages || !code) return NULL;
    for (guint i = 0; i < g_user_languages->len; i++) {
        user_language_t *lang = g_ptr_array_index(g_user_languages, i);
        if (lang && strcmp(lang->code, code) == 0) return lang;
    }
    return NULL;
}

static gboolean i18n_language_exists(const char *code) {
    return builtin_language_name(code) != NULL || i18n_find_user_language(code) != NULL;
}

static gboolean i18n_set_language(const char *code) {
    if (!i18n_language_exists(code)) return FALSE;
    g_strlcpy(g_lang, code, sizeof(g_lang));
    return TRUE;
}

static const char *i18n(const char *key) {
    if (!key) return "";
    user_language_t *user = i18n_find_user_language(g_lang);
    if (user && user->strings) {
        const char *v = g_hash_table_lookup(user->strings, key);
        if (v) return v;
        if (user->fallback && builtin_language_name(user->fallback)) {
            const i18n_entry_t *e = i18n_find_builtin(key);
            if (e) return i18n_builtin_value(e, user->fallback);
        }
    }
    const i18n_entry_t *e = i18n_find_builtin(key);
    return e ? i18n_builtin_value(e, g_lang) : key;
}

static gboolean i18n_next_printf_type(const char **cursor, char out[5], gboolean *found) {
    const char *p = cursor && *cursor ? *cursor : NULL;
    if (!p || !out || !found) return FALSE;
    *found = FALSE;
    while (*p) {
        if (*p++ != '%') continue;
        if (*p == '%') { p++; continue; }
        if (*p == '\0') return FALSE;
        while (*p && strchr("-+ #0'I", *p)) p++;
        if (*p == '*') return FALSE;
        while (g_ascii_isdigit((guchar)*p)) p++;
        if (*p == '$') return FALSE;
        if (*p == '.') {
            p++;
            if (*p == '*') return FALSE;
            while (g_ascii_isdigit((guchar)*p)) p++;
        }
        char l1 = 0, l2 = 0;
        if (*p == 'h' || *p == 'l') {
            l1 = *p++;
            if (*p == l1) l2 = *p++;
        } else if (*p == 'j' || *p == 'z' || *p == 't' || *p == 'L') {
            l1 = *p++;
        }
        char conv = *p++;
        if (!strchr("diuoxXfFeEgGaAcsp", conv) || conv == 'n') return FALSE;
        out[0] = l1 ? l1 : '-';
        out[1] = l2 ? l2 : '-';
        out[2] = ':';
        out[3] = conv;
        out[4] = '\0';
        *cursor = p;
        *found = TRUE;
        return TRUE;
    }
    *cursor = p;
    return TRUE;
}

static gboolean i18n_printf_signature_matches(const char *expected, const char *candidate) {
    if (!expected || !candidate) return FALSE;
    const char *a = expected;
    const char *b = candidate;
    for (;;) {
        char ta[5] = {0}, tb[5] = {0};
        gboolean fa = FALSE, fb = FALSE;
        if (!i18n_next_printf_type(&a, ta, &fa) || !i18n_next_printf_type(&b, tb, &fb)) return FALSE;
        if (fa != fb) return FALSE;
        if (!fa) return TRUE;
        if (strcmp(ta, tb) != 0) return FALSE;
    }
}

static void user_language_free(user_language_t *lang) {
    if (!lang) return;
    g_free(lang->code);
    g_free(lang->name);
    g_free(lang->fallback);
    if (lang->strings) g_hash_table_destroy(lang->strings);
    g_free(lang);
}

static gboolean i18n_read_safe_file(const char *path, gchar **out_data, gsize *out_len) {
    if (!path || !out_data || !out_len) return FALSE;
    *out_data = NULL;
    *out_len = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return FALSE;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) || st.st_size <= 0 || st.st_size > 1024 * 1024) {
        close(fd);
        return FALSE;
    }
    gsize len = (gsize)st.st_size;
    gchar *buf = g_malloc(len + 1);
    if (!buf) { close(fd); return FALSE; }
    gsize off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n > 0) off += (gsize)n;
        else if (n < 0 && errno == EINTR) continue;
        else { g_free(buf); close(fd); return FALSE; }
    }
    close(fd);
    buf[len] = '\0';
    if (!g_utf8_validate(buf, (gssize)len, NULL)) { g_free(buf); return FALSE; }
    *out_data = buf;
    *out_len = len;
    return TRUE;
}

static void i18n_load_user_pack(const char *path) {
    gchar *data = NULL;
    gsize len = 0;
    if (!i18n_read_safe_file(path, &data, &len)) return;
    GKeyFile *kf = g_key_file_new();
    GError *err = NULL;
    if (!g_key_file_load_from_data(kf, data, len, G_KEY_FILE_NONE, &err)) {
        g_clear_error(&err);
        g_key_file_unref(kf);
        g_free(data);
        return;
    }
    g_free(data);
    char *code = g_key_file_get_string(kf, "language", "code", NULL);
    char *name = g_key_file_get_string(kf, "language", "name", NULL);
    char *fallback = g_key_file_get_string(kf, "language", "fallback", NULL);
    if (!fallback) fallback = g_strdup("en");
    if (!i18n_language_code_valid(code) || !name || !name[0] || strlen(name) > 96 ||
        !g_utf8_validate(name, -1, NULL) || !builtin_language_name(fallback) ||
        builtin_language_name(code) || i18n_find_user_language(code)) {
        g_free(code); g_free(name); g_free(fallback); g_key_file_unref(kf); return;
    }
    gsize count = 0;
    gchar **keys = g_key_file_get_keys(kf, "strings", &count, NULL);
    if (!keys || count == 0 || count > 512) {
        g_strfreev(keys); g_free(code); g_free(name); g_free(fallback); g_key_file_unref(kf); return;
    }
    user_language_t *lang = g_new0(user_language_t, 1);
    lang->code = code;
    lang->name = name;
    lang->fallback = fallback;
    lang->strings = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (!lang->strings) { user_language_free(lang); g_strfreev(keys); g_key_file_unref(kf); return; }
    for (gsize i = 0; i < count; i++) {
        const char *key = keys[i];
        if (!key || !key[0] || strlen(key) > 96) continue;
        const i18n_entry_t *base = i18n_find_builtin(key);
        if (!base) continue;
        char *value = g_key_file_get_string(kf, "strings", key, NULL);
        if (!value) continue;
        const char *expected = i18n_builtin_value(base, fallback);
        if (strlen(value) > 8192 || !g_utf8_validate(value, -1, NULL) ||
            !i18n_printf_signature_matches(expected, value)) { g_free(value); continue; }
        g_hash_table_replace(lang->strings, g_strdup(key), value);
    }
    g_strfreev(keys);
    g_key_file_unref(kf);
    if (g_hash_table_size(lang->strings) == 0) { user_language_free(lang); return; }
    g_ptr_array_add(g_user_languages, lang);
}

static gint i18n_path_compare(gconstpointer a, gconstpointer b) {
    const char *const *pa = a;
    const char *const *pb = b;
    return g_strcmp0(pa ? *pa : NULL, pb ? *pb : NULL);
}

static char *i18n_language_directory(void) {
    const char *home = g_get_home_dir();
    if (!home || !home[0]) return NULL;
    char *base = g_build_filename(home, ".diskpass", NULL);
    if (!base) return NULL;
    if (g_mkdir_with_parents(base, 0700) != 0) { g_free(base); return NULL; }
    struct stat st;
    if (g_lstat(base, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || chmod(base, 0700) != 0) {
        g_free(base); return NULL;
    }
    char *dir = g_build_filename(base, "lang", NULL);
    g_free(base);
    if (!dir) return NULL;
    if (g_mkdir_with_parents(dir, 0700) != 0 || g_lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != getuid() || chmod(dir, 0700) != 0) { g_free(dir); return NULL; }
    return dir;
}

static void i18n_init(void) {
    if (g_user_languages) return;
    g_user_languages = g_ptr_array_new_with_free_func((GDestroyNotify)user_language_free);
    if (!g_user_languages) return;
    char *dir = i18n_language_directory();
    if (!dir) return;
    GDir *d = g_dir_open(dir, 0, NULL);
    if (!d) { g_free(dir); return; }
    GPtrArray *paths = g_ptr_array_new_with_free_func(g_free);
    const char *name = NULL;
    while ((name = g_dir_read_name(d)) != NULL) {
        if (!g_str_has_suffix(name, ".ini")) continue;
        char *path = g_build_filename(dir, name, NULL);
        if (path) g_ptr_array_add(paths, path);
    }
    g_dir_close(d);
    g_free(dir);
    g_ptr_array_sort(paths, i18n_path_compare);
    for (guint i = 0; i < paths->len; i++) i18n_load_user_pack(g_ptr_array_index(paths, i));
    g_ptr_array_free(paths, TRUE);
}

static void i18n_shutdown(void) {
    if (g_user_languages) g_ptr_array_free(g_user_languages, TRUE);
    g_user_languages = NULL;
}

static void i18n_populate_combo(GtkComboBoxText *combo) {
    if (!combo) return;
    gtk_combo_box_text_remove_all(combo);
    const char *codes[] = {"ru","en","uk","be","kk"};
    for (guint i = 0; i < G_N_ELEMENTS(codes); i++)
        gtk_combo_box_text_append(combo, codes[i], builtin_language_name(codes[i]));
    if (g_user_languages) {
        for (guint i = 0; i < g_user_languages->len; i++) {
            user_language_t *lang = g_ptr_array_index(g_user_languages, i);
            if (lang) gtk_combo_box_text_append(combo, lang->code, lang->name);
        }
    }
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), g_lang))
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), "en");
}
