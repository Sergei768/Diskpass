#include "diskpass.h"

const char ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const size_t ALPHABET_LEN = 32;
const char *SCHEMA_PARTS[] = {"type","size","content_tag","cipher","dsalt"};
const int SCHEMA_COUNT = 5;
const int PART_LENGTHS[] = {1, 2, 2, 1, 2};
const int FULL_PART_LENGTHS[] = {2, 3, 3, 2, 3};

const map_entry_t TYPE_MAP[] = {
    {"HDD","H"},{"SSD","S"},{"USB","U"},{"M.2","M"},{"SD","D"},{"CF","C"},
    {"OPTICAL","O"},{"OTHER","X"},
    {"LTO1","1"},{"LTO2","2"},{"LTO3","3"},{"LTO4","4"},
    {"LTO5","5"},{"LTO6","6"},{"LTO7","7"},{"LTO8","8"},{"LTO9","9"}
};
const int TYPE_MAP_N = ARRAY_SIZE(TYPE_MAP);

const map_entry_t SIZE_MAP[] = {
    {"700MB","7M"},{"1GB","1A"},{"2GB","2A"},{"4GB","4G"},{"8GB","8G"},
    {"16GB","1F"},{"32GB","3F"},{"64GB","6F"},
    {"4.7GB","D4"},{"8.5GB","D8"},{"25GB","B5"},{"50GB","B0"},{"100GB","B1"},
    {"120GB","C1"},{"128GB","C2"},{"200GB","E1"},{"240GB","C3"},{"250GB","C4"},{"256GB","C5"},
    {"320GB","C6"},{"400GB","E2"},{"480GB","C7"},{"500GB","C8"},{"512GB","C9"},{"800GB","E3"},
    {"1TB","T1"},{"1.5TB","T2"},{"1.6TB","T3"},{"2TB","T4"},{"2.5TB","T5"},
    {"3TB","T6"},{"3.0TB","T7"},{"4TB","T8"},{"6TB","T9"},{"6.25TB","TA"},
    {"8TB","TB"},{"10TB","TC"},{"12TB","TD"},{"14TB","TE"},{"15TB","TF"},
    {"16TB","TG"},{"18TB","TH"},{"20TB","TJ"},{"22TB","TK"},
    {"24TB","TM"},{"30TB","TN"},{"36TB","TP"},{"45TB","TQ"}
};
const int SIZE_MAP_N = ARRAY_SIZE(SIZE_MAP);

const map_entry_t CIPHER_MAP[] = {
    {"LUKS","L"},{"VERACRYPT","V"},{"BITLOCKER","B"},
    {"7ZIP","7"},{"AGE","A"},{"GPG","G"},{"NONE","N"}
};
const int CIPHER_MAP_N = ARRAY_SIZE(CIPHER_MAP);

const char *SIZE_FOR_USB[] = {"1GB","2GB","4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB","1TB","2TB",NULL};
const char *SIZE_FOR_SD[] = {"4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB","1TB","2TB",NULL};
const char *SIZE_FOR_CF[] = {"4GB","8GB","16GB","32GB","64GB","128GB","256GB","512GB",NULL};
const char *SIZE_FOR_HDD[] = {"250GB","320GB","500GB","1TB","2TB","3TB","4TB","6TB","8TB","10TB","12TB","14TB","16TB","18TB","20TB","22TB","24TB",NULL};
const char *SIZE_FOR_SSD[] = {"120GB","128GB","240GB","250GB","256GB","480GB","500GB","512GB","1TB","2TB","4TB","8TB","16TB",NULL};
const char *SIZE_FOR_M2[] = {"128GB","250GB","256GB","500GB","512GB","1TB","2TB","4TB","8TB",NULL};
const char *SIZE_FOR_OPT[] = {"700MB","4.7GB","8.5GB","25GB","50GB","100GB",NULL};
const char *SIZE_FOR_LTO1[] = {"100GB","200GB",NULL};
const char *SIZE_FOR_LTO2[] = {"200GB","400GB",NULL};
const char *SIZE_FOR_LTO3[] = {"400GB","800GB",NULL};
const char *SIZE_FOR_LTO4[] = {"800GB","1.6TB",NULL};
const char *SIZE_FOR_LTO5[] = {"1.5TB","3.0TB",NULL};
const char *SIZE_FOR_LTO6[] = {"2.5TB","6.25TB",NULL};
const char *SIZE_FOR_LTO7[] = {"6TB","15TB",NULL};
const char *SIZE_FOR_LTO8[] = {"12TB","30TB",NULL};
const char *SIZE_FOR_LTO9[] = {"18TB","45TB",NULL};
const char *SIZE_FOR_OTHER[] = {
    "700MB","1GB","2GB","4GB","8GB","16GB","32GB","64GB",
    "4.7GB","8.5GB","25GB","50GB","100GB",
    "120GB","128GB","200GB","240GB","250GB","256GB",
    "320GB","400GB","480GB","500GB","512GB","800GB",
    "1TB","1.5TB","1.6TB","2TB","2.5TB","3TB","3.0TB",
    "4TB","6TB","6.25TB","8TB","10TB","12TB","14TB","15TB",
    "16TB","18TB","20TB","22TB","24TB","30TB","36TB","45TB",NULL
};

const type_size_assoc_t TYPE_SIZE_MAP[] = {
    {"USB",SIZE_FOR_USB},{"SD",SIZE_FOR_SD},{"CF",SIZE_FOR_CF},
    {"HDD",SIZE_FOR_HDD},{"SSD",SIZE_FOR_SSD},{"M.2",SIZE_FOR_M2},
    {"OPTICAL",SIZE_FOR_OPT},{"OTHER",SIZE_FOR_OTHER},
    {"LTO1",SIZE_FOR_LTO1},{"LTO2",SIZE_FOR_LTO2},{"LTO3",SIZE_FOR_LTO3},
    {"LTO4",SIZE_FOR_LTO4},{"LTO5",SIZE_FOR_LTO5},{"LTO6",SIZE_FOR_LTO6},
    {"LTO7",SIZE_FOR_LTO7},{"LTO8",SIZE_FOR_LTO8},{"LTO9",SIZE_FOR_LTO9}
};
const int TYPE_SIZE_MAP_N = ARRAY_SIZE(TYPE_SIZE_MAP);

static const i18n_entry_t I18N[] = {
    {"app_desc","Безопасное хранилище паролей для дисков","Secure password storage for disks"},
    {"open_db","Открыть базу","Open Database"},
    {"create_db","Создать новую базу","Create New Database"},
    {"setup_title","Настройка шифрования","Encryption Setup"},
    {"db_file","Файл базы:","Database File:"},
    {"not_selected","не выбран","not selected"},
    {"pgp_key","Ключ OpenPGP:","OpenPGP Key:"},
    {"language","Язык:","Language:"},
    {"back","Назад","Back"},
    {"create_btn","Создать базу","Create Database"},
    {"no_keys","Подходящие OpenPGP ключи не найдены.","No suitable OpenPGP keys found."},
    {"gpg_err","Ошибка GPG: ","GPG Error: "},
    {"locked_title","База заблокирована","Database Locked"},
    {"file","Файл:","File:"},
    {"unlock_btn","Разблокировать","Unlock"},
    {"lock_db","Заблокировать базу","Lock Database"},
    {"add_entry","Добавить запись","Add Entry"},
    {"edit_entry","Изменить запись","Edit Entry"},
    {"del_entry","Удалить запись","Delete Entry"},
    {"show_schema","Показать схему меток","Show Label Schema"},
    {"search","Поиск...","Search..."},
    {"select_entry","Выберите запись","Select an entry"},
    {"copy_label","Копировать метку","Copy Label"},
    {"copy_pass","Копировать пароль","Copy Password"},
    {"full_tag","Полный тег","Full Tag"},
    {"password","Пароль","Password"},
    {"notes","Заметки","Notes"},
    {"delete_msg","Удалить?","Delete?"},
    {"schema_title","Схема меток","Label Schema"},
    {"block","Блок","Block"},
    {"val","Значение","Value"},
    {"chk","Соль","Salt"},
    {"schema_footer","Последний символ блока — соль-символ.","The last character of the block is a salt character."},
    {"size_hint_title","Расшифровка кодов объёма","Size Code Reference"},
    {"cancel","Отмена","Cancel"},
    {"create","Создать","Create"},
    {"save","Сохранить","Save"},
    {"media_type","Тип носителя","Media Type"},
    {"size","Объём","Size"},
    {"cipher","Шифр","Cipher"},
    {"tag_min","Тег (мин. 2 симв.)","Tag (min. 2 chars)"},
    {"salt","Соль","Salt"},
    {"generate","Сгенерировать","Generate"},
    {"label","Метка","Label"},
    {"block_err","Ошибка в блоке","Error in block"},
    {"block_len_err","Неверная длина блока","Invalid block length"},
    {"label_err","Метка: должно быть 5 блоков","Label: must be 5 blocks"},
    {"invalid_label","Неверная метка","Invalid label"},
    {"type","Тип","Type"},
    {"content_tag","Содержимое","Content"},
    {"dsalt","Соль","Salt"},
    {"close","Закрыть","Close"},
    {"key_mismatch","Выбранный ключ не подходит для этой базы.","The selected key does not match this database."},
    {"alias","Название (для себя)","Name (for yourself)"},
    {"alias_placeholder","необязательно","optional"},
    {"file_corrupted","Файл повреждён","File corrupted"},
    {"no_recipient","Не выбран GPG сертификат","No GPG certificate selected"},
};
static const int I18N_N = ARRAY_SIZE(I18N);
char g_lang[8] = "ru";

const char *i18n(const char *key) {
    for (int i = 0; i < I18N_N; i++)
        if (strcmp(I18N[i].key, key) == 0)
            return (g_lang[0] == 'e' && g_lang[1] == 'n') ? I18N[i].en : I18N[i].ru;
    return key;
}

const char *map_encode(const char *part_name, const char *value) {
    const map_entry_t *tbl = NULL; int n = 0;
    if (strcmp(part_name, "type") == 0) { tbl = TYPE_MAP; n = TYPE_MAP_N; }
    else if (strcmp(part_name, "size") == 0) { tbl = SIZE_MAP; n = SIZE_MAP_N; }
    else if (strcmp(part_name, "cipher") == 0) { tbl = CIPHER_MAP; n = CIPHER_MAP_N; }
    if (!tbl) return value;
    for (int i = 0; i < n; i++)
        if (strcmp(tbl[i].name, value) == 0) return tbl[i].code;
    return value;
}

const char *map_decode(const char *part_name, const char *code) {
    const map_entry_t *tbl = NULL; int n = 0;
    if (strcmp(part_name, "type") == 0) { tbl = TYPE_MAP; n = TYPE_MAP_N; }
    else if (strcmp(part_name, "size") == 0) { tbl = SIZE_MAP; n = SIZE_MAP_N; }
    else if (strcmp(part_name, "cipher") == 0) { tbl = CIPHER_MAP; n = CIPHER_MAP_N; }
    if (!tbl) return code;
    for (int i = 0; i < n; i++)
        if (strcmp(tbl[i].code, code) == 0) return tbl[i].name;
    return code;
}

const char **get_sizes_for_type(const char *type_name) {
    for (int i = 0; i < TYPE_SIZE_MAP_N; i++)
        if (strcmp(TYPE_SIZE_MAP[i].type, type_name) == 0)
            return (const char **)TYPE_SIZE_MAP[i].sizes;
    return (const char **)SIZE_FOR_OTHER;
}
