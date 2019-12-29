#define MODULE_LOG_PREFIX "cardlist"

#include "globals.h"

#ifdef WITH_CARDLIST

#include "cardlist.h"

//
//
// Some legal data for cards
//
// eg: 0x01,0x02,0x03,...,

#ifdef READER_VIACCESS
/* Redlight Mega Elite */
static uint8_t rlme_boxkey[4] = {0x0};
static uint8_t rlme_deskey[16] = {0x0};
/* Redlight Mega Royale */
static uint8_t rlmr_boxkey[4] = {0x0};
static uint8_t rlmr_deskey[16] = {0x0};
/* TNT Viaccess v5 */
static uint8_t tnt_boxkey[4] = {0x0};
static uint8_t tnt_deskey[16] = {0x0};
/* TNT Viaccess v6 */
static uint8_t tnt6_boxkey[4] = {0x0};
static uint8_t tnt6_deskey[16] = {0x0};
#endif
#ifdef READER_IRDETO
/* ICE Irdeto-Mode */
static uint8_t ice_boxkey[8] = {0x0};
static uint8_t ice_rsakey[64] = {0x0};
/* Ziggo NL */
static uint8_t znl_boxkey[8] = {0x0};
static uint8_t znl_rsakey[64] = {0x0};
#endif
#ifdef READER_NAGRA
/* Astra HD01 / HD02 */
static uint8_t hd_boxkey[8] = {0x0};
static uint8_t hd_rsakey[64] = {0x0};
/* Tivusat 183D / 183E */
static uint8_t tivu_rsakey[120] = {0x0};
/* Unitymedia UM01 / UM02v */
static uint8_t um_boxkey[8] = {0x0};
static uint8_t um_rsakey[64] = {0x0};
/* Vodafone D0x Ix2 */
static uint8_t vf_boxkey[8] = {0x0};
static uint8_t vf_rsakey[64] = {0x0};
#endif
#ifdef READER_NAGRA_MERLIN
/* Astra HD03 / HD03a / HD03b / HD04 / HD04a / HD04b / HD04h / HD05a */
static uint8_t mod1[112] = {0x0};
static uint8_t mod2[112] = {0x0};
static uint8_t key3588[136] = {0x0};
static uint8_t data50[80] = {0x0};
static uint8_t mod50[80] = {0x0};
static uint8_t nuid[4] = {0x0};
static uint8_t cwpk[16] = {0x0};
/* Max TV */
static uint8_t maxtv_mod1[112] = {0x0};
static uint8_t maxtv_mod2[112] = {0x0};
static uint8_t maxtv_key3588[136] = {0x0};
static uint8_t maxtv_data50[80] = {0x0};
static uint8_t maxtv_mod50[80] = {0x0};
static uint8_t maxtv_nuid[4] = {0x0};
static uint8_t maxtv_cwpk[16] = {0x0};
#endif

//
//
// Sky section
//
//

#ifdef READER_VIDEOGUARD
/* Sky V13 / V14 / V15 */

static uint32_t v13_boxid = 0x12345678;
static uint8_t  v13_ins7E[26 + 1] = {0x0};
static uint8_t  v13_k1_generic[16 + 1] = {0x0};
static uint8_t  v13_k1_unique[16 + 1] = {0x0};
static uint32_t v14_boxid = 0x12345678;
static uint8_t  v14_ins7E[26 + 1] = {0x0};
static uint8_t  v14_k1_generic[16 + 1] = {0x0};
static uint8_t  v14_k1_unique[16 + 1] = {0x0};
static uint32_t v15_boxid = 0x12345678;
static uint8_t  v15_ins7E[26 + 1] = {0x0};
static uint8_t  v15_k1_generic[16 + 1] = {0x0};
static uint8_t  v15_k1_unique[16 + 1] = {0x0};
#endif

//
//
// End Sky section
//
//

/*
Bit pattern for save/block EMMs:
EMM_UNIQUE: 1
EMM_SHARED: 2
EMM_GLOBAL: 4
EMM_UNKNOWN: 8
SUM EMM for Value
*/

struct atrlist current;

void findatr(struct s_reader *reader) {
	current.found = 1;
	strcpy(current.info, "recognized");

	/* more providers: ? */
	if (strncmp(current.atr, "3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6", 42) == 0) {
		strcpy(current.providername, "Canal Digitaal (NL)");
#ifdef READER_SECA
		reader->caid = 0x0100;
		reader->ratelimitecm = 4;
		reader->ratelimittime = 9000;
		reader->saveemm = (3 | reader->saveemm);
		reader->blockemm = (12 | reader->blockemm);
#else
		strcpy(current.info, " - but card system SECA not built in!");
#endif
	} else if (strncmp(current.atr, "3F 77 18 00 00 C2 EB 41 02 6C 90 00", 35) == 0) {
		/* Mega Elite Royale V5 (INT) (0500:043800,050F00) */
		strcpy(current.providername, "Redlight Mega Elite");
#ifdef READER_VIACCESS
		if (rlme_boxkey[sizeof(rlme_boxkey) - 1]) {
			memcpy(reader->boxkey, rlme_boxkey, sizeof(rlme_boxkey));
			reader->boxkey_length = sizeof(rlme_boxkey);
			memcpy(reader->des_key, rlme_deskey, sizeof(rlme_deskey));
			reader->des_key_length = sizeof(rlme_deskey);
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + deskey");
		}
		memcpy(reader->pincode, "0000", 4);
		reader->blockemm = (12 | reader->blockemm);
#else
		strcpy(current.info, " - but card system VIACCESS not built in!");
#endif
	} else if (
			/* ? */
			strncmp(current.atr, "3F 77 18 00 00 D3 8A 42 01 64 90 00", 35) == 0 ||
			// TNTSAT V5
			strncmp(current.atr, "3F 77 18 00 00 C2 EB 45 02 6C 90 00", 35) == 0) {
		strcpy(current.providername, "Redlight Mega Royale");
#ifdef READER_VIACCESS
		if (rlmr_boxkey[sizeof(rlmr_boxkey) - 1]) {
			memcpy(reader->boxkey, rlmr_boxkey, sizeof(rlmr_boxkey));
			reader->boxkey_length = sizeof(rlmr_boxkey);
			memcpy(reader->des_key, rlmr_deskey, sizeof(rlmr_deskey));
			reader->des_key_length = sizeof(rlmr_deskey);
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + deskey");
		}
		memcpy(reader->pincode, "0000", 4);
		reader->blockemm = (12 | reader->blockemm);
#else
		strcpy(current.info, " - but card system VIACCESS not built in!");
#endif
	} else if (strncmp(current.atr, "3F 77 18 00 00 C2 7A 41 02 68", 29) == 0) {
		/* more providers: FRANSAT (FR) V4 (0500:041900), SRF (CH) V4 (0500:040810) */
		strcpy(current.providername, "SRG v4");
#ifdef READER_VIACCESS
		reader->blockemm = (8 | reader->blockemm);
#else
		strcpy(current.info, " - but card system VIACCESS not built in!");
#endif
	} else if (strncmp(current.atr, "3F 77 18 00 00 C2 7A 44 02 68", 29) == 0) {
		/* more providers: FRANSAT (FR) V5 (0500:041950), Bis TV V4 (FR) (0500:042800) */
		strcpy(current.providername, "SRG v5");
#ifdef READER_VIACCESS
		reader->read_old_classes = 0;
		reader->blockemm = (8 | reader->blockemm);
#else
		strcpy(current.info, " - but card system VIACCESS not built in!");
#endif
	} else if (strncmp(current.atr, "3F 77 18 00 00 C2 EB 41 02 6C", 29) == 0) {
		/* more providers: TNTSAT V4/V5 (FR) (0500:030B00), NTV+ (RU) V6 (0500:050100), TVSAT AFRICA (INT) V5 (0500:042840) */
		strcpy(current.providername, "TNT Viaccess v5");
#ifdef READER_VIACCESS
		if (tnt_boxkey[sizeof(tnt_boxkey) - 1]) {
			if (!reader->boxkey_length) {
				memcpy(reader->boxkey, tnt_boxkey, sizeof(tnt_boxkey));
				reader->boxkey_length = sizeof(tnt_boxkey);
			}
			if (!reader->des_key_length) {
				memcpy(reader->des_key, tnt_deskey, sizeof(tnt_deskey));
				reader->des_key_length = sizeof(tnt_deskey);
			}
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + deskey");
		}
		memcpy(reader->pincode, "0000", 4);
#else
		strcpy(current.info, " - but card system VIACCESS not built in!");
#endif
	} else if (strncmp(current.atr, "3F 77 18 00 00 D3 8A 40 01 64", 29) == 0) {
		/* more providers: TNTSAT V6 (FR) (0500:030B00), CANAL+/CANAL (FR) V6 (0500:032830), ORANGE SAT (FR) V6 (0500:032900), SRF (CH) V6 (0500:060200), TELESAT (ex MOBISTAR) (BE) V6 (0500:051900) */
		strcpy(current.providername, "TNT Viaccess v6");
#ifdef READER_VIACCESS
		if (tnt6_boxkey[sizeof(tnt6_boxkey) - 1]) {
			if (!reader->boxkey_length) {
				memcpy(reader->boxkey, tnt6_boxkey, sizeof(tnt6_boxkey));
				reader->boxkey_length = sizeof(tnt6_boxkey);
			}
			if (!reader->des_key_length) {
				memcpy(reader->des_key, tnt6_deskey, sizeof(tnt6_deskey));
				reader->des_key_length = sizeof(tnt6_deskey);
			}
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + deskey");
		}
		memcpy(reader->pincode, "0000", 4);
#else
		strcpy(current.info, " - but card system VIACCESS not built in!");
#endif
	} else if (strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 20 56 35 2E 38 95", 59) == 0) {
		/* Ziggo NL ? */
		strcpy(current.providername, "Ziggo NL");
#ifdef READER_IRDETO
		if (znl_boxkey[sizeof(znl_boxkey) - 1]) {
			if (!reader->boxkey_length) {
				memcpy(reader->boxkey, znl_boxkey, sizeof(znl_boxkey));
				reader->boxkey_length = sizeof(znl_boxkey);
			}
			if (!reader->rsa_mod_length) {
				memcpy(reader->rsa_mod, znl_rsakey, sizeof(znl_rsakey));
				reader->rsa_mod_length = sizeof(znl_rsakey);
			}
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + rsakey");
		}
		reader->blockemm = (12 | reader->blockemm);
#else
		strcpy(current.info, " - but card system IRDETO not built in!");
#endif
	} else if (strncmp(current.atr, "3B 78 12 00 00 54 C4 03 00 8F F1 90 00", 38) == 0) {
		/* more providers: ? */
		if (!reader->force_irdeto) {
			strcpy(current.providername, "ICE CW-Mode");
#ifdef READER_CRYPTOWORKS
			reader->needsglobalfirst = 1;
			reader->blockemm = (12 | reader->blockemm);
#else
			strcpy(current.info, " - but card system CRYPTOWORKS not built in!");
#endif
		} else {
			strcpy(current.providername, "ICE Irdeto-Mode");
#ifdef READER_IRDETO
			if (ice_boxkey[sizeof(ice_boxkey) - 1] && ice_rsakey[sizeof(ice_rsakey) - 1]) {
				if (!reader->boxkey_length) {
					memcpy(reader->boxkey, ice_boxkey, sizeof(ice_boxkey));
					reader->boxkey_length = sizeof(ice_boxkey);
				}
				if (!reader->rsa_mod_length) {
					memcpy(reader->rsa_mod, ice_rsakey, sizeof(ice_rsakey));
					reader->rsa_mod_length = sizeof(ice_rsakey);
				}
			} else {
				rdr_log(reader, "no keys built in, use config values boxkey + rsakey or disable force_irdeto");
			}
			reader->blockemm = (12 | reader->blockemm);
#else
			strcpy(current.info, " - but card system IRDETO not built in!");
#endif
		}
	} else if (strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FF 47 00 54 49 47 45 52 30 30 33 20 52 65 76 32 35 30 64", 80) == 0 ||
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 38 37 14", 80) == 0) {
			/* Tivusat (IT) (183x/Sat) */
		strcpy(current.providername, "Tivusat 183D / 183E");
#ifdef READER_NAGRA
		if (tivu_rsakey[sizeof(tivu_rsakey) - 1]) {
			memcpy(reader->rsa_mod, tivu_rsakey, sizeof(tivu_rsakey));
			reader->rsa_mod_length = sizeof(tivu_rsakey);
		} else {
			rdr_log(reader, "no keys built in, use config value rsakey");
		}
		reader->blockemm = (8 | reader->blockemm);
#else
		strcpy(current.info, " - but card system NAGRA not built in!");
#endif
	}
	/* Unitymedia UM01 */
	else if (strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15", 80) == 0 ||
			 // UM02
			 strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12", 80) == 0) {
		strcpy(current.providername, "Unitymedia UM01 / UM02");
#ifdef READER_NAGRA
		if (um_boxkey[sizeof(um_boxkey) - 1]) {
			memcpy(reader->boxkey, um_boxkey, sizeof(um_boxkey));
			reader->boxkey_length = sizeof(um_boxkey);
			memcpy(reader->rsa_mod, um_rsakey, sizeof(um_rsakey));
			reader->rsa_mod_length = sizeof(um_rsakey);
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + rsakey");
		}
		reader->blockemm = (12 | reader->blockemm);
#else
		strcpy(current.info, " - but card system NAGRA not built in!");
#endif
	} else if (strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 03 84 55 FF 80 6D", 59) == 0) {
		/* more providers: ? */
		strcpy(current.providername, "Vodafone D0x Ix2");
#ifdef READER_NAGRA
		if (vf_boxkey[sizeof(vf_boxkey) - 1]) {
			memcpy(reader->boxkey, vf_boxkey, sizeof(vf_boxkey));
			reader->boxkey_length = sizeof(vf_boxkey);
			memcpy(reader->rsa_mod, vf_rsakey, sizeof(vf_rsakey));
			reader->rsa_mod_length = sizeof(vf_rsakey);
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + rsakey");
		}
		reader->blockemm = (12 | reader->blockemm);
#else
		strcpy(current.info, " - but card system NAGRA not built in!");
#endif
	} else if (
			// HD+ HD01 RevGC4 (DE) (1830/Sat)
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 34 63", 80) == 0 ||
			// HD+ HD01 RevGC6 (DE) (1830/Sat)
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61", 80) == 0 ||
			// HD+ HD02 (DE) (1843/Sat)
			(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28", 80) == 0 && (!reader->cak7_mode))) {
		strcpy(current.providername, "Astra HD+ HD01/HD02");
#ifdef READER_NAGRA
		if (hd_boxkey[sizeof(hd_boxkey) - 1]) {
			memcpy(reader->boxkey, hd_boxkey, sizeof(hd_boxkey));
			reader->boxkey_length = sizeof(hd_boxkey);
			memcpy(reader->rsa_mod, hd_rsakey, sizeof(hd_rsakey));
			reader->rsa_mod_length = sizeof(hd_rsakey);
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + rsakey");
		}
		reader->cak7_mode = 0;
		reader->blockemm = (12 | reader->blockemm);
#else
		strcpy(current.info, " - but card system NAGRA not built in!");
#endif
	} else if (
			// HD+ HD02 (DE) (1843/Sat)
			(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28", 80) == 0 && (reader->cak7_mode)) ||
			// HD+ HD03 (DE) (1860/Sat)
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 39 30 20 4D 65 72 51 32 35 4F", 80) == 0 ||
			// HD03a (DE) (1860/Sat)
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 31 30 20 52 65 76 51 32 35 17", 80) == 0 ||
			// HD03b (DE) (1860/Sat)
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 51 32 35 17", 80) == 0 ||
			// HD04a|b (DE) (186A/Sat)
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 30 17", 80) == 0 ||
			// HD04h (DE) (186A/Sat)
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 34 13", 80) == 0 ||
			// HD05 (DE) (186A/Sat)
			strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 35 30 20 52 65 76 57 36 30 14", 80) == 0) {
		if (reader->cak7_mode) {
			strcpy(current.providername, "Astra HD+ HD02/HD03/HD04/HD05");
		} else {
			strcpy(current.providername, "Astra HD+ HD03/HD04/HD05");
		}
#ifdef READER_NAGRA_MERLIN
		if (mod1[sizeof(mod1) - 1]) {
			memcpy(reader->mod1, mod1, sizeof(mod1));
			reader->mod1_length = sizeof(mod1);
			memcpy(reader->mod2, mod2, sizeof(mod2));
			reader->mod2_length = sizeof(mod2);
			memcpy(reader->key3588, key3588, sizeof(key3588));
			reader->key3588_length = sizeof(key3588);
			memcpy(reader->data50, data50, sizeof(data50));
			reader->data50_length = sizeof(data50);
			memcpy(reader->mod50, mod50, sizeof(mod50));
			reader->mod50_length = sizeof(mod50);
			memcpy(reader->nuid, nuid, sizeof(nuid));
			reader->nuid_length = sizeof(nuid);
			memcpy(reader->cwekey0, cwpk, sizeof(cwpk));
			reader->cwekey0_length = sizeof(cwpk);
		} else {
			rdr_log(reader, "no keys built in, use config values mod1 + mod2 + key3588 + data50 + mod50 + nuid + cwekey0");
		}
		reader->cak7_mode = 1;
		reader->forceemmg = 1;
		reader->blockemm = (8 | reader->blockemm);
#else
		strcpy(current.info, " - but card system NAGRA_MERLIN not built in!");
#endif
	} else if (strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 38 32 20 52 65 76 52 32 36 1C", 80) == 0) {
		/* MAXTV (HR) (1830/Sat) */
		strcpy(current.providername, "Max TV");
#ifdef READER_NAGRA_MERLIN
		if (maxtv_mod1[sizeof(maxtv_mod1) - 1]) {
			memcpy(reader->mod1, maxtv_mod1, sizeof(maxtv_mod1));
			reader->mod1_length = sizeof(maxtv_mod1);
			memcpy(reader->mod2, maxtv_mod2, sizeof(maxtv_mod2));
			reader->mod2_length = sizeof(maxtv_mod2);
			memcpy(reader->key3588, maxtv_key3588, sizeof(maxtv_key3588));
			reader->key3588_length = sizeof(maxtv_key3588);
			memcpy(reader->data50, maxtv_data50, sizeof(maxtv_data50));
			reader->data50_length = sizeof(maxtv_data50);
			memcpy(reader->mod50, maxtv_mod50, sizeof(maxtv_mod50));
			reader->mod50_length = sizeof(maxtv_mod50);
			memcpy(reader->nuid, maxtv_nuid, sizeof(maxtv_nuid));
			reader->nuid_length = sizeof(maxtv_nuid);
			memcpy(reader->cwekey0, maxtv_cwpk, sizeof(maxtv_cwpk));
			reader->cwekey0_length = sizeof(maxtv_cwpk);
		} else {
			rdr_log(reader, "no keys built in, use config values mod1 + mod2 + key3588 + data50 + mod50 + nuid + cwekey0");
		}
		reader->blockemm = (8 | reader->blockemm);
#else
		strcpy(current.info, " - but card system NAGRA_MERLIN not built in!");
#endif
	} else {
		current.found = 0;
	}

#ifdef READER_VIDEOGUARD
	if (current.found == 0) {
		int i;
		char buf[66];
		for (i = 10; i < 17; i++) {
			// Check for Sky 19.2 E Sat
			snprintf(buf, 66, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
			if (strncmp(current.atr, buf, 65) == 0)	{
				strcpy(current.providername, "Sky Deutschland V13");
				reader->caid = 0x09C4;
				if (strlen((char*)v13_k1_generic)) {
					if (!reader->boxid || reader->boxid == 0x12345678) {
						reader->boxid = v13_boxid;
					}
					if (!strlen((char*)reader->ins7E) && strlen((char*)v13_ins7E)) {
						v13_ins7E[sizeof(v13_ins7E) - 1] = 0x01;
						memcpy(reader->ins7E, v13_ins7E, sizeof(v13_ins7E));
					}
					if (!strlen((char*)reader->k1_generic)) {
						v13_k1_generic[sizeof(v13_k1_generic) - 1] = 0x08;
						memcpy(reader->k1_generic, v13_k1_generic, sizeof(v13_k1_generic));
					}
					if (!strlen((char*)reader->k1_unique) && strlen((char*)v13_k1_unique)) {
						v13_k1_unique[sizeof(v13_k1_unique) - 1] = 0x08;
						memcpy(reader->k1_unique, v13_k1_unique, sizeof(v13_k1_unique));
					}
				} else {
					rdr_log(reader, "no keys built in, use config values boxid + ins7e + k1_generic + k1_unique");
				}
				reader->blockemm = (10 | reader->blockemm);
				current.found = 1;
				break;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if (strncmp(current.atr, buf, 62) == 0) {
				strcpy(current.providername, "Sky Deutschland V14");
				reader->caid = 0x098C;
				if (strlen((char*)v14_k1_generic)) {
					if (!reader->boxid || reader->boxid == 0x12345678) {
						reader->boxid = v14_boxid;
					}
					if (!strlen((char*)reader->ins7E) && strlen((char*)v14_ins7E)) {
						v14_ins7E[sizeof(v14_ins7E) - 1] = 0x01;
						memcpy(reader->ins7E, v14_ins7E, sizeof(v14_ins7E));
					}
					if (!strlen((char*)reader->k1_generic)) {
						v14_k1_generic[sizeof(v14_k1_generic) - 1] = 0x10;
						memcpy(reader->k1_generic, v14_k1_generic, sizeof(v14_k1_generic));
					}
					if (!strlen((char*)reader->k1_unique) && strlen((char*)v14_k1_unique)) {
						v14_k1_unique[sizeof(v14_k1_unique) - 1] = 0x10;
						memcpy(reader->k1_unique, v14_k1_unique, sizeof(v14_k1_unique));
					}
				} else {
					rdr_log(reader, "no keys built in, use config values boxid + ins7e + k1_generic + k1_unique");
				}
				reader->blockemm = (10 | reader->blockemm);
				current.found = 1;
				break;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 80 0F 55 B0 02 69 FF 4A 50 F0 80 00 50 31 03", i);
			if (strncmp(current.atr, buf, 62) == 0) {
				strcpy(current.providername, "Sky Deutschland V15");
				reader->caid = 0x098D;
				if (strlen((char*)v15_k1_generic)) {
					if (!reader->boxid || reader->boxid == 0x12345678) {
						reader->boxid = v15_boxid;
					}
					if (!strlen((char*)reader->ins7E) && strlen((char*)v15_ins7E)) {
						v15_ins7E[sizeof(v15_ins7E) - 1] = 0x01;
						memcpy(reader->ins7E, v15_ins7E, sizeof(v15_ins7E));
					}
					if (!strlen((char*)reader->k1_generic)) {
						v15_k1_generic[sizeof(v15_k1_generic) - 1] = 0x10;
						memcpy(reader->k1_generic, v15_k1_generic, sizeof(v15_k1_generic));
					}
					if (!strlen((char*)reader->k1_unique) && strlen((char*)v15_k1_unique)) {
						v15_k1_unique[sizeof(v15_k1_unique) - 1] = 0x10;
						memcpy(reader->k1_unique, v15_k1_unique, sizeof(v15_k1_unique));
					}
				} else {
					rdr_log(reader, "no keys built in, use config values boxid + ins7e + k1_generic + k1_unique");
				}
				reader->blockemm = (10 | reader->blockemm);
				current.found = 1;
				break;
			}
			snprintf(buf, 66, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if (strncmp(current.atr, buf, 65) == 0) {
				strcpy(current.providername, "Sky/Unitymedia V23");
				reader->boxid = 0x12345678;
				reader->blockemm = (12 | reader->blockemm);
				current.found = 1;
				break;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if (strncmp(current.atr, buf, 62) == 0) {
				strcpy(current.providername, "Vodafone G09");
				reader->boxid = 0x12345678;
				reader->blockemm = (12 | reader->blockemm);
				reader->deprecated = 1;
				current.found = 1;
				break;
			}
		}
	}
#endif
	if ( current.found == 1 ) {
		// if(reader->grp < 1) { reader->grp = 0x1ULL; }
		if(reader->grp < 1) { reader->grp = 0xFFFFFFFFFFFFFFFFULL; };
	}
	return;
}

#endif // WITH_CARDLIST
