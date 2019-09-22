#include <string.h>
#include "../globals.h"
#include "cardlist.h"

//
//
// Some legal data for cards
//
//

static const char data50[81]       = { "\x00" };
static const char mod50[81]        = { "\x00" };
static const char key60[97]        = { "\x00" };
static const char exp60[97]        = { "\x00" };
static const char key3588[137]     = { "\x00" };
static const char key3460[97]      = { "\x00" };
static const char key3310[17]      = { "\x00" };
static const char mod1[113]        = { "\x00" };
static const char mod2[113]        = { "\x00" };
static const char idird[5]         = { "\x00" };
static const char cmd0eprov[3]     = { "\x00" };
static const char hd_boxkey[9]     = { "\x00" };
static const char hd_rsakey[129]   = { "\x00" };
static const char hd_nuid[5]       = { "\x00" };
static const char hd_cwpk[17]      = { "\x00" };
static const char max_nuid[5]      = { "\x00" };
static const char max_cwpk[17]     = { "\x00" };
static const char rlme_boxkey[5]   = { "\x00" };
static const char rlme_deskey[17]  = { "\x00" };
static const char rlmr_boxkey[5]   = { "\x00" };
static const char rlmr_deskey[17]  = { "\x00" };
static const char tivu_rsakey[121] = { "\x00" };
static const char tnt_boxkey[5]    = { "\x00" };
static const char tnt_deskey[17]   = { "\x00" };
static const char um_boxkey[9]     = { "\x00" };
static const char um_rsakey[129]   = { "\x00" };
static const char vf_boxkey[9]     = { "\x00" };
static const char vf_rsakey[129]   = { "\x00" };
static const char znl_boxkey[9]    = { "\x00" };
static const char znl_rsakey[65]   = { "\x00" };

//
//
// End section
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

struct atrlist current = { 1, "\0", "\0" };

void findatr(struct s_reader *reader) {
	current.found = 1;
	int ishdold = 0;
	int ishdnew = 0;
	int istivu = 0;
	int istnt = 0;
	int isum = 0;

	if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61", 80) == 0 ) {
		// HD+ 01
		ishdold = 1;
		strcpy(current.providername,"Astra HD+ HD01\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28", 80) == 0 ) {
		// HD+ 02
		ishdold = 1;
		strcpy(current.providername,"Astra HD+ HD02\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 39 30 20 4D 65 72 51 32 35 4F", 80) == 0 ) {
		// HD+ 03
		ishdnew = 1;
		strcpy(current.providername,"Astra HD+ HD03\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 31 30 20 52 65 76 51 32 35 17", 80) == 0 ) {
		// HD+ 03a
		ishdnew = 1;
		strcpy(current.providername,"Astra HD+ HD03a\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 51 32 35 17", 80) == 0 ) {
		// HD+ 03b
		ishdnew = 1;
		strcpy(current.providername,"Astra HD+ HD03b\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 30 17", 80) == 0 ) {
		// HD+ 04
		ishdnew = 1;
		strcpy(current.providername,"Astra HD+ HD04\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 34 13", 80) == 0 ) {
		// HD+ 04a
		ishdnew = 1;
		strcpy(current.providername,"Astra HD+ HD04a\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15", 80) == 0 ) {
		// UM01
		isum = 1;
		strcpy(current.providername,"Unitymedia UM01\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12", 80) == 0 ) {
		// UM02
		isum = 1;
		strcpy(current.providername,"Unitymedia UM02\x0");
	} else if ( strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 03 84 55 FF 80 6D", 59) == 0 ) {
		strcpy(current.providername,"Vodafone D0x Ix2\x0");
		if ( !strncmp(vf_rsakey, "0", 1) == 0 ) {
			memcpy(reader->boxkey, vf_boxkey, 8);
			memcpy(reader->rsa_mod, vf_rsakey, 64);
			reader->boxkey_length = 8;
			reader->rsa_mod_length = 64;
		}
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 12 | reader->blockemm);
	} else if ( strncmp(current.atr, "3F 77 18 00 00 C2 EB 41 02 6C 90 00", 35) == 0 ) {
		strcpy(current.providername,"Redlight Mega Elite\x0");
		if ( !strncmp(rlme_deskey, "0", 1) == 0 ) {
			memcpy(reader->boxkey, rlme_boxkey, 4);
			memcpy(reader->des_key, rlme_deskey, 16);
			reader->boxkey_length = 4;
			reader->des_key_length = 16;
		}
		memcpy(reader->pincode, "0000\0", 5);
		reader->disablecrccws = 1;
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 12 | reader->blockemm);
	} else if ( strncmp(current.atr, "3F 77 18 00 00 D3 8A 42 01 64 90 00", 35) == 0 ) {
		strcpy(current.providername,"Redlight Mega Royale\x0");
		if ( !strncmp(rlmr_deskey, "0", 1) == 0 ) {
			memcpy(reader->boxkey, rlmr_boxkey, 4);
			memcpy(reader->des_key, rlmr_deskey, 16);
			reader->boxkey_length = 4;
			reader->des_key_length = 16;
		}
		memcpy(reader->pincode, "0000\0", 5);
		reader->disablecrccws = 1;
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 12 | reader->blockemm);
	} else if ( strncmp(current.atr, "3B 24 00 30 42 30 30", 20) == 0 ) {
		strcpy(current.providername,"MTV Unlimited\x0");
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 8 | reader->blockemm);
	} else if ( strncmp(current.atr, "3B 78 12 00 00 54 C4 03 00 8F F1 90 00", 38) == 0 ) {
		strcpy(current.providername,"Cryptoworks\x0");
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 8 | reader->blockemm);
		reader->needsglobalfirst = 1;
	} else if ( strncmp(current.atr, "3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6", 42) == 0 ) {
		strcpy(current.providername,"Canal Digitaal (NL)\x0");
		reader->caid = 0x0100;
		reader->ratelimitecm = 4;
		reader->ratelimittime = 9000;
		reader->saveemm = ( 3 | reader->saveemm);
		reader->blockemm = ( 12 | reader->blockemm);
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FF 47 00 54 49 47 45 52 30 30 33 20 52 65 76 32 35 30 64", 80) == 0 ) {
		strcpy(current.providername,"Tivusat 183D\x0");
		istivu = 1;
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 38 37 14", 80) == 0 ) {
		strcpy(current.providername,"Tivusat 183E\x0");
		istivu = 1;
	} else if ( strncmp(current.atr, "3F 77 18 00 00 C2 7A 41 02 68", 29) == 0 ) {
		strcpy(current.providername,"SRG v4\x0");
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 8 | reader->blockemm);
	} else if ( strncmp(current.atr, "3F 77 18 00 00 C2 7A 44 02 68", 29) == 0 ) {
		strcpy(current.providername,"SRG v5\x0");
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 8 | reader->blockemm);
		reader->read_old_classes = 0;
	} else if ( strncmp(current.atr, "3F 77 18 00 00 D3 8A 40 01 64", 29) == 0 ) {
		strcpy(current.providername,"SRG v6\x0");
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 8 | reader->blockemm);
		reader->read_old_classes = 0;
	} else if ( strncmp(current.atr, "3F 77 18 00 00 C2 EB 41 02 6C", 29) == 0 ) {
		strcpy(current.providername,"TNT Viaccess v5\x0");
		istnt = 1;
	} else if ( strncmp(current.atr, "3F 77 18 00 00 D3 8A 40 01 64", 29) == 0 ) {
		strcpy(current.providername,"TNT Viaccess v6\x0");
		istnt = 1;
	} else if ( strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 20 56 35 2E 33 9E", 59) == 0 ) {
		strcpy(current.providername,"Ziggo NL\x0");
		if ( !strncmp(znl_boxkey, "0", 1) == 0 ) {
			memcpy(reader->boxkey, znl_boxkey, 9);
			memcpy(reader->rsa_mod, znl_rsakey, 65);
			reader->boxkey_length = 8;
			reader->rsa_mod_length = 64;
		}
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 12 | reader->blockemm);
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 38 32 20 52 65 76 52 32 36 1C", 80) == 0 ) {
		strcpy(current.providername,"Max TV\x0");
		if ( !strncmp(max_cwpk, "0", 1) == 0 ) {
			memcpy(reader->data50, data50,  80);
			memcpy(reader->mod50,  mod50,  80);
			memcpy(reader->key60,  key60,  96);
			memcpy(reader->exp60,  exp60,  96);
			memcpy(reader->mod1,   mod1, 112);
			memcpy(reader->nuid,   max_nuid,   4);
			memcpy(reader->cwekey0, max_cwpk,  16);

			reader->data50_length =  80;
			reader->mod50_length  =  80;
			reader->key60_length  =  96;
			reader->exp60_length  =  96;
			reader->mod1_length   = 112;
			reader->nuid_length   =   4;
			reader->cwekey0_length =  16;
		}
		reader->saveemm = ( 0 | reader->saveemm);
		reader->blockemm = ( 8 | reader->blockemm);
	} else {
		current.found = 0;
	}

	if ( current.found == 1 ) {
		if ( ishdold == 1 ) {
			// Astra HD01 / HD02
			if ( !strncmp(hd_rsakey, "0", 1) == 0 ) {
				memcpy(reader->boxkey, hd_boxkey, 9);
				memcpy(reader->rsa_mod, hd_rsakey, 65);
				reader->boxkey_length = 8;
				reader->rsa_mod_length = 64;
			}
			reader->saveemm = ( 0 | reader->saveemm);
			reader->blockemm = ( 12 | reader->blockemm);
		} else if ( ishdnew == 1 ) {
			// Astra HD03 / HD03a / HD03b / HD04 / HD04a
			if ( !strncmp(hd_cwpk, "0", 1) == 0 ) {
				memcpy(reader->data50, data50,   80);
				memcpy(reader->mod50,   mod50,   80);
				memcpy(reader->key60,   key60,   96);
				memcpy(reader->exp60,   exp60,   96);
				memcpy(reader->mod1,    mod1,   112);
				memcpy(reader->nuid,    hd_nuid,  4);
				memcpy(reader->cwekey0,  hd_cwpk, 16);

				reader->data50_length =  80;
				reader->mod50_length  =  80;
				reader->key60_length  =  96;
				reader->exp60_length  =  96;
				reader->mod1_length   = 112;
				reader->nuid_length   =   4;
				reader->cwekey0_length =  16;
			}
			reader->saveemm = ( 0 | reader->saveemm);
			reader->blockemm = ( 8 | reader->blockemm);
		} else if ( isum == 1 ) {
			if ( !strncmp(um_rsakey, "0", 1) == 0 ) {
				memcpy(reader->boxkey, um_boxkey, 9);
				memcpy(reader->rsa_mod, um_rsakey, 65);
				reader->boxkey_length = 8;
				reader->rsa_mod_length = 64;
			}
			reader->saveemm = ( 0 | reader->saveemm);
			reader->blockemm = ( 12 | reader->blockemm);
		} else if ( istivu == 1 ) {
			if ( !strncmp(tivu_rsakey, "0", 1) == 0 ) {
				memcpy(reader->rsa_mod, tivu_rsakey, 120);
				reader->rsa_mod_length = 120;
			}
			reader->saveemm = ( 0 | reader->saveemm);
			reader->blockemm = ( 8 | reader->blockemm);
		} else if ( istnt == 1 ) {
			if ( !strncmp(tnt_deskey, "0", 1) == 0 ) {
				memcpy(reader->boxkey, tnt_boxkey, 4);
				memcpy(reader->des_key, tnt_deskey, 16);
				reader->boxkey_length = 4;
				reader->des_key_length = 16;
			}
			memcpy(reader->pincode, "0000\0", 5);
			reader->saveemm = ( 0 | reader->saveemm);
			reader->blockemm = ( 0 | reader->blockemm);
		}
	} else {
		int i;
		char buf[66];
		for( i = 10; i < 17; i++ ) {
			// Check for Sky 19.2 E Sat
			snprintf(buf, 66, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
			if ( strncmp(current.atr, buf, 65) == 0 ) {
				strcpy(current.providername,"Sky Deutschland V13\x0");
				reader->disablecrccws = 1;
				reader->saveemm = ( 1 | reader->saveemm);
				reader->blockemm = 15;
				reader->boxid = 0x12345678;
				reader->caid = 0x09C4;
				current.found = 1;
				break;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if ( strncmp(current.atr, buf, 62) == 0 ) {
				strcpy(current.providername,"Sky Deutschland V14\x0");
				reader->saveemm = ( 1 | reader->saveemm);
				reader->blockemm = 15;
				reader->boxid = 0x12345678;
				reader->disablecrccws = 1;
				reader->caid = 0x098C;
				current.found = 1;
				break;
			}

			snprintf(buf, 63, "3F FD %i 25 02 50 80 0F 55 B0 02 69 FF 4A 50 F0 80 00 50 31 03", i);
			if ( strncmp(current.atr, buf, 62) == 0 ) {
				strcpy(current.providername,"Sky Deutschland V15\x0");
				reader->saveemm = ( 1 | reader->saveemm);
				reader->blockemm = 15;
				reader->boxid = 0x12345678;
				reader->disablecrccws = 1;
				reader->caid = 0x098D;
				current.found = 1;
				break;
			}

			snprintf(buf, 66, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if ( strncmp(current.atr, buf, 65) == 0 ) {
				strcpy(current.providername,"Sky/Unitymedia V23\x0");
				reader->saveemm = ( 0 | reader->saveemm);
				reader->blockemm = ( 12 | reader->blockemm);
				reader->boxid = 0x12345678;
				current.found = 1;
				break;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if ( strncmp(current.atr, buf, 62) == 0 ) {
				strcpy(current.providername,"Vodafone G09\x0");
				reader->saveemm = ( 0 | reader->saveemm);
				reader->blockemm = ( 12 | reader->blockemm);
				reader->boxid = 0x12345678;
				reader->deprecated = 1;
				current.found = 1;
				break;
			}
		}
	}
	if ( current.found == 1 ) {
		if(reader->grp < 1) { reader->grp = 0x1ULL; }
	}
	return;
}
