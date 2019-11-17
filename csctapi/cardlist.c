#include <string.h>
#include "../globals.h"
#include "cardlist.h"

//
//
// Some legal data for cards
//
//

#ifdef READER_NAGRA_MERLIN
static const char data50[81]       = { "\x00" };
static const char mod50[81]        = { "\x00" };
//static const char key3460[97]      = { "\x00" };
//static const char key3310[17]      = { "\x00" };
static const char mod1[113]        = { "\x00" };
//static const char mod2[113]        = { "\x00" };
//static const char cmd0eprov[3]     = { "\x00" };
static const char hd_cwpk[17]      = { "\x00" };
static const char hd_nuid[5]       = { "\x00" };
static const char hd_key3588[137]  = { "\x00" };
//static const char hd_idird[5]      = { "\x00" };
static const char max_cwpk[17]     = { "\x00" };
static const char max_nuid[5]      = { "\x00" };
#endif
#ifdef READER_NAGRA
static const char hd_boxkey[9]     = { "\x00" };
static const char hd_rsakey[129]   = { "\x00" };
static const char tivu_rsakey[121] = { "\x00" };
static const char um_boxkey[9]     = { "\x00" };
static const char um_rsakey[129]   = { "\x00" };
static const char vf_boxkey[9]     = { "\x00" };
static const char vf_rsakey[129]   = { "\x00" };
#endif
#ifdef READER_VIACCESS
static const char rlme_boxkey[5]   = { "\x00" };
static const char rlme_deskey[17]  = { "\x00" };
static const char rlmr_boxkey[5]   = { "\x00" };
static const char rlmr_deskey[17]  = { "\x00" };
static const char tnt_boxkey[5]    = { "\x00" };
static const char tnt_deskey[17]   = { "\x00" };
#endif
#ifdef READER_IRDETO
static const char znl_boxkey[9]    = { "\x00" };
static const char znl_rsakey[65]   = { "\x00" };
#endif

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

struct atrlist current = { 1, "\0", "\0", "\0" };

void findatr(struct s_reader *reader) {
	current.found = 1;
	strcpy(current.info, "\x0");
	int ishdold = 0;
	int ishdnew = 0;
	int istivu = 0;
	int istnt = 0;
	int isum = 0;

	if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 34 63", 80) == 0 ) {
		// HD+ 01 RevGC4
		ishdold = 1;
		strcpy(current.providername,"Astra HD+ HD01\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61", 80) == 0 ) {
		// HD+ 01 RevGC6
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
		// HD+ 04a|b
		ishdnew = 1;
		strcpy(current.providername,"Astra HD+ HD04a|b\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 34 13", 80) == 0 ) {
		// HD+ 04h
		ishdnew = 1;
		strcpy(current.providername,"Astra HD+ HD04h\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 35 30 20 52 65 76 57 36 30 14", 80) == 0 ) {
		// HD+ 05a
		ishdnew = 1;
		strcpy(current.providername,"Astra HD+ HD05\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15", 80) == 0 ) {
		// UM01
		isum = 1;
		strcpy(current.providername,"Unitymedia UM01\x0");
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12", 80) == 0 ) {
		// UM02
		isum = 1;
		strcpy(current.providername,"Unitymedia UM02\x0");
	} else if ( strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 03 84 55 FF 80 6D", 59) == 0 ) {
#ifdef READER_NAGRA
		strcpy(current.providername,"Vodafone D0x Ix2\x0");
		if ( strlen(vf_rsakey) > 0 ) {
			memcpy(reader->boxkey,	vf_boxkey,	  9);
			memcpy(reader->rsa_mod, vf_rsakey,	 65);
			
			reader->boxkey_length	=   8;
			reader->rsa_mod_length	=  64;
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + rsakey");
		}
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= (12 | reader->blockemm);
#else
		strcpy(current.info, "- but card system NAGRA not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3F 77 18 00 00 C2 EB 41 02 6C 90 00", 35) == 0 ) {
#ifdef READER_VIACCESS
		strcpy(current.providername,"Redlight Mega Elite\x0");
		if ( strlen(rlme_deskey) > 0 ) {
			memcpy(reader->boxkey,	rlme_boxkey,  5);
			memcpy(reader->des_key, rlme_deskey, 17);
			
			reader->boxkey_length	=   4;
			reader->des_key_length	=  16;
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + deskey");
		}
		memcpy(reader->pincode, "0000\0", 5);
		reader->disablecrccws		= 1;
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= (12 | reader->blockemm);
#else
		strcpy(current.info, "- but card system VIACCESS not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3F 77 18 00 00 D3 8A 42 01 64 90 00", 35) == 0 ) {
#ifdef READER_VIACCESS
		strcpy(current.providername,"Redlight Mega Royale\x0");
		if ( strlen(rlmr_deskey) > 0 ) {
			memcpy(reader->boxkey,	rlmr_boxkey,  5);
			memcpy(reader->des_key, rlmr_deskey, 17);

			reader->boxkey_length	=   4;
			reader->des_key_length	=  16;
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + deskey");
		}
		memcpy(reader->pincode, "0000\0", 5);
		reader->disablecrccws		= 1;
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= (12 | reader->blockemm);
#else
		strcpy(current.info, "- but card system VIACCESS not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3B 24 00 30 42 30 30", 20) == 0 ) {
#ifdef READER_CONAX
		strcpy(current.providername,"MTV Unlimited\x0");
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= ( 8 | reader->blockemm);
#else
		strcpy(current.info, "- but card system CONAX not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3B 78 12 00 00 54 C4 03 00 8F F1 90 00", 38) == 0 ) {
#ifdef READER_CRYPTOWORKS
		strcpy(current.providername,"Cryptoworks\x0");
		reader->needsglobalfirst 	= 1;
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= ( 8 | reader->blockemm);
#else
		strcpy(current.info, "- but card system CRYPTOWORKS not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6", 42) == 0 ) {
#ifdef READER_SECA
		strcpy(current.providername,"Canal Digitaal (NL)\x0");
		reader->caid 				= 0x0100;
		reader->ratelimitecm 		= 4;
		reader->ratelimittime 		= 9000;
		reader->saveemm				= ( 3 | reader->saveemm);
		reader->blockemm			= (12 | reader->blockemm);
#else
		strcpy(current.info, "- but card system SECA not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FF 47 00 54 49 47 45 52 30 30 33 20 52 65 76 32 35 30 64", 80) == 0 ) {
		strcpy(current.providername,"Tivusat 183D\x0");
		istivu = 1;
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 38 37 14", 80) == 0 ) {
		strcpy(current.providername,"Tivusat 183E\x0");
		istivu = 1;
	} else if ( strncmp(current.atr, "3F 77 18 00 00 C2 7A 41 02 68", 29) == 0 ) {
#ifdef READER_VIACCESS
		strcpy(current.providername,"SRG v4\x0");
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= ( 8 | reader->blockemm);
#else
		strcpy(current.info, "- but card system VIACCESS not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3F 77 18 00 00 C2 7A 44 02 68", 29) == 0 ) {
#ifdef READER_VIACCESS
		strcpy(current.providername,"SRG v5\x0");
		reader->read_old_classes	= 0;
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= ( 8 | reader->blockemm);
#else
		strcpy(current.info, "- but card system VIACCESS not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3F 77 18 00 00 D3 8A 40 01 64", 29) == 0 ) {
#ifdef READER_VIACCESS
		strcpy(current.providername,"SRG v6\x0");
		reader->read_old_classes	= 0;
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= ( 8 | reader->blockemm);
#else
		strcpy(current.info, "- but card system VIACCESS not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3F 77 18 00 00 C2 EB 41 02 6C", 29) == 0 ) {
		strcpy(current.providername,"TNT Viaccess v5\x0");
		istnt = 1;
	} else if ( strncmp(current.atr, "3F 77 18 00 00 D3 8A 40 01 64", 29) == 0 ) {
		strcpy(current.providername,"TNT Viaccess v6\x0");
		istnt = 1;
	} else if ( strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 20 56 35 2E 33 9E", 59) == 0 ) {
#ifdef READER_IRDETO
		strcpy(current.providername,"Ziggo NL\x0");
		if ( strlen(znl_boxkey) > 0 ) {
			memcpy(reader->boxkey,	znl_boxkey,	  9);
			memcpy(reader->rsa_mod,	znl_rsakey,  65);
			
			reader->boxkey_length	=   8;
			reader->rsa_mod_length	=  64;
		} else {
			rdr_log(reader, "no keys built in, use config values boxkey + rsakey");
		}
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= (12 | reader->blockemm);
#else
		strcpy(current.info, "- but card system IRDETO not built in!\x0");
#endif
	} else if ( strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 38 32 20 52 65 76 52 32 36 1C", 80) == 0 ) {
#ifdef READER_NAGRA_MERLIN
		strcpy(current.providername,"Max TV\x0");
		if ( strlen(max_cwpk) > 0 ) {
			memcpy(reader->data50,	data50,		 81);
			memcpy(reader->mod50,	mod50,  	 81);
			memcpy(reader->mod1,	mod1, 		113);
			memcpy(reader->nuid,	max_nuid,	  5);
			memcpy(reader->cwekey,	max_cwpk,	 17);

		} else {
			rdr_log(reader, "no keys built in, use config values data50 + mod50 + mod1 + nuid + cwekey");
		}
		reader->saveemm				= ( 0 | reader->saveemm);
		reader->blockemm			= ( 8 | reader->blockemm);
#else
		strcpy(current.info, "- but card system NAGRA_MERLIN not built in!\x0");
#endif
	} else {
		current.found = 0;
	}

	if ( current.found == 1 ) {
		if ( ishdold == 1 ) {
#ifdef READER_NAGRA
			// Astra HD01 / HD02
			if ( strlen(hd_rsakey) > 0 ) {
				memcpy(reader->boxkey, 	hd_boxkey, 	  9);
				memcpy(reader->rsa_mod, hd_rsakey, 	 65);
				
				reader->boxkey_length	=   8;
				reader->rsa_mod_length	=  64;
			} else {
				rdr_log(reader, "no keys built in, use config values boxkey + rsakey");
			}
			reader->cak7_mode			= 0;
			reader->saveemm				= ( 0 | reader->saveemm);
			reader->blockemm			= (12 | reader->blockemm);
#else
			strcpy(current.info, "- but card system NAGRA not built in!\x0");
#endif
		} else if ( ishdnew == 1 ) {
#ifdef READER_NAGRA_MERLIN
			// Astra HD03 / HD03a / HD03b / HD04 / HD04a / HD04b / HD04h / HD05a
			if ( strlen(hd_cwpk) > 0 ) {
				memcpy(reader->data50,  data50,      81);
				memcpy(reader->mod50,   mod50,       81);
				memcpy(reader->mod1,    mod1,       113);
				memcpy(reader->nuid,    hd_nuid,      5);
				memcpy(reader->cwekey,  hd_cwpk,     17);
				memcpy(reader->key3588, hd_key3588, 137);
				
			} else {
				rdr_log(reader, "no keys built in, use config values data50 + mod50 + mod1 + nuid + cwekey + key3588");
			}
			reader->cak7_mode			= 1;
			reader->saveemm				= ( 0 | reader->saveemm);
			reader->blockemm			= ( 8 | reader->blockemm);
#else
			strcpy(current.info, "- but card system NAGRA_MERLIN not built in!\x0");
#endif
		} else if ( isum == 1 ) {
#ifdef READER_NAGRA
			// Unitymedia UM01 / UM02
			if ( strlen(um_rsakey) > 0 ) {
				memcpy(reader->boxkey, 	um_boxkey, 	  9);
				memcpy(reader->rsa_mod, um_rsakey, 	 65);
				
				reader->boxkey_length	=   8;
				reader->rsa_mod_length	=  64;
			} else {
				rdr_log(reader, "no keys built in, use config values boxkey + rsakey");
			}
			reader->saveemm				= ( 0 | reader->saveemm);
			reader->blockemm			= (12 | reader->blockemm);
#else
			strcpy(current.info, "- but card system NAGRA not built in!\x0");
#endif
		} else if ( istivu == 1 ) {
#ifdef READER_NAGRA
			// Tivusat 183D / 183E
			if ( strlen(tivu_rsakey) > 0 ) {
				memcpy(reader->rsa_mod, tivu_rsakey, 	121);
				
				reader->rsa_mod_length	= 120;
			} else {
				rdr_log(reader, "no keys built in, use config value rsakey");
			}
			reader->saveemm				= ( 0 | reader->saveemm);
			reader->blockemm			= ( 8 | reader->blockemm);
#else
			strcpy(current.info, "- but card system NAGRA not built in!\x0");
#endif
		} else if ( istnt == 1 ) {
#ifdef READER_VIACCESS
			// TNT Viaccess v5 / v6
			if ( strlen(tnt_deskey) > 0 ) {
				memcpy(reader->boxkey, 	tnt_boxkey, 	  5);
				memcpy(reader->des_key, tnt_deskey, 	 17);
				
				reader->boxkey_length	=   4;
				reader->des_key_length	=  16;
			} else {
				rdr_log(reader, "no keys built in, use config values boxkey + deskey");
			}
			memcpy(reader->pincode, "0000\0", 5);
			reader->saveemm				= ( 0 | reader->saveemm);
			reader->blockemm			= ( 0 | reader->blockemm);
#else
			strcpy(current.info, "- but card system VIACCESS not built in!\x0");
#endif
		}
	} else {
		int i;
		char buf[66];
		for( i = 10; i < 17; i++ ) {
			// Check for Sky 19.2 E Sat
			snprintf(buf, 66, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
#ifdef READER_VIDEOGUARD
			if ( strncmp(current.atr, buf, 65) == 0 ) {
				strcpy(current.providername,"Sky Deutschland V13\x0");
				reader->caid				= 0x09C4;
				reader->disablecrccws		= 1;
				if ( !reader->boxid ) {reader->boxid = 0x12345678;}
				reader->saveemm				= ( 1 | reader->saveemm);
				reader->blockemm			= 15;
				current.found = 1;
				break;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if ( strncmp(current.atr, buf, 62) == 0 ) {
				strcpy(current.providername,"Sky Deutschland V14\x0");
				reader->caid				= 0x098C;
				reader->disablecrccws		= 1;
				if ( !reader->boxid ) {reader->boxid = 0x12345678;}
				reader->saveemm				= ( 1 | reader->saveemm);
				reader->blockemm			= 15;
				current.found = 1;
				break;
			}

			snprintf(buf, 63, "3F FD %i 25 02 50 80 0F 55 B0 02 69 FF 4A 50 F0 80 00 50 31 03", i);
			if ( strncmp(current.atr, buf, 62) == 0 ) {
				strcpy(current.providername,"Sky Deutschland V15\x0");
				reader->caid				= 0x098D;
				reader->disablecrccws		= 1;
				if ( !reader->boxid ) {reader->boxid = 0x12345678;}
				reader->saveemm				= ( 1 | reader->saveemm);
				reader->blockemm			= 15;
				current.found = 1;
				break;
			}

			snprintf(buf, 66, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if ( strncmp(current.atr, buf, 65) == 0 ) {
				strcpy(current.providername,"Sky/Unitymedia V23\x0");
				if ( !reader->boxid ) {reader->boxid = 0x12345678;}
				reader->saveemm				= ( 0 | reader->saveemm);
				reader->blockemm			= (12 | reader->blockemm);
				current.found = 1;
				break;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if ( strncmp(current.atr, buf, 62) == 0 ) {
				strcpy(current.providername,"Vodafone G09\x0");
				if ( !reader->boxid ) {reader->boxid = 0x12345678;}
				reader->saveemm				= ( 0 | reader->saveemm);
				reader->blockemm			= (12 | reader->blockemm);
				reader->deprecated = 1;
				current.found = 1;
				break;
			}
#else
			strcpy(current.info, "- but card system VIDEOGUARD not built in!\x0");
#endif
		}
	}
	if ( current.found == 1 ) {
		if(reader->grp < 1) { reader->grp = 0x1ULL; }
	}
	return;
}
