struct known_cards {
//custom name output on webif log
	char providername[32];
	/*
	EMM_UNIQUE: 1
	EMM_SHARED: 2
	EMM_GLOBAL: 4
	EMM_UNKNOWN: 8
	SUM EMM for Value
	*/
	int saveemm;
	int blockemm;
//max atrsize incl. spaces
	char atr[80];
	int atrsize;
//fill in boxkey and rsakey if required
	int  boxid;
	char boxkey[9];
	char rsakey[129];
	char deskey[33];
	char aeskeys[1024];
}

orfice	 =	{ "ORF ICE CW-Mode", 0, 12, "3B 78 12 00 00 54 C4 03 00 8F F1 90 00",        38, 0, "\x00", "\x00", "\x00", "" },
cdnl	 =	{ "CANAL DIGITAAL (NL)", 3, 12, "3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6", 42, 0, "\x00", "\x00", "\x00", "" },
vf_g09	 =	{ "Vodafone G09", 0, 12, "3F FD 11 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03",   62, 12345678, "\x00", "\x00", "\x00", ""},
skyDEv14 =	{ "Sky Deutschland V14", 1, 15, "3F FD 13 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03",    62, 12345678, "\x00", "\x00", "\x00", "" },
skyDEv13 =	{ "Sky Deutschland V13", 1, 15, "3F FF 11 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 11", 65, 12345678, "\x00", "\x00", "\x00", "" },
skyUMv23 =	{ "Sky/Unitymedia V23", 0, 12, "3F FF 14 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", 65, 12345678, "\x00", "\x00", "\x00", ""},
unity_01 =	{ "Unitymedia 01", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15", 80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\xB5\x5E\x0E\xB0\x56\x28\x05\xF1\x78\x8B\xDA\x0C\xD8\xB8\x56\xBF\x69\x6C\xFF\x1C\xBF\x4E\xD6\x2B\x85\xE6\x43\xF3\x85\xB0\xF8\x89\x92\x75\xDE\xA6\x69\xAC\x77\xBD\xA4\x3A\x20\xCC\xB8\x44\xA3\xAF\x5A\x2B\xE0\x62\x27\x79\xFA\xB1\x53\xD1\x56\x95\x7D\xF3\x67\xFF\x00", "\x00", "" },
unity_02 =	{ "Unitymedia 02", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12", 80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\xB5\x5E\x0E\xB0\x56\x28\x05\xF1\x78\x8B\xDA\x0C\xD8\xB8\x56\xBF\x69\x6C\xFF\x1C\xBF\x4E\xD6\x2B\x85\xE6\x43\xF3\x85\xB0\xF8\x89\x92\x75\xDE\xA6\x69\xAC\x77\xBD\xA4\x3A\x20\xCC\xB8\x44\xA3\xAF\x5A\x2B\xE0\x62\x27\x79\xFA\xB1\x53\xD1\x56\x95\x7D\xF3\x67\xFF\x00", "\x00", "" },
hdplus01 =	{ "HD-Plus 01", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61",    80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\xBF\x35\x8B\x54\x61\x86\x31\x30\x68\x6F\xC9\x33\xFB\x54\x1F\xFC\xED\x68\x2F\x36\x80\xF0\x9D\xBC\x1A\x23\x82\x9F\xB3\xB2\xF7\x66\xB9\xDD\x1B\xF3\xB3\xEC\xC9\xAD\x66\x61\xB7\x53\xDC\xC3\xA9\x62\x41\x56\xF9\xEB\x64\xE8\x16\x8E\xF0\x9E\x4D\x9C\x5C\xCA\x4D\xD5\x00", "\x00", "" },
hdplus02 =	{ "HD-Plus 02", 0, 12, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28",    80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\xBF\x35\x8B\x54\x61\x86\x31\x30\x68\x6F\xC9\x33\xFB\x54\x1F\xFC\xED\x68\x2F\x36\x80\xF0\x9D\xBC\x1A\x23\x82\x9F\xB3\xB2\xF7\x66\xB9\xDD\x1B\xF3\xB3\xEC\xC9\xAD\x66\x61\xB7\x53\xDC\xC3\xA9\x62\x41\x56\xF9\xEB\x64\xE8\x16\x8E\xF0\x9E\x4D\x9C\x5C\xCA\x4D\xD5\x00", "\x00", "" },
hdplus03 =	{ "HD-Plus 03", 0, 12, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 39 30 20 4D 65 72 51 32 35 4F",    80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\x90\x1E\x59\x51\x52\xE6\x7D\xFD\x5B\x13\x4E\x1D\x19\x5C\x41\x41\xB3\xBB\x13\x94\xA8\xAF\x4D\x6B\xF1\xD1\x08\x5D\xCC\x4D\x9C\xBA\x5C\x73\xA0\x6E\xD2\x1F\xC3\x55\x6B\x68\x54\x98\x03\x0B\xB1\x18\x57\x66\x11\x75\x65\xE3\x99\x95\xEF\xBF\x72\x13\x5C\x28\x17\xB7\x00", "\x00", "" },
redlight =	{ "Redlight Elite", 0, 0, "3F 77 18 00 00 C2 EB 41 02 6C 90 00",                                                   30, 0, "\x01\x4D\x90\x2F\x00", "\x00", "\x22\xD6\x0F\x37\x56\x7B\xAB\x12\xF5\x05\xD8\xC8\xC7\x1A\x22\xE3\x00", "" },
tntviav5 =	{ "TNT Viaccess V5", 0, 0, "3F 77 18 00 00 C2 EB 41 02 6C",                                                   30, 0, "\x01\x4D\x90\x2F\x00", "\x00", "\x22\xD6\x0F\x37\x56\x7B\xAB\x12\xF5\x05\xD8\xC8\xC7\x1A\x22\xE3\x00", "0500@030B00:439726EBB6A939A456C05FF6AA606C43,F1DCB15A3DE3FA1D7E2998DA7DD4898A,48C19B86A4E2EB7288DFDCE7C2BB7577,0,0,0,0,0,0,0,0,0,9A3EAB0203EBFFCA85B4F18280749F56,2504B382B16D8C6758DB960E311E9351,349883E54D58336DCA750A878ACC5CD5,4A26AD251795A58A11BBC07B53C44348,2844258792F6D9529A328B3E8CD2FD0E,F62C3BE300E98BBB378DFA38BB6EEEF1,0,0,6B1B024D36F60974973CB81FA5E8F01C,127003F8E95100367A556121C779FB6E,9D73BE61D6498E2F20E157E1C6416A23,1DE5B042AD670BB16A3A76BDAD2F7AC0,6747F2E500CF123428337591435C6585" },
tntviav6 =	{ "TNT Viaccess V6", 0, 0, "3F 77 18 00 00 D3 8A 40 01 64",                                                   30, 0, "\x01\x4D\x90\x2F\x00", "\x00", "\x22\xD6\x0F\x37\x56\x7B\xAB\x12\xF5\x05\xD8\xC8\xC7\x1A\x22\xE3\x00", "0500@030B00:439726EBB6A939A456C05FF6AA606C43,F1DCB15A3DE3FA1D7E2998DA7DD4898A,48C19B86A4E2EB7288DFDCE7C2BB7577,0,0,0,0,0,0,0,0,0,9A3EAB0203EBFFCA85B4F18280749F56,2504B382B16D8C6758DB960E311E9351,349883E54D58336DCA750A878ACC5CD5,4A26AD251795A58A11BBC07B53C44348,2844258792F6D9529A328B3E8CD2FD0E,F62C3BE300E98BBB378DFA38BB6EEEF1,0,0,6B1B024D36F60974973CB81FA5E8F01C,127003F8E95100367A556121C779FB6E,9D73BE61D6498E2F20E157E1C6416A23,1DE5B042AD670BB16A3A76BDAD2F7AC0,6747F2E500CF123428337591435C6585" };

struct atrlist {
	int found;
	char providername[32];
	char atr[80];
} current = { 0, "\0", "\0" };

void findatr(struct s_reader *reader) {
	current.found = 0;
	memset(current.providername, 0, 32);
	if ( strncmp(current.atr, hdplus01.atr, hdplus01.atrsize) == 0 ) {
		memcpy(current.providername, hdplus01.providername, strlen(hdplus01.providername));
		memcpy(reader->boxkey, hdplus01.boxkey, 9);
		memcpy(reader->rsa_mod, hdplus01.rsakey, 129);
		reader->saveemm = hdplus01.saveemm;
		reader->blockemm = hdplus01.blockemm;
		current.found = 1;
	} else if ( strncmp(current.atr, hdplus02.atr, hdplus02.atrsize) == 0 ) {
		memcpy(current.providername, hdplus02.providername, strlen(hdplus02.providername));
		memcpy(reader->boxkey, hdplus02.boxkey, 9);
		memcpy(reader->rsa_mod, hdplus02.rsakey, 129);
		reader->saveemm = hdplus02.saveemm;
		reader->blockemm = hdplus02.blockemm;
		current.found = 1;
	} else if ( strncmp(current.atr, hdplus03.atr, hdplus03.atrsize) == 0 ) {
		memcpy(current.providername, hdplus03.providername, strlen(hdplus03.providername));
		memcpy(reader->boxkey, hdplus03.boxkey, 9);
		memcpy(reader->rsa_mod, hdplus03.rsakey, 129);
		reader->saveemm = hdplus03.saveemm;
		reader->blockemm = hdplus03.blockemm;
		current.found = 1;
	} else if ( strncmp(current.atr, unity_01.atr, unity_01.atrsize) == 0 ) {
		memcpy(current.providername, unity_01.providername, strlen(unity_01.providername));
		memcpy(reader->boxkey, unity_01.boxkey, 9);
		memcpy(reader->rsa_mod, unity_01.rsakey, 129);
		reader->saveemm = unity_01.saveemm;
		reader->blockemm = unity_01.blockemm;
		current.found = 1;
	} else if ( strncmp(current.atr, unity_02.atr, unity_02.atrsize) == 0 ) {
		memcpy(current.providername, unity_02.providername, strlen(unity_02.providername));
		memcpy(reader->boxkey, unity_02.boxkey, 9);
		memcpy(reader->rsa_mod, unity_02.rsakey, 129);
		reader->saveemm = unity_02.saveemm;
		reader->blockemm = unity_02.blockemm;
		current.found = 1;
	} else if ( strncmp(current.atr, redlight.atr, redlight.atrsize) == 0 ) {
		memcpy(current.providername, redlight.providername, strlen(redlight.providername));
		memcpy(reader->boxkey, redlight.boxkey, 5);
		memcpy(reader->des_key, redlight.deskey, 33);
		memcpy(reader->pincode, "0000\0", 5);
		reader->des_key_length = 16;
		current.found = 1;
	} else if ( strncmp(current.atr, tntviav5.atr, tntviav5.atrsize) == 0 ) {
		memcpy(current.providername, tntviav5.providername, strlen(tntviav5.providername));
		memcpy(reader->boxkey, tntviav5.boxkey, 5);
		memcpy(reader->des_key, tntviav5.deskey, 33);
		memcpy(reader->pincode, "0000\0", 5);
		parse_aes_keys(reader, tntviav5.aeskeys);
		reader->des_key_length = 16;
		current.found = 1;
	} else if ( strncmp(current.atr, tntviav6.atr, tntviav6.atrsize) == 0 ) {
		memcpy(current.providername, tntviav6.providername, strlen(tntviav6.providername));
		memcpy(reader->boxkey, tntviav6.boxkey, 5);
		memcpy(reader->des_key, tntviav6.deskey, 33);
		memcpy(reader->pincode, "0000\0", 5);
		parse_aes_keys(reader, tntviav6.aeskeys);
		reader->des_key_length = 16;
		current.found = 1;
	}
	/* test ATR for ins7e11 11,12,13,14,15 */
	if ( current.found == 0 ) {
		int i;
		char buf[66];
		for( i = 10; i < 16; i++ ) {
			snprintf(buf, skyDEv13.atrsize+1, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
			if ( strncmp(current.atr, buf, skyDEv13.atrsize) == 0 ) {
				memcpy(current.providername, skyDEv13.providername, strlen(skyDEv13.providername));
				reader->saveemm = skyDEv13.saveemm;
				reader->blockemm = skyDEv13.blockemm;
				reader->boxid = skyDEv13.boxid;
				current.found = 1;
				break;
			}
			snprintf(buf, skyDEv14.atrsize+1, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if ( strncmp(current.atr, buf, skyDEv14.atrsize) == 0 ) {
				memcpy(current.providername, skyDEv14.providername, strlen(skyDEv14.providername));
				reader->saveemm = skyDEv14.saveemm;
				reader->blockemm = skyDEv14.blockemm;
				reader->boxid = skyDEv14.boxid;
				current.found = 1;
				break;
			}
			snprintf(buf, skyUMv23.atrsize+1, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if ( strncmp(current.atr, buf, skyUMv23.atrsize) == 0 ) {
				memcpy(current.providername, skyUMv23.providername, strlen(skyUMv23.providername));
				reader->saveemm = skyUMv23.saveemm;
				reader->blockemm = skyUMv23.blockemm;
				reader->boxid = skyUMv23.boxid;
				current.found = 1;
				break;
			}
			snprintf(buf, vf_g09.atrsize+1, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if ( strncmp(current.atr, buf, vf_g09.atrsize) == 0 ) {
				memcpy(current.providername, vf_g09.providername, strlen(vf_g09.providername));
				reader->saveemm = vf_g09.saveemm;
				reader->blockemm = vf_g09.blockemm;
				reader->boxid = vf_g09.boxid;
				current.found = 1;
				break;
			}
		}
	}
}


