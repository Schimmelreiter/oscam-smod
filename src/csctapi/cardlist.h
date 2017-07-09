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
}

orfice	 =	{ "ORF ICE CW-Mode", 0, 12, "3B 78 12 00 00 54 C4 03 00 8F F1 90 00",        38, 0, "\x00", "\x00" },
cdnl	 =	{ "CANAL DIGITAAL (NL)", 3, 12, "3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6", 42, 0, "\x00", "\x00" },
vf_g09	 =	{ "Vodafone G09", 0, 12, "3F FD 11 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03",   62, 12345678, "\x00", "\x00"},
skyDEv14 =	{ "Sky Deutschland V14", 1, 15, "3F FD 13 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03",    62, 12345678, "\x00", "\x00" },
skyDEv13 =	{ "Sky Deutschland V13", 1, 15, "3F FF 11 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 11", 65, 12345678, "\x00", "\x00" },
skyUMv23  =	{ "Sky/Unitymedia V23", 0, 12, "3F FF 14 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", 65, 12345678, "\x00", "\x00"},
unity_01 =	{ "Unitymedia 01", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15", 80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\xB5\x5E\x0E\xB0\x56\x28\x05\xF1\x78\x8B\xDA\x0C\xD8\xB8\x56\xBF\x69\x6C\xFF\x1C\xBF\x4E\xD6\x2B\x85\xE6\x43\xF3\x85\xB0\xF8\x89\x92\x75\xDE\xA6\x69\xAC\x77\xBD\xA4\x3A\x20\xCC\xB8\x44\xA3\xAF\x5A\x2B\xE0\x62\x27\x79\xFA\xB1\x53\xD1\x56\x95\x7D\xF3\x67\xFF\x00" },
unity_02 =	{ "Unitymedia 02", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12", 80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\xB5\x5E\x0E\xB0\x56\x28\x05\xF1\x78\x8B\xDA\x0C\xD8\xB8\x56\xBF\x69\x6C\xFF\x1C\xBF\x4E\xD6\x2B\x85\xE6\x43\xF3\x85\xB0\xF8\x89\x92\x75\xDE\xA6\x69\xAC\x77\xBD\xA4\x3A\x20\xCC\xB8\x44\xA3\xAF\x5A\x2B\xE0\x62\x27\x79\xFA\xB1\x53\xD1\x56\x95\x7D\xF3\x67\xFF\x00" },
hdplus01 =	{ "HD-Plus 01", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61",     80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\xBF\x35\x8B\x54\x61\x86\x31\x30\x68\x6F\xC9\x33\xFB\x54\x1F\xFC\xED\x68\x2F\x36\x80\xF0\x9D\xBC\x1A\x23\x82\x9F\xB3\xB2\xF7\x66\xB9\xDD\x1B\xF3\xB3\xEC\xC9\xAD\x66\x61\xB7\x53\xDC\xC3\xA9\x62\x41\x56\xF9\xEB\x64\xE8\x16\x8E\xF0\x9E\x4D\x9C\x5C\xCA\x4D\xD5\x00" },
hdplus02 =	{ "HD-Plus 02", 0, 12, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28",     80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C\x00", "\xBF\x35\x8B\x54\x61\x86\x31\x30\x68\x6F\xC9\x33\xFB\x54\x1F\xFC\xED\x68\x2F\x36\x80\xF0\x9D\xBC\x1A\x23\x82\x9F\xB3\xB2\xF7\x66\xB9\xDD\x1B\xF3\xB3\xEC\xC9\xAD\x66\x61\xB7\x53\xDC\xC3\xA9\x62\x41\x56\xF9\xEB\x64\xE8\x16\x8E\xF0\x9E\x4D\x9C\x5C\xCA\x4D\xD5\x00" };
struct atrlist {
	int found;
	char providername[32];
	char atr[80];
} current = { 0, "\0", "\0" };

void findatr(struct s_reader *reader)
{
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

