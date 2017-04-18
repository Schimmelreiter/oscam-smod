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

orfice	 =	{ "ORF ICE CW-Mode\0", 0, 12, "3B 78 12 00 00 54 C4 03 00 8F F1 90 00",        38, 0, "\0", "\0" },
cdnl	 =	{ "CANAL DIGITAAL (NL)\0", 3, 12, "3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6", 42, 0, "\0", "\0" },
kbw_v23  =	{ "Kabel-BW V23\0",        0, 12, "3F FF 14 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", 65, 12345678, "\0", "\0"},
kdg9	 =	{ "Kabel Deutschland G9\0", 0, 12, "3F FD 11 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03",   62, 12345678, "\0", "\0"},
skyDEv14 =	{ "Sky Deutschland V14\0", 1, 15, "3F FD 13 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03",    62, 12345678, "\0", "\0" },
skyDEv13 =	{ "Sky Deutschland V13\0", 1, 15, "3F FF 11 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 11", 65, 12345678, "\0", "\0" },
unity_01 =	{ "Unity Media 01\0", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15", 80, 0, "\x00", "\x00" },
unity_02 =	{ "Unity Media 02\0", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12", 80, 0, "\x00", "\x00" },
hdplus01 =	{ "HD-Plus 01\0", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61",     80, 0, "\x00", "\x00" },
hdplus02 =	{ "HD-Plus 02\0", 0, 12, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28",     80, 0, "\x00", "\x00" };
struct atrlist {
	int found;
	char providername[32];
	char atr[80];
} current = { 0, "\0", "\0" };

void findatr(struct s_reader *reader)
{
	current.found = 0;
	if ( strncmp(current.atr, hdplus01.atr, hdplus01.atrsize) == 0 ) {
		strncpy(current.providername, hdplus01.providername, strlen(hdplus01.providername));
		memcpy(reader->boxkey, hdplus01.boxkey, 9);
		memcpy(reader->rsa_mod, hdplus01.rsakey, 129);
		reader->saveemm = hdplus01.saveemm;
		reader->blockemm = hdplus01.blockemm;
		current.found = 1;
	} else if ( strncmp(current.atr, hdplus02.atr, hdplus02.atrsize) == 0 ) {
		strncpy(current.providername, hdplus02.providername, strlen(hdplus02.providername));
		memcpy(reader->boxkey, hdplus01.boxkey, 9);
		memcpy(reader->rsa_mod, hdplus01.rsakey, 129);
		reader->saveemm = hdplus02.saveemm;
		reader->blockemm = hdplus02.blockemm;
		current.found = 1;
	} else if ( strncmp(current.atr, unity_01.atr, unity_01.atrsize) == 0 ) {
		strncpy(current.providername, hdplus01.providername, strlen(hdplus01.providername));
		memcpy(reader->boxkey, unity_01.boxkey, 9);
		memcpy(reader->rsa_mod, unity_01.rsakey, 129);
		reader->saveemm = unity_01.saveemm;
		reader->blockemm = unity_01.blockemm;
		current.found = 1;
	} else if ( strncmp(current.atr, unity_02.atr, unity_02.atrsize) == 0 ) {
		strncpy(current.providername, hdplus02.providername, strlen(hdplus02.providername));
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
				strncpy(current.providername, skyDEv13.providername, strlen(skyDEv13.providername));
				reader->saveemm = skyDEv13.saveemm;
				reader->blockemm = skyDEv13.blockemm;
				reader->boxid = skyDEv13.boxid;
				current.found = 1;
				break;
			}
			snprintf(buf, skyDEv14.atrsize+1, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if ( strncmp(current.atr, buf, skyDEv14.atrsize) == 0 ) {
				strncpy(current.providername, skyDEv14.providername, strlen(skyDEv14.providername));
				reader->saveemm = skyDEv14.saveemm;
				reader->blockemm = skyDEv14.blockemm;
				reader->boxid = skyDEv14.boxid;
				current.found = 1;
				break;
			}
			snprintf(buf, kbw_v23.atrsize+1, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if ( strncmp(current.atr, buf, kbw_v23.atrsize) == 0 ) {
				strncpy(current.providername, kbw_v23.providername, strlen(kbw_v23.providername));
				reader->saveemm = kbw_v23.saveemm;
				reader->blockemm = kbw_v23.blockemm;
				reader->boxid = kbw_v23.boxid;
				current.found = 1;
				break;
			}
			snprintf(buf, kdg9.atrsize+1, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if ( strncmp(current.atr, buf, kdg9.atrsize) == 0 ) {
				strncpy(current.providername, kdg9.providername, strlen(kdg9.providername));
				reader->saveemm = kdg9.saveemm;
				reader->blockemm = kdg9.blockemm;
				reader->boxid = kdg9.boxid;
				current.found = 1;
				break;
			}
		}
	}
}
