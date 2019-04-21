#ifndef _CSCTAPI_CARDLIST_H_
#define _CSCTAPI_CARDLIST_H_

struct known_cards
{
	char providername[32];
//max atrsize incl. spaces
	char atr[80];
	int atrsize;
}
mtv = { "MTV UNLIMITED","3B 24 00 30 42 30 30",20 },
srg = { "SRG v5","3F 77 18 00 00 C2 7A 44 02 68 90 00",35 },
orfice = { "ORF ICE","3B 78 12 00 00 54 C4 03 00 8F F1 90 00",38 },
cdnl = { "CANAL DIGITAAL (NL)","3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6",42 },
kbw_v23 = { "Kabel-BW V23","3F FF 14 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00",65 },
kdg9 = { "Kabel Deutschland G0x","3F FD 11 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03",62 },
skyDEv14 = { "Sky Deutschland V14","3F FD 13 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03",62 },
skyDEv13 = { "Sky Deutschland V13","3F FF 11 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 11",65 },
tivusatd = { "Tivusat 183D","3F FF 95 00 FF 91 81 71 FF 47 00 54 49 47 45 52 30 30 33 20 52 65 76 32 35 30 64",80 },
tivusate = { "Tivusat 183E","3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 38 37 14",80 },
rlmega = { "Redlight Mega Elite","3F 77 18 00 00 C2 EB 41 02 6C 90 00",35 },
rlmegar = { "Redlight Mega Royale","3F 77 18 00 00 D3 8A 42 01 64 90 00",35 },
kdg_02 = { "Kabel Deutschland D0x Ix2","3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 03 84 55 FF 80 6D",59 },
hdplus01  = { "HD-Plus 01","3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61",80 },
hdplus02  = { "HD-Plus 02","3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28",80 },
hdplus03  = { "HD-Plus 03","3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 39 30 20 4D 65 72 51 32 35 4F",80 },
hdplus03a = { "HD-Plus 3A","3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 31 30 20 52 65 76 51 32 35 17",80 },
hdplus03b = { "HD-Plus 03","3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 51 32 35 17",80 },
hdplus04  = { "HD-Plus 04","3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 30 17",80 },
hdplus04a = { "HD-Plus 04","3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 34 13",80 },
unity_01  = { "Unity Media 01","3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15",80 },
unity_02  = { "Unity Media 02","3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12",80 };

struct atrlist
{
	int found;
	int ishd03;
	int badcard;
	int ishd04;
	char providername[32];
	char atr[80];
} current = { 0, 0, 0, 0, "\0", "\0" };

void findatr(struct s_reader *reader)
{
	current.found  = 0;
	current.ishd03 = 0;
	current.ishd04 = 0;

	memset(current.providername, 0, 32);
	if ( strncmp(current.atr, hdplus01.atr, hdplus01.atrsize) == 0 )
	{
		memcpy(current.providername, hdplus01.providername, strlen(hdplus01.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus02.atr, hdplus02.atrsize) == 0 )
	{
		memcpy(current.providername, hdplus02.providername, strlen(hdplus02.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus03.atr, hdplus03.atrsize) == 0 )
	{
		current.ishd03=1;
		memcpy(current.providername, hdplus03.providername, strlen(hdplus03.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus03a.atr, hdplus03a.atrsize) == 0 )
	{
		current.ishd03=1;
		current.badcard=1;
		memcpy(current.providername, hdplus03a.providername, strlen(hdplus03a.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus03b.atr, hdplus03b.atrsize) == 0 )
	{
		current.ishd03=1;
		memcpy(current.providername, hdplus03b.providername, strlen(hdplus03b.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus04.atr, hdplus04.atrsize) == 0 )
	{
		current.ishd04=1;
		memcpy(current.providername, hdplus04.providername, strlen(hdplus04.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, hdplus04a.atr, hdplus04a.atrsize) == 0 )
	{
		current.ishd04=1;
		memcpy(current.providername, hdplus04a.providername, strlen(hdplus04a.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, unity_01.atr, unity_01.atrsize) == 0 )
	{
		memcpy(current.providername, unity_01.providername, strlen(unity_01.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, unity_02.atr, unity_02.atrsize) == 0 )
	{
		memcpy(current.providername, unity_02.providername, strlen(unity_02.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, kdg_02.atr, kdg_02.atrsize) == 0 )
	{
		memcpy(current.providername, kdg_02.providername, strlen(kdg_02.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, rlmega.atr, rlmega.atrsize) == 0 )
	{
		memcpy(current.providername, rlmega.providername, strlen(rlmega.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, rlmegar.atr, rlmegar.atrsize) == 0 )
	{
		memcpy(current.providername, rlmegar.providername, strlen(rlmegar.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, mtv.atr, mtv.atrsize) == 0 )
	{
		memcpy(current.providername, mtv.providername, strlen(mtv.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, orfice.atr, orfice.atrsize) == 0 )
	{
		memcpy(current.providername, orfice.providername, strlen(orfice.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, cdnl.atr, cdnl.atrsize) == 0 )
	{
		memcpy(current.providername, cdnl.providername, strlen(cdnl.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, tivusatd.atr, tivusatd.atrsize) == 0 )
	{
		memcpy(current.providername, tivusatd.providername, strlen(tivusatd.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, tivusate.atr, tivusate.atrsize) == 0 )
	{
		memcpy(current.providername, tivusate.providername, strlen(tivusate.providername));
		current.found = 1;
		return;
	}
	else if ( strncmp(current.atr, srg.atr, srg.atrsize) == 0 )
	{
		memcpy(current.providername, srg.providername, strlen(srg.providername));
		reader->read_old_classes = 0;
		current.found = 1;
		return;
	}

	/* test ATR for ins7e11 12,13,14,15 */
	if ( current.found == 0 )
	{
		int i;
		char buf[66];
		for( i = 11; i < 16; i++ )
		{
			snprintf(buf, skyDEv13.atrsize+1, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
			if ( strncmp(current.atr, buf, skyDEv13.atrsize) == 0 )
			{
				memcpy(current.providername, skyDEv13.providername, strlen(skyDEv13.providername));
				reader->caid = 0x09C4;
				current.found = 1;
				break;
			}
			snprintf(buf, skyDEv14.atrsize+1, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if ( strncmp(current.atr, buf, skyDEv14.atrsize) == 0 )
			{
				memcpy(current.providername, skyDEv14.providername, strlen(skyDEv14.providername));
				reader->caid = 0x098C;
				current.found = 1;
				break;
			}
			snprintf(buf, kbw_v23.atrsize+1, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if ( strncmp(current.atr, buf, kbw_v23.atrsize) == 0 )
			{
				memcpy(current.providername, kbw_v23.providername, strlen(kbw_v23.providername));
				current.found = 1;
				break;
			}
			snprintf(buf, kdg9.atrsize+1, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if ( strncmp(current.atr, buf, kdg9.atrsize) == 0 )
			{
				memcpy(current.providername, kdg9.providername, strlen(kdg9.providername));
				current.found = 1;
				break;
			}
		}
	}
}

#endif
#ifndef _CSCTAPI_CARDLIST_H_
#define _CSCTAPI_CARDLIST_H_

struct known_cards {
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

mtv      =      { "MTV UNLIMITED", 0, 8,"3B 24 00 30 42 30 30",20,0, "", "", "", "" },
srg      =      { "SRG v5", 0, 8,"3F 77 18 00 00 C2 7A 44 02 68 90 00",35,0, "", "", "", "" },
orfice	 =	{ "ORF ICE CW-Mode", 0, 12, "3B 78 12 00 00 54 C4 03 00 8F F1 90 00",        38, 0, "", "", "", "" },
cdnl	 =	{ "CANAL DIGITAAL (NL)", 3, 12, "3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6", 42, 0, "", "", "", "" },
vf_d02   =	{ "Vodafone D0x Ix2", 0, 12,"3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 03 84 55 FF 80 6D",                    59, 0, "\x66\x60\xA9\xAE\x55\xA4\x84\x7B", "\x8A\x54\x46\x88\x67\x15\x9C\x11\x88\xD1\x3A\xCE\x7D\xF3\x48\xFA\x08\xBD\xF8\xBE\x33\xF1\xB2\xF7\x2F\x74\xFB\xCD\x18\x4C\x82\x55\x19\xE5\x17\xE3\x49\x4A\x6D\xD8\xCF\x04\x66\x30\x45\x61\x11\xF9\x52\x97\x9D\xEC\xCF\xF5\x17\x6D\x89\x0A\xE9\x3F\x4E\x26\x77\x11", "", "" },
vf_g09	 =	{ "Vodafone G09", 0, 12, "3F FD 11 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03",                    62, 0x12345678, "", "", "", ""},
skyDEv14 =	{ "Sky Deutschland V14", 1, 15, "3F FD 13 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03",             62, 0x12345678, "", "", "", "" },
skyDEv13 =	{ "Sky Deutschland V13", 1, 15, "3F FF 11 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 11",          65, 0x12345678, "", "", "", "" },
skyUMv23 =	{ "Sky/Unitymedia V23", 0, 12, "3F FF 14 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00",           65, 0x12345678, "", "", "", ""},
unity_01 =	{ "Unitymedia 01", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15", 80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C", "\xB5\x5E\x0E\xB0\x56\x28\x05\xF1\x78\x8B\xDA\x0C\xD8\xB8\x56\xBF\x69\x6C\xFF\x1C\xBF\x4E\xD6\x2B\x85\xE6\x43\xF3\x85\xB0\xF8\x89\x92\x75\xDE\xA6\x69\xAC\x77\xBD\xA4\x3A\x20\xCC\xB8\x44\xA3\xAF\x5A\x2B\xE0\x62\x27\x79\xFA\xB1\x53\xD1\x56\x95\x7D\xF3\x67\xFF", "", "" },
unity_02 =	{ "Unitymedia 02", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12", 80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C", "\xB5\x5E\x0E\xB0\x56\x28\x05\xF1\x78\x8B\xDA\x0C\xD8\xB8\x56\xBF\x69\x6C\xFF\x1C\xBF\x4E\xD6\x2B\x85\xE6\x43\xF3\x85\xB0\xF8\x89\x92\x75\xDE\xA6\x69\xAC\x77\xBD\xA4\x3A\x20\xCC\xB8\x44\xA3\xAF\x5A\x2B\xE0\x62\x27\x79\xFA\xB1\x53\xD1\x56\x95\x7D\xF3\x67\xFF", "", "" },
hdplus01 =	{ "HD-Plus 01", 0, 12, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61",    80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C", "\xBF\x35\x8B\x54\x61\x86\x31\x30\x68\x6F\xC9\x33\xFB\x54\x1F\xFC\xED\x68\x2F\x36\x80\xF0\x9D\xBC\x1A\x23\x82\x9F\xB3\xB2\xF7\x66\xB9\xDD\x1B\xF3\xB3\xEC\xC9\xAD\x66\x61\xB7\x53\xDC\xC3\xA9\x62\x41\x56\xF9\xEB\x64\xE8\x16\x8E\xF0\x9E\x4D\x9C\x5C\xCA\x4D\xD5", "", "" },
hdplus02 =	{ "HD-Plus 02", 0, 12, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28",    80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C", "\xBF\x35\x8B\x54\x61\x86\x31\x30\x68\x6F\xC9\x33\xFB\x54\x1F\xFC\xED\x68\x2F\x36\x80\xF0\x9D\xBC\x1A\x23\x82\x9F\xB3\xB2\xF7\x66\xB9\xDD\x1B\xF3\xB3\xEC\xC9\xAD\x66\x61\xB7\x53\xDC\xC3\xA9\x62\x41\x56\xF9\xEB\x64\xE8\x16\x8E\xF0\x9E\x4D\x9C\x5C\xCA\x4D\xD5", "", "" },
hdplus03 =      { "HD-Plus 03", 0, 12, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 39 30 20 4D 65 72 51 32 35 4F",    80, 0, "\xA7\x64\x2F\x57\xBC\x96\xD3\x7C", "\x90\x1E\x59\x51\x52\xE6\x7D\xFD\x5B\x13\x4E\x1D\x19\x5C\x41\x41\xB3\xBB\x13\x94\xA8\xAF\x4D\x6B\xF1\xD1\x08\x5D\xCC\x4D\x9C\xBA\x5C\x73\xA0\x6E\xD2\x1F\xC3\x55\x6B\x68\x54\x98\x03\x0B\xB1\x18\x57\x66\x11\x75\x65\xE3\x99\x95\xEF\xBF\x72\x13\x5C\x28\x17\xB7", "", "" },
hdplus03a =     { "HD-Plus 3A", 0, 12, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 31 30 20 52 65 76 51 32 35 17",    80, 0, "", "", "", "" },
hdplus03b =     { "HD-Plus 03", 0, 12, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 51 32 35 17",    80, 0, "", "", "", "" },
hdplus04  =     { "HD-Plus 04", 0, 12, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 30 17",    80, 0, "", "", "", "" },
hdplus04a =     { "HD-Plus 04", 0, 12, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 34 13",    80, 0, "", "", "", "" },
redlight =	{ "Redlight Mega Elite", 0, 12, "3F 77 18 00 00 C2 EB 41 02 6C 90 00",                                        35, 0, "\x01\x4D\x90\x2F", "\x00", "\x22\xD6\x0F\x37\x56\x7B\xAB\x12\xF5\x05\xD8\xC8\xC7\x1A\x22\xE3", "" },
tivusatd =	{ "Tivusat 183D", 0, 8,"3F FF 95 00 FF 91 81 71 FF 47 00 54 49 47 45 52 30 30 33 20 52 65 76 32 35 30 64",    80, 0, "", "\xA9\x2D\xA7\x2F\xEE\xAC\xF2\x94\x7B\x00\x3E\xD6\x52\x15\x3B\x18\x9E\x40\x43\xB0\x13\x8C\x36\x8B\xDF\x6B\x9E\xD7\x7D\xDA\xD6\xC0\x76\x1A\x21\x98\xAE\xB3\xFC\x97\xA1\x9C\x9D\x01\xCA\x76\x9B\x3F\xFF\xE4\xF6\xE7\x0F\xA4\xE0\x69\x6A\x89\x80\xE1\x8D\x8C\x58\xE1\x1D\x81\x71\x21\x34\x6E\x3E\x66\x45\x7F\xDD\x84\xCF\xA7\x25\x89\xB2\x5B\x53\x8E\xFC\x30\x43\x61\xB5\x48\x45\xF3\x9E\x9E\xFA\x52\xD8\x05\xE5\xFD\x86\xB5\x95\xB3\x66\xC3\x57\x16\xAB\xC9\x1F\xA3\xDC\x15\x9C\x9F\x4D\x81\x64\xB5", "", ""},
tivusate =	{ "Tivusat 183E", 0, 8,"3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 38 37 14",    80, 0, "", "\xA9\x2D\xA7\x2F\xEE\xAC\xF2\x94\x7B\x00\x3E\xD6\x52\x15\x3B\x18\x9E\x40\x43\xB0\x13\x8C\x36\x8B\xDF\x6B\x9E\xD7\x7D\xDA\xD6\xC0\x76\x1A\x21\x98\xAE\xB3\xFC\x97\xA1\x9C\x9D\x01\xCA\x76\x9B\x3F\xFF\xE4\xF6\xE7\x0F\xA4\xE0\x69\x6A\x89\x80\xE1\x8D\x8C\x58\xE1\x1D\x81\x71\x21\x34\x6E\x3E\x66\x45\x7F\xDD\x84\xCF\xA7\x25\x89\xB2\x5B\x53\x8E\xFC\x30\x43\x61\xB5\x48\x45\xF3\x9E\x9E\xFA\x52\xD8\x05\xE5\xFD\x86\xB5\x95\xB3\x66\xC3\x57\x16\xAB\xC9\x1F\xA3\xDC\x15\x9C\x9F\x4D\x81\x64\xB5", "", ""},
tntviav5 =	{ "TNT Viaccess V5", 0, 0, "3F 77 18 00 00 C2 EB 41 02 6C",                                                   30, 0, "\x01\x4D\x90\x2F", "\x00", "\x22\xD6\x0F\x37\x56\x7B\xAB\x12\xF5\x05\xD8\xC8\xC7\x1A\x22\xE3", "0500@030B00:439726EBB6A939A456C05FF6AA606C43,F1DCB15A3DE3FA1D7E2998DA7DD4898A,48C19B86A4E2EB7288DFDCE7C2BB7577,0,0,0,0,0,0,0,0,0,9A3EAB0203EBFFCA85B4F18280749F56,2504B382B16D8C6758DB960E311E9351,349883E54D58336DCA750A878ACC5CD5,4A26AD251795A58A11BBC07B53C44348,2844258792F6D9529A328B3E8CD2FD0E,F62C3BE300E98BBB378DFA38BB6EEEF1,0,0,6B1B024D36F60974973CB81FA5E8F01C,127003F8E95100367A556121C779FB6E,9D73BE61D6498E2F20E157E1C6416A23,1DE5B042AD670BB16A3A76BDAD2F7AC0,6747F2E500CF123428337591435C6585" },
tntviav6 =	{ "TNT Viaccess V6", 0, 0, "3F 77 18 00 00 D3 8A 40 01 64",                                                   30, 0, "\x01\x4D\x90\x2F", "\x00", "\x22\xD6\x0F\x37\x56\x7B\xAB\x12\xF5\x05\xD8\xC8\xC7\x1A\x22\xE3", "0500@030B00:439726EBB6A939A456C05FF6AA606C43,F1DCB15A3DE3FA1D7E2998DA7DD4898A,48C19B86A4E2EB7288DFDCE7C2BB7577,0,0,0,0,0,0,0,0,0,9A3EAB0203EBFFCA85B4F18280749F56,2504B382B16D8C6758DB960E311E9351,349883E54D58336DCA750A878ACC5CD5,4A26AD251795A58A11BBC07B53C44348,2844258792F6D9529A328B3E8CD2FD0E,F62C3BE300E98BBB378DFA38BB6EEEF1,0,0,6B1B024D36F60974973CB81FA5E8F01C,127003F8E95100367A556121C779FB6E,9D73BE61D6498E2F20E157E1C6416A23,1DE5B042AD670BB16A3A76BDAD2F7AC0,6747F2E500CF123428337591435C6585" },
ziggo_nl =	{ "Ziggo NL", 0, 12, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 20 56 35 2E 33 9E",                           59, 0, "\x11\x22\x33\x44\x55\x66\x77\x88", "\x3C\x86\x33\xAA\xC0\xD3\x67\x53\x3D\xEC\x7B\xB2\xEE\xED\xEB\x8C\xA3\xAD\xA5\x2E\x58\xB9\x9B\xB3\x46\x72\x78\x32\x77\xA1\xDA\xAC\x3B\x61\x06\xAD\x09\x09\x77\x4E\x03\x1B\x2A\x6E\x30\x19\x5B\x43\x76\x83\xAD\x0F\xC5\x99\xB8\x7D\x08\xCE\xA4\x7B\xE1\xB6\xC7\x6A", "", "" };

struct atrlist {
	int found;
	int ishd03;
	int badcard;
	int ishd04;
	char providername[32];
	char atr[80];
} current = { 0, 0, 0, 0, "\0", "\0" };

void findatr(struct s_reader *reader) {
	current.found  = 0;
	current.ishd03 = 0;
	current.ishd04 = 0;
	memset(current.providername, 0, 32);
	if ( strncmp(current.atr, hdplus01.atr, hdplus01.atrsize) == 0 ) {
		memcpy(current.providername, hdplus01.providername, strlen(hdplus01.providername));
		memcpy(reader->boxkey, hdplus01.boxkey, 8);
		memcpy(reader->rsa_mod, hdplus01.rsakey, 64);
		reader->saveemm = hdplus01.saveemm;
		reader->blockemm = hdplus01.blockemm;
		reader->boxkey_length = 8;
		reader->rsa_mod_length = 64;
		reader->caid = 0x1830;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, hdplus02.atr, hdplus02.atrsize) == 0 ) {
		memcpy(current.providername, hdplus02.providername, strlen(hdplus02.providername));
		memcpy(reader->boxkey, hdplus02.boxkey, 8);
		memcpy(reader->rsa_mod, hdplus02.rsakey, 64);
		reader->saveemm = hdplus02.saveemm;
		reader->blockemm = hdplus02.blockemm;
		reader->boxkey_length = 8;
		reader->rsa_mod_length = 64;
		reader->caid = 0x1843;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, hdplus03.atr, hdplus03.atrsize) == 0 ) {
		current.ishd03=1;
		memcpy(current.providername, hdplus03.providername, strlen(hdplus03.providername));
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, hdplus03a.atr, hdplus03a.atrsize) == 0 ) {
		current.ishd03=1;
		current.badcard=1;
		memcpy(current.providername, hdplus03a.providername, strlen(hdplus03a.providername));
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, hdplus03b.atr, hdplus03b.atrsize) == 0 ) {
		current.ishd03=1;
		memcpy(current.providername, hdplus03b.providername, strlen(hdplus03b.providername));
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, hdplus04.atr, hdplus04.atrsize) == 0 ) {
		current.ishd04=1;
		memcpy(current.providername, hdplus04.providername, strlen(hdplus04.providername));
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, hdplus04a.atr, hdplus04a.atrsize) == 0 ) {
		current.ishd04=1;
		memcpy(current.providername, hdplus04a.providername, strlen(hdplus04a.providername));
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, vf_d02.atr, vf_d02.atrsize) == 0 ) {
		memcpy(current.providername, vf_d02.providername, strlen(vf_d02.providername));
		memcpy(reader->boxkey, vf_d02.boxkey, 8);
		memcpy(reader->rsa_mod, vf_d02.rsakey, 64);
		reader->boxkey_length = 8;
		reader->rsa_mod_length = 64;
		reader->saveemm = vf_d02.saveemm;
		reader->blockemm = vf_d02.blockemm;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, unity_01.atr, unity_01.atrsize) == 0 ) {
		memcpy(current.providername, unity_01.providername, strlen(unity_01.providername));
		memcpy(reader->boxkey, unity_01.boxkey, 8);
		memcpy(reader->rsa_mod, unity_01.rsakey, 64);
		reader->saveemm = unity_01.saveemm;
		reader->blockemm = unity_01.blockemm;
		reader->boxkey_length = 8;
		reader->rsa_mod_length = 64;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, unity_02.atr, unity_02.atrsize) == 0 ) {
		memcpy(current.providername, unity_02.providername, strlen(unity_02.providername));
		memcpy(reader->boxkey, unity_02.boxkey, 8);
		memcpy(reader->rsa_mod, unity_02.rsakey, 64);
		reader->saveemm = unity_02.saveemm;
		reader->blockemm = unity_02.blockemm;
		reader->boxkey_length = 8;
		reader->rsa_mod_length = 64;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, redlight.atr, redlight.atrsize) == 0 ) {
		memcpy(current.providername, redlight.providername, strlen(redlight.providername));
		memcpy(reader->boxkey, redlight.boxkey, 4);
		memcpy(reader->des_key, redlight.deskey, 16);
		memcpy(reader->pincode, "0000\0", 5);
		reader->saveemm = redlight.saveemm;
		reader->blockemm = redlight.blockemm;
		reader->boxkey_length = 4;
		reader->des_key_length = 16;
		reader->caid = 0x0500;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, mtv.atr, mtv.atrsize) == 0 ) {
		memcpy(current.providername, mtv.providername, strlen(mtv.providername));
		reader->saveemm = mtv.saveemm;
		reader->blockemm = mtv.blockemm;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, orfice.atr, orfice.atrsize) == 0 ) {
		memcpy(current.providername, orfice.providername, strlen(orfice.providername));
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, cdnl.atr, cdnl.atrsize) == 0 ) {
		memcpy(current.providername, cdnl.providername, strlen(cdnl.providername));
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, tntviav5.atr, tntviav5.atrsize) == 0 ) {
		memcpy(current.providername, tntviav5.providername, strlen(tntviav5.providername));
		memcpy(reader->boxkey, tntviav5.boxkey, 4);
		memcpy(reader->des_key, tntviav5.deskey, 16);
		memcpy(reader->pincode, "0000\0", 5);
		parse_aes_keys(reader, tntviav5.aeskeys);
		reader->boxkey_length = 4;
		reader->des_key_length = 16;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, tntviav6.atr, tntviav6.atrsize) == 0 ) {
		memcpy(current.providername, tntviav6.providername, strlen(tntviav6.providername));
		memcpy(reader->boxkey, tntviav6.boxkey, 4);
		memcpy(reader->des_key, tntviav6.deskey, 16);
		memcpy(reader->pincode, "0000\0", 5);
		parse_aes_keys(reader, tntviav6.aeskeys);
		reader->boxkey_length = 4;
		reader->des_key_length = 16;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, ziggo_nl.atr, ziggo_nl.atrsize) == 0 ) {
		memcpy(current.providername, ziggo_nl.providername, strlen(ziggo_nl.providername));
		memcpy(reader->boxkey, ziggo_nl.boxkey, 8);
		memcpy(reader->rsa_mod, ziggo_nl.rsakey, 64);
		reader->saveemm = ziggo_nl.saveemm;
		reader->blockemm = ziggo_nl.blockemm;
		reader->boxkey_length = 8;
		reader->rsa_mod_length = 64;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, tivusatd.atr, tivusatd.atrsize) == 0 ) {
		memcpy(current.providername, tivusatd.providername, strlen(tivusatd.providername));
		memcpy(reader->rsa_mod, tivusatd.rsakey, 120);
		reader->rsa_mod_length = 120;
		reader->saveemm = tivusatd.saveemm;
		reader->blockemm = tivusatd.blockemm;
		reader->caid = 0x183D;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, tivusate.atr, tivusate.atrsize) == 0 ) {
		memcpy(current.providername, tivusate.providername, strlen(tivusate.providername));
		memcpy(reader->rsa_mod, tivusate.rsakey, 120);
		reader->rsa_mod_length = 120;
		reader->saveemm = tivusate.saveemm;
		reader->blockemm = tivusate.blockemm;
		reader->caid = 0x183E;
		current.found = 1;
		return;
	} else if ( strncmp(current.atr, srg.atr, srg.atrsize) == 0 ) {
		memcpy(current.providername, srg.providername, strlen(srg.providername));
		reader->saveemm = tivusate.saveemm;
		reader->blockemm = tivusate.blockemm;
		reader->read_old_classes = 0;
		reader->caid = 0x0500;
		current.found = 1;
		return;
	}

	/* test ATR for ins7e11 12,13,14,15 */
	if ( current.found == 0 ) {
		int i;
		char buf[66];
		for( i = 11; i < 16; i++ ) {
			snprintf(buf, skyDEv13.atrsize+1, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
			if ( strncmp(current.atr, buf, skyDEv13.atrsize) == 0 ) {
				memcpy(current.providername, skyDEv13.providername, strlen(skyDEv13.providername));
				reader->caid = 0x09C4;
				reader->saveemm = skyDEv13.saveemm;
				reader->blockemm = skyDEv13.blockemm;
				reader->boxid = skyDEv13.boxid;
				current.found = 1;
				break;
			}
			snprintf(buf, skyDEv14.atrsize+1, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if ( strncmp(current.atr, buf, skyDEv14.atrsize) == 0 ) {
				memcpy(current.providername, skyDEv14.providername, strlen(skyDEv14.providername));
				reader->caid = 0x098C;
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
				reader->deprecated = 1;
				reader->saveemm = vf_g09.saveemm;
				reader->blockemm = vf_g09.blockemm;
				reader->boxid = vf_g09.boxid;
				current.found = 1;
				break;
			}
		}
	}
}

#endif
