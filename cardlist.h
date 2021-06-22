#ifndef _CSCTAPI_CARDLIST_H_
#define _CSCTAPI_CARDLIST_H_

#ifdef WITH_CARDLIST
extern struct atrlist current;
struct atrlist{ int found; char providername[32]; char atr[80]; char info[50];};
void findatr(struct s_reader *reader);
#endif // WITH_CARDLIST

#endif
