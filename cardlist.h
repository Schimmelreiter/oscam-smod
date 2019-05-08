#ifndef _CSCTAPI_CARDLIST_H_
#define _CSCTAPI_CARDLIST_H_
struct atrlist{ int found; char providername[32]; char atr[80]; };
void findatr(struct s_reader *reader);
#endif
