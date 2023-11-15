#ifndef __NDS_COMMON__
#define __NDS_COMMON__

#define write_cmd_vg(cmd, data) (card_write(reader, cmd, data, cta_res, &cta_lr) == 0)

#define NDSUNKNOWN 0
#define NDSAUTO    0
#define NDS1       1
#define NDS12     12
#define NDS2       2

struct s_CmdTabEntry
{
	uint8_t cla;
	uint8_t cmd;
	uint8_t len;
	uint8_t mode;
};

struct s_CmdTab
{
	uint8_t index;
	uint8_t size;
	uint8_t Nentries;
	uint8_t dummy;
	struct s_CmdTabEntry e[1];
};

struct videoguard_data
{
	const char      *card_desc;
	int32_t         card_baseyear;
	int32_t         card_tierstart;
	int32_t         card_system_version;
	time_t          card_valid_to;
	struct s_CmdTab *cmd_table;
	uint16_t        cardkeys[3][32];
	uint8_t         stateD3A[16];
	AES_KEY         ekey;
	AES_KEY         astrokey;
};

typedef struct nds_atr
{
	uint8_t atr[MAX_ATR_LEN];
	uint16_t atr_len;
	int32_t base_year;
	int32_t tier_start;
	int32_t nds_version;
	const char *desc;
} NDS_ATR_ENTRY;

extern int32_t cw_is_valid(uint8_t *cw);
extern void cAES_SetKey(struct s_reader *reader, const uint8_t *key);

extern void __xxor(uint8_t *data, int32_t len, const uint8_t *v1, const uint8_t *v2);
#define xor16(v1,v2,d) __xxor((d),16,(v1),(v2))
#define val_by2on3(x) ((0xaaab*(x))>>16) // fixed point *2/3

extern void cCamCryptVG_SetSeed(struct s_reader *reader);
extern void cCamCryptVG_GetCamKey(struct s_reader *reader, uint16_t *tb2);
extern int32_t status_ok(const uint8_t *status);
extern int32_t checksum_ok(const uint8_t *ird_payload);
extern void memorize_cmd_table(struct s_reader *reader, const uint8_t *mem, int32_t size);
extern int32_t cmd_table_get_info(struct s_reader *reader, const uint8_t *cmd, uint8_t *rlen, uint8_t *rmode);
extern int32_t cmd_exists(struct s_reader *reader, const uint8_t *cmd);
extern int32_t read_cmd_len(struct s_reader *reader, const uint8_t *cmd);
extern int32_t do_cmd(struct s_reader *reader, const uint8_t *ins, const uint8_t *txbuff, uint8_t *rxbuff, uint8_t *cta_res);
int32_t videoguard_do_rawcmd(struct s_reader *reader, CMD_PACKET *cp);
extern void rev_date_calc_tm(const uint8_t *Date, struct tm *timeinfo , int32_t base_year);
extern void set_known_card_info(struct s_reader *reader, const uint8_t *atr, const uint32_t *atr_size);

int32_t videoguard_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr);
int32_t videoguard_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **, unsigned int *);
int32_t videoguard_do_emm(struct s_reader *reader, EMM_PACKET *ep, uint8_t CLA, void (*read_tiers)(struct s_reader *),
						  int32_t (*docmd)(struct s_reader *, const uint8_t *ins, const uint8_t *txbuff, uint8_t *rxbuff, uint8_t *cta_res)
						 );
void videoguard_mail_msg(struct s_reader *rdr, uint8_t *data);

#endif // __NDS_COMMON__
