#ifndef OSCAM_CHK_H_
#define OSCAM_CHK_H_

// betatunnel check (chk_on_btun)
#define SRVID_ZERO 0 // srvid + 0000 (used for service-filter bypass)
#define SRVID_MASK 1 // srvid + FFFF

uint32_t get_fallbacktimeout(uint16_t caid);
int32_t ecm_ratelimit_check(struct s_reader *reader, ECM_REQUEST *er, int32_t reader_mode);
int32_t matching_reader(ECM_REQUEST *er, struct s_reader *rdr);
uint8_t chk_if_ignore_checksum(ECM_REQUEST *er, FTAB *disablecrc_only_for);

uint8_t is_localreader(struct s_reader *rdr, ECM_REQUEST *er);
uint8_t chk_is_fixed_fallback(struct s_reader *rdr, ECM_REQUEST *er);
uint8_t chk_has_fixed_fallback(ECM_REQUEST *er);
int32_t chk_srvid_match(ECM_REQUEST *er, SIDTAB *sidtab);
int32_t chk_srvid(struct s_client *cl, ECM_REQUEST *er);
int32_t has_srvid(struct s_client *cl, ECM_REQUEST *er);
int32_t has_lb_srvid(struct s_client *cl, ECM_REQUEST *er);
int32_t chk_srvid_match_by_caid_prov(uint16_t caid, uint32_t provid, SIDTAB *sidtab);
int32_t chk_srvid_by_caid_prov(struct s_client *cl, uint16_t caid, uint32_t provid);
int32_t chk_srvid_by_caid_prov_rdr(struct s_reader *rdr, uint16_t caid, uint32_t provid);
int32_t chk_is_betatunnel_caid(uint16_t caid);
uint16_t chk_on_btun(uint8_t chk_sx, struct s_client *cl, ECM_REQUEST *er);
int32_t chk_ident_filter(uint16_t rcaid, uint32_t rprid, FTAB *ftab);
int32_t chk_sfilter(ECM_REQUEST *er, PTAB *ptab);
int32_t chk_ufilters(ECM_REQUEST *er);
int32_t chk_rsfilter(struct s_reader *reader, ECM_REQUEST *er);
int32_t chk_rfilter2(uint16_t rcaid, uint32_t rprid, struct s_reader *rdr);
int32_t chk_ctab(uint16_t caid, CAIDTAB *ctab);
int32_t chk_ctab_ex(uint16_t caid, CAIDTAB *ctab);
int32_t chk_caid(uint16_t caid, CAIDTAB *ctab);
int32_t chk_caid_rdr(struct s_reader *rdr, uint16_t caid);
int32_t chk_bcaid(ECM_REQUEST *er, CAIDTAB *ctab);
int32_t chk_is_null_CW(uint8_t cw[]);
int8_t is_halfCW_er(ECM_REQUEST *er);
int8_t chk_halfCW(ECM_REQUEST *er, uint8_t *cw);
int32_t chk_is_null_nodeid(uint8_t node_id[], uint8_t len);
bool check_client(struct s_client *cl);
uint16_t caidvaluetab_get_value(CAIDVALUETAB *cv, uint16_t caid, uint16_t default_value);
int32_t chk_is_fakecw(uint8_t *cw);
#ifdef CS_CACHEEX_AIO
int32_t chk_srvid_disablecrccws_only_for_exception(ECM_REQUEST *er);
int32_t chk_srvid_no_wait_time(ECM_REQUEST *er);
int32_t chk_srvid_localgenerated_only_exception(ECM_REQUEST *er);
bool chk_nopushafter(uint16_t caid, CAIDVALUETAB *cv, int32_t ecm_time);
uint8_t chk_lg_only(ECM_REQUEST *er, FTAB *ftab);
uint8_t chk_lg_only_cp(uint16_t caid, uint32_t prid, FTAB *lg_only_ftab);
#endif
#endif
