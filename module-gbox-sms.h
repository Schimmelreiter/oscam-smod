#ifndef MODULE_GBOX_SMS_H_
#define MODULE_GBOX_SMS_H_

#ifdef MODULE_GBOX

#define FILE_GSMS_TXT  "gsms.txt"
#define FILE_GSMS_MSG  "gsms.log"
#define FILE_OSD_MSG   "gsms.osd"
#define FILE_GSMS_ACK  "gsms.ack"
#define FILE_GSMS_NACK "gsms.nack"

void gbox_init_send_gsms(void);
void write_gsms_msg(struct s_client *cli, uint8_t *gsms, uint16_t type, uint16_t UNUSED(msglen));
void gbox_send_gsms_ack(struct s_client *cli);
int  gbox_direct_send_gsms(uint16_t boxid, uint8_t num, char *gsms);
void gbox_get_online_peers(void);
void write_gsms_ack(struct s_client *cli);
void gsms_unavail(void);

#endif

#endif
