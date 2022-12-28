#include "../globals.h"

#ifdef CARDREADER_SMARGO
#include "../oscam-time.h"
#include "icc_async.h"
#include "io_serial.h"

#if defined(__CYGWIN__)
#undef OK
#undef ERROR
#undef LOBYTE
#undef HIBYTE
#endif

#define OK 0
#define ERROR 1
#define LOBYTE(w) ((unsigned char)((w) & 0xff))
#define HIBYTE(w) ((unsigned char)((w) >> 8))

#define SMARGO_DELAY 150

static void smargo_set_config_mode_on(struct s_reader *reader)
{
	struct termios term;

	tcgetattr(reader->handle, &term);
	term.c_cflag &= ~CSIZE;
	term.c_cflag |= CS5;
	tcsetattr(reader->handle, TCSANOW, &term);

	cs_sleepms(SMARGO_DELAY);
}

static void smargo_set_config_mode_off(struct s_reader *reader)
{
	struct termios term;

	cs_sleepms(SMARGO_DELAY);

	tcgetattr(reader->handle, &term);
	term.c_cflag &= ~CSIZE;
	term.c_cflag |= CS8;
	tcsetattr(reader->handle, TCSANOW, &term);
}

static int32_t smargo_set_settings(struct s_reader *reader, int32_t freq, unsigned char T, unsigned char inv, uint16_t Fi, unsigned char Di, unsigned char Ni)
{
	uint16_t freqk = (freq * 10);
	uint8_t data[4];

	smargo_set_config_mode_on(reader);

	rdr_log_dbg(reader, D_DEVICE, "sending F=%04X (%d), D=%02X (%d), Freq=%04X (%d), N=%02X (%d), T=%02X (%d), inv=%02X (%d)",
				   Fi, Fi, Di, Di, freqk, freqk, Ni, Ni, T, T, inv, inv);

	if(T != 14 || freq == 369)
	{
		data[0] = 0x01;
		data[1] = HIBYTE(Fi);
		data[2] = LOBYTE(Fi);
		data[3] = Di;
		IO_Serial_Write(reader, 0, 1000, 4, data);
	}

	data[0] = 0x02;
	data[1] = HIBYTE(freqk);
	data[2] = LOBYTE(freqk);
	IO_Serial_Write(reader, 0, 1000, 3, data);

	data[0] = 0x03;
	data[1] = Ni;
	IO_Serial_Write(reader, 0, 1000, 2, data);

	data[0] = 0x04;
	data[1] = T;
	IO_Serial_Write(reader, 0, 1000, 2, data);

	data[0] = 0x05;
	data[1] = inv;
	IO_Serial_Write(reader, 0, 1000, 2, data);

	smargo_set_config_mode_off(reader);

	return OK;
}

static int32_t smargo_write_settings(struct s_reader *reader, struct s_cardreader_settings *s)
{
	return smargo_set_settings(reader, reader->mhz, reader->protocol_type == 1 ? 0 : reader->protocol_type , reader->convention, s->Fi, s->D, s->Ni);
}


static int32_t smargo_init(struct s_reader *reader)
{
	reader->handle = open(reader->device,  O_RDWR);

	if(reader->handle < 0)
	{
		rdr_log(reader, "ERROR: Opening device %s (errno=%d %s)", reader->device, errno, strerror(errno));
		return ERROR;
	}

	if(IO_Serial_SetParams(reader, DEFAULT_BAUDRATE, 8, PARITY_EVEN, 2, NULL, NULL))
		{ return ERROR; }

	IO_Serial_RTS_Set(reader);
	IO_Serial_DTR_Set(reader);
	IO_Serial_Flush(reader);

	return OK;
}

static int32_t smargo_Serial_Read(struct s_reader *reader, uint32_t timeout, uint32_t size, unsigned char *data, int32_t *read_bytes)
{
	uint32_t count = 0;
	uint32_t bytes_read = 0;

	for(count = 0; count < size ; count += bytes_read)
	{
		if(IO_Serial_WaitToRead(reader, 0, timeout) == OK)
		{
			if((bytes_read = read(reader->handle, data + count, size - count)) < 1)
			{
				int saved_errno = errno;
				rdr_log_dump_dbg(reader, D_DEVICE, data, count, "Receiving:");
				rdr_log(reader, "ERROR: %s (errno=%d %s)", __func__, saved_errno, strerror(saved_errno));
				return ERROR;
			}
		}
		else
		{
			rdr_log_dump_dbg(reader, D_DEVICE, data, count, "Receiving:");
			rdr_log_dbg(reader, D_DEVICE, "Timeout in IO_Serial_Read");
			*read_bytes = count;
			return ERROR;
		}
	}
	rdr_log_dump_dbg(reader, D_DEVICE, data, count, "Receiving:");
	return OK;
}

static int32_t smargo_fast_reset_by_atr(struct s_reader *reader, ATR *atr)
{
	int32_t ret = ERROR;
	unsigned char buf[ATR_MAX_SIZE];
	int32_t n = 0;
	int8_t atr_len = 0;

	if(reader->seca_nagra_card == 1)
	{
		atr_len = reader->card_atr_length; // this is a special case the data buffer has only the atr length.
	}
	else
	{
		atr_len = reader->card_atr_length + 2; // data buffer has atr length + 2 bytes
	}

	IO_Serial_Read(reader, 0, 500000, atr_len, buf);

	IO_Serial_RTS_Set(reader);
	cs_sleepms(150);
	IO_Serial_RTS_Clr(reader);

	smargo_Serial_Read(reader, ATR_TIMEOUT, atr_len + 1, buf, &n);

	if(ATR_InitFromArray(atr, buf, n) != ERROR)
	{
		rdr_log_dbg(reader, D_DEVICE, "SR: ATR parsing OK");
		ret = OK;
	}

	return ret;
}

static int32_t smargo_reset(struct s_reader *reader, ATR *atr)
{
	rdr_log_dbg(reader, D_IFD, "Resetting card");
	int32_t ret = ERROR;
	int32_t i;
	unsigned char buf[ATR_MAX_SIZE];

	int32_t parity[4] = {PARITY_EVEN, PARITY_ODD, PARITY_NONE, PARITY_EVEN};

	int32_t mhz = 369;

	if(reader->mhz == reader->cardmhz && reader->cardmhz > 369)
		{ mhz = reader->cardmhz; }

	for(i = 0; i < 4; i++)
	{
		if(i == 3)  // hack for irdeto cards
			{ smargo_set_settings(reader, 600, 1, 0, 618, 1, 0); }
		else
			{ smargo_set_settings(reader, mhz, 0, 0, 372, 1, 0); }

		call(IO_Serial_SetParity(reader, parity[i]));

		//IO_Serial_Flush(reader);

		IO_Serial_Read(reader, 0, 500000, ATR_MAX_SIZE, buf);

		IO_Serial_RTS_Set(reader);
		cs_sleepms(150);
		IO_Serial_RTS_Clr(reader);

		int32_t n = 0;

		smargo_Serial_Read(reader, ATR_TIMEOUT, ATR_MAX_SIZE, buf, &n);

		if(n == 0 || buf[0] == 0)
			{ continue; }

		rdr_log_dump_dbg(reader, D_IFD, buf, n, "ATR: %d bytes", n);

		if((buf[0] != 0x3B && buf[0] != 0x03 && buf[0] != 0x3F) || (buf[1] == 0xFF && buf[2] == 0x00))
			{ continue; } // this is not a valid ATR

		if(ATR_InitFromArray(atr, buf, n) != ERROR)
		{
			ret = OK;
			break;
		}
	}

	int32_t convention;

	ATR_GetConvention(atr, &convention);
	// If inverse convention, switch here due to if not PTS will fail
	if(convention == ATR_CONVENTION_INVERSE)
	{
		uint8_t data[4];

		smargo_set_config_mode_on(reader);

		data[0] = 0x05;
		data[1] = 0x01;
		IO_Serial_Write(reader, 0, 1000, 2, data);

		smargo_set_config_mode_off(reader);
	}

	return ret;
}

int32_t smargo_activate(struct s_reader *reader, struct s_ATR *atr)
{
	if(!reader->ins7e11_fast_reset)
	{
		call(smargo_reset(reader, atr));
	}
	else
	{
		rdr_log_dbg(reader, D_DEVICE, "Fast card reset with atr");
		call(smargo_fast_reset_by_atr(reader, atr));
	}
	return OK;
}

const struct s_cardreader cardreader_smargo =
{
	.desc            = "smargo",
	.typ             = R_MOUSE,
	.max_clock_speed = 1,
	.reader_init     = smargo_init,
	.activate        = smargo_activate,
	.write_settings  = smargo_write_settings,
	.get_status      = IO_Serial_GetStatus,
	.transmit        = IO_Serial_Transmit,
	.receive         = IO_Serial_Receive,
	.close           = IO_Serial_Close,
	.set_parity      = IO_Serial_SetParity,
};

#endif
