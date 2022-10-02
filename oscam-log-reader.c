#define MODULE_LOG_PREFIX "reader"

#include "globals.h"

#include "oscam-log.h"
#include "oscam-log-reader.h"
#include "oscam-reader.h"
#include "oscam-string.h"

extern int log_remove_sensitive;

static char *debug_mask_txt(int mask)
{
	switch(mask)
	{
		case D_EMM:
			return "EMM: ";

		case D_IFD:
			return "IFD: ";

		case D_TRACE:
			return "TRACE: ";

		case D_DEVICE:
			return "IO: ";

		default:
			return "";
	}
}

static const char *reader_desc_txt(struct s_reader *reader)
{
	if(reader->csystem && reader->csystem->desc)
		{ return reader->csystem->desc; }
	else if(reader->crdr && reader->crdr->desc)
		{ return reader->crdr->desc; }
	else if(reader->ph.desc)
		{ return reader->ph.desc; }
	else
		{ return reader_get_type_desc(reader, 1); }
}

static char *format_sensitive(char *result, int remove_sensitive)
{
	// Filter sensitive information
	int i, n = cs_strlen(result), p = 0;
	if(remove_sensitive)
	{
		int in_sens = 0;
		for(i = 0; i < n; i++)
		{
			switch(result[i])
			{
				case '{':
					in_sens = 1;
					continue;

				case '}':
					in_sens = 0;
					break;
			}

			if(in_sens)
				{ result[i] = '#'; }
		}
	}

	// Filter sensitive markers
	for(i = 0; i < n; i++)
	{
		if(result[i] == '{' || result[i] == '}')
			{ continue; }

		result[p++] = result[i];
	}
	result[p] = '\0';
	return result;
}

void rdr_log(struct s_reader *reader, char *fmt, ...)
{
	char txt[256];
	va_list args;
	va_start(args, fmt);
	vsnprintf(txt, sizeof(txt), fmt, args);
	va_end(args);
	cs_log("%s [%s] %s", reader->label, reader_desc_txt(reader), txt);
}

void rdr_log_sensitive(struct s_reader *reader, char *fmt, ...)
{
	char txt[256];
	va_list args;
	va_start(args, fmt);
	vsnprintf(txt, sizeof(txt), fmt, args);
	va_end(args);
	format_sensitive(txt, log_remove_sensitive);
	rdr_log(reader, "%s", txt);
}

void rdr_log_dbg(struct s_reader *reader, uint16_t mask, char *fmt, ...)
{
	if(config_enabled(WITH_DEBUG))
	{
		char txt[2048];
		va_list args;
		va_start(args, fmt);
		vsnprintf(txt, sizeof(txt), fmt, args);
		va_end(args);
		cs_log_dbg(mask, "%s [%s] %s%s", reader->label, reader_desc_txt(reader), debug_mask_txt(mask), txt);
	}
}

void rdr_log_dbg_sensitive(struct s_reader *reader, uint16_t mask, char *fmt, ...)
{
	if(config_enabled(WITH_DEBUG))
	{
		char txt[2048];
		va_list args;
		va_start(args, fmt);
		vsnprintf(txt, sizeof(txt), fmt, args);
		va_end(args);
		format_sensitive(txt, log_remove_sensitive);
		rdr_log_dbg(reader, mask, "%s", txt);
	}
}

void rdr_log_dump(struct s_reader *reader, const uint8_t *buf, int n, char *fmt, ...)
{
	char txt[2048];
	va_list args;
	va_start(args, fmt);
	vsnprintf(txt, sizeof(txt), fmt, args);
	va_end(args);
	cs_log_dump(buf, n, "%s [%s] %s", reader->label, reader_desc_txt(reader), txt);
}

void rdr_log_dump_dbg(struct s_reader *reader, uint16_t mask, const uint8_t *buf, int n, char *fmt, ...)
{
	if(config_enabled(WITH_DEBUG))
	{
		char txt[2048];
		va_list args;
		va_start(args, fmt);
		vsnprintf(txt, sizeof(txt), fmt, args);
		va_end(args);
		cs_log_dump_dbg(mask, buf, n, "%s [%s] %s%s", reader->label, reader_desc_txt(reader), debug_mask_txt(mask), txt);
	}
}
