#define MODULE_LOG_PREFIX "dvbstapi"

#include "globals.h"

#if defined(HAVE_DVBAPI) && defined(WITH_STAPI)

#include "module-dvbapi.h"
#include "module-dvbapi-stapi.h"
#include "oscam-client.h"
#include "oscam-files.h"
#include "oscam-string.h"
#include "oscam-time.h"

extern int32_t exit_oscam;

struct STDEVICE
{
	char name[20];
	uint32_t SessionHandle;
	uint32_t SignalHandle;
	pthread_t thread;
	struct filter_s demux_fd[MAX_DEMUX][MAX_FILTER];
};

struct read_thread_param
{
	int32_t id;
	struct s_client *cli;
};

#define BUFFLEN 1024
#define PROCDIR "/proc/stpti4_core/"

/* These functions are in liboscam_stapi.a */
extern uint32_t oscam_stapi_Capability(char *name);
extern char *oscam_stapi_LibVersion(void);
extern uint32_t oscam_stapi_Open(char *name, uint32_t *sessionhandle);
extern uint32_t oscam_stapi_SignalAllocate(uint32_t sessionhandle, uint32_t *signalhandle);
extern uint32_t oscam_stapi_FilterAllocate(uint32_t sessionhandle, uint32_t *filterhandle);
extern uint32_t oscam_stapi_SlotInit(uint32_t sessionhandle, uint32_t signalhandle, uint32_t *bufferhandle, uint32_t *slothandle, uint16_t pid);
extern uint32_t oscam_stapi_FilterSet(uint32_t filterhandle, uint8_t *filt, uint8_t *mask);
extern uint32_t oscam_stapi_FilterAssociate(uint32_t filterhandle, uint32_t slothandle);
extern uint32_t oscam_stapi_SlotDeallocate(uint32_t slothandle);
extern uint32_t oscam_stapi_BufferDeallocate(uint32_t bufferhandle);
extern uint32_t oscam_stapi_FilterDeallocate(uint32_t filterhandle);
extern uint32_t oscam_stapi_Close(uint32_t sessionhandle);
extern uint32_t oscam_stapi_CheckVersion(void);
extern uint32_t oscam_stapi_DescramblerAssociate(uint32_t deschandle, uint32_t slot);
extern uint32_t oscam_stapi_DescramblerDisassociate(uint32_t deschandle, uint32_t slot);
extern uint32_t oscam_stapi_DescramblerAllocate(uint32_t sessionhandle, uint32_t *deschandle);
extern uint32_t oscam_stapi_DescramblerDeallocate(uint32_t deschandle);
extern uint32_t oscam_stapi_DescramblerSet(uint32_t deschandle, int32_t parity, uint8_t *cw);
extern uint32_t oscam_stapi_SignalWaitBuffer(uint32_t signalhandle, uint32_t *qbuffer, int32_t timeout);
extern uint32_t oscam_stapi_BufferReadSection(uint32_t bufferhandle, uint32_t *filterlist, int32_t maxfilter, uint32_t *filtercount, int32_t *crc, uint8_t *buf, int32_t bufsize, uint32_t *size);
extern uint32_t oscam_stapi_SignalAbort(uint32_t signalhandle);
extern uint32_t oscam_stapi_PidQuery(char *name, uint16_t pid);
extern uint32_t oscam_stapi_BufferFlush(uint32_t bufferhandle);
extern uint32_t oscam_stapi_SlotClearPid(uint32_t slot);

// Local functions
static void *stapi_read_thread(void *);
static int32_t stapi_do_set_filter(int32_t demux_id, FILTERTYPE *filter, uint16_t *pids, int32_t pidcount, uint8_t *filt, uint8_t *mask, int32_t dev_id);
static int32_t stapi_do_remove_filter(int32_t demux_id, FILTERTYPE *filter, int32_t dev_id);

// These variables are declared in module-dvbapi.c
extern int32_t disable_pmt_files;
extern struct s_dvbapi_priority *dvbapi_priority;
extern DEMUXTYPE demux[MAX_DEMUX];

static int32_t stapi_on;
static pthread_mutex_t filter_lock;
static struct STDEVICE dev_list[PTINUM];

static void stapi_off(void)
{
	int32_t i;

	SAFE_MUTEX_LOCK(&filter_lock);

	cs_log("stapi shutdown");

	disable_pmt_files = 1;
	stapi_on = 0;
	for(i = 0; i < MAX_DEMUX; i++)
	{
		dvbapi_stop_descrambling(i, 0);
	}

	for(i = 0; i < PTINUM; i++)
	{
		if(dev_list[i].SessionHandle > 0)
		{
			if(dev_list[i].SignalHandle > 0)
			{
				oscam_stapi_SignalAbort(dev_list[i].SignalHandle);
			}
			pthread_cancel(dev_list[i].thread);
		}
	}

	SAFE_MUTEX_UNLOCK(&filter_lock);
	sleep(2);
	return;
}

int32_t stapi_open(void)
{
	uint32_t ErrorCode;

	DIR *dirp;
	struct dirent entry, *dp = NULL;
	struct stat buf;
	int32_t i;
	char pfad[512];
	stapi_on = 1;
	int32_t stapi_priority = 0;

	dirp = opendir(PROCDIR);
	if(!dirp)
	{
		cs_log("opendir failed (errno=%d %s)", errno, strerror(errno));
		return 0;
	}

	memset(dev_list, 0, sizeof(struct STDEVICE)*PTINUM);
	memset(pfad, 0, sizeof(pfad));

	if(dvbapi_priority)
	{
		struct s_dvbapi_priority *p;
		for(p = dvbapi_priority; p != NULL; p = p->next)
		{
			if(p->type == 's')
			{
				stapi_priority = 1;
				break;
			}
		}
	}

	if(!stapi_priority)
	{
		cs_log("WARNING: no PTI devices defined, stapi disabled");
		return 0;
	}

	oscam_stapi_CheckVersion();

	i = 0;
	while(!cs_readdir_r(dirp, &entry, &dp))
	{
		if(!dp)
			break;

		snprintf(pfad, sizeof(pfad), "%s%s", PROCDIR, dp->d_name);
		if(stat(pfad, &buf) != 0)
			{ continue; }

		if(!(buf.st_mode & S_IFDIR && strncmp(dp->d_name, ".", 1) != 0))
			{ continue; }

		int32_t do_open = 0;
		struct s_dvbapi_priority *p;

		for(p = dvbapi_priority; p != NULL; p = p->next)
		{
			if(p->type != 's') { continue; }
			if(strcmp(dp->d_name, p->devname) == 0)
			{
				do_open = 1;
				break;
			}
		}

		if(!do_open)
		{
			cs_log("PTI: %s skipped", dp->d_name);
			continue;
		}

		ErrorCode = oscam_stapi_Open(dp->d_name, &dev_list[i].SessionHandle);
		if(ErrorCode != 0)
		{
			cs_log("STPTI_Open ErrorCode: %d", ErrorCode);
			continue;
		}

		//debug
		//oscam_stapi_Capability(dp->d_name);

		cs_strncpy(dev_list[i].name, dp->d_name, sizeof(dev_list[i].name));
		cs_log("PTI: %s open %d", dp->d_name, i);

		ErrorCode = oscam_stapi_SignalAllocate(dev_list[i].SessionHandle, &dev_list[i].SignalHandle);
		if(ErrorCode != 0)
			{ cs_log("SignalAllocate: ErrorCode: %d SignalHandle: %x", ErrorCode, dev_list[i].SignalHandle); }

		i++;
		if(i >= PTINUM) { break; }
	}
	closedir(dirp);

	if(i == 0) { return 0; }

	SAFE_MUTEX_INIT(&filter_lock, NULL);

	for(i = 0; i < PTINUM; i++)
	{
		if(dev_list[i].SessionHandle == 0)
			{ continue; }

		struct read_thread_param *para;
		if(!cs_malloc(&para, sizeof(struct read_thread_param)))
			{ return 0; }
		para->id = i;
		para->cli = cur_client();

		int32_t ret = start_thread("stapi read", stapi_read_thread, (void *)para, &dev_list[i].thread, 1, 0);
		if(ret)
		{
			return 0;
		}
	}

	atexit(stapi_off);

	cs_log("liboscam_stapi v.%s initialized", oscam_stapi_LibVersion());
	return 1;
}

int32_t stapi_activate_section_filter(int32_t fd, uint8_t *filter, uint8_t *mask)
{
	int n = 0, ret = 852049;
	while(n < 3 && ret == 852049)
	{
		ret = oscam_stapi_FilterSet(fd, filter, mask);
		if(ret)
		{
			cs_log_dbg(D_DVBAPI, "Error: oscam_stapi_FilterSet; %d", ret);
			cs_sleepms(50);
			n++;
		}
	}

	if(ret)
	{
		cs_log("Error: stapi_activate_section_filter: %d", ret);
		ret = -1;
	}
	return ret;
}

int32_t stapi_set_filter(int32_t demux_id, uint16_t pid, uint8_t *filter, uint8_t *mask, int32_t num, char *pmtfile)
{
	int32_t i;
	int32_t ret = -1;
	char dest[1024];
	uint16_t pids[1] = { pid };
	struct s_dvbapi_priority *p;

	if(!pmtfile)
	{
		cs_log_dbg(D_DVBAPI, "No valid pmtfile!");
		return -1;
	}

	cs_log_dbg(D_DVBAPI, "pmt file %s demux_id %d", pmtfile, demux_id);

	for(p = dvbapi_priority; p != NULL; p = p->next)
	{
		if(p->type != 's') { continue; } // stapi rule?
		if(strcmp(pmtfile, p->pmtfile) != 0) { continue; } // same file?

		for(i = 0; i < PTINUM; i++)
		{
			if(strcmp(dev_list[i].name, p->devname) == 0 && p->disablefilter == 0) // check device name and if filtering is enabled!
			{
				cs_log_dbg(D_DVBAPI, "set stapi filter on %s for pid %04X", dev_list[i].name, pids[0]);
				ret = stapi_do_set_filter(demux_id, &dev_list[i].demux_fd[demux_id][num], pids, 1, filter, mask, i);
				if(ret > 0) // success
				{
					cs_log_dbg(D_DVBAPI, "%s filter %d set (pid %04X)", dev_list[i].name, num, pid);
					return ret; // return filternumber
				}
				else // failure
				{
					cs_log_dbg(D_DVBAPI, "Error setting new filter for pid %04X on %s!", pid, dev_list[i].name);
					return -1; // set return to error
				}
			}
		}
	}

	if(p == NULL)
	{
		cs_log_dbg(D_DVBAPI, "No matching S: line in oscam.dvbapi for pmtfile %s -> stop descrambling!", pmtfile);
		snprintf(dest, sizeof(dest), "%s%s", TMPDIR, demux[demux_id].pmt_file);
		unlink(dest); // remove obsolete pmt file
		dvbapi_stop_descrambling(demux_id, 0);
	}
	return ret;
}

int32_t stapi_remove_filter(int32_t demux_id, int32_t num, char *pmtfile)
{
	int32_t i, ret = 0;
	struct s_dvbapi_priority *p;

	if(!pmtfile) { return 0; }

	for(p = dvbapi_priority; p != NULL; p = p->next)
	{
		if(p->type != 's') { continue; }
		if(strcmp(pmtfile, p->pmtfile) != 0)
			{ continue; }

		for(i = 0; i < PTINUM; i++)
		{
			if(strcmp(dev_list[i].name, p->devname) == 0 && p->disablefilter == 0)
			{
				ret = stapi_do_remove_filter(demux_id, &dev_list[i].demux_fd[demux_id][num], i);
			}
		}
	}
	if(ret == 1)
	{
		cs_log_dbg(D_DVBAPI, "filter %d removed", num);
	}
	else
	{
		cs_log_dbg(D_DVBAPI, "Error: filter %d was not removed!", num);
	}
	return ret;
}

static uint32_t check_slot(int32_t dev_id, uint32_t checkslot, FILTERTYPE *skipfilter)
{
	int32_t d, f, l;
	for(d = 0; d < MAX_DEMUX; d++)
	{
		for(f = 0; f < MAX_FILTER; f++)
		{
			if(skipfilter && &dev_list[dev_id].demux_fd[d][f] == skipfilter)
				{ continue; }
			for(l = 0; l < dev_list[dev_id].demux_fd[d][f].NumSlots; l++)
			{
				if(checkslot == dev_list[dev_id].demux_fd[d][f].SlotHandle[l])
				{
					return dev_list[dev_id].demux_fd[d][f].BufferHandle[l];
				}
			}
		}
	}
	return 0;
}


static int32_t stapi_do_set_filter(int32_t demux_id, FILTERTYPE *filter, uint16_t *pids, int32_t pidcount, uint8_t *filt, uint8_t *mask, int32_t dev_id)
{
	uint32_t FilterAssociateError = 0;
	int32_t k, ret = 0;

	filter->fd = 0;
	filter->BufferHandle[0] = 0;
	filter->SlotHandle[0] = 0;

	if(dev_list[dev_id].SessionHandle == 0) { return 0; }

	uint32_t FilterAllocateError = oscam_stapi_FilterAllocate(dev_list[dev_id].SessionHandle, &filter->fd);

	if(FilterAllocateError != 0)
	{
		cs_log("FilterAllocate problem");
		filter->fd = 0;
		return 0;
	}

	for(k = 0; k < pidcount; k++)
	{
		uint16_t pid = pids[k];

		uint32_t QuerySlot = oscam_stapi_PidQuery(dev_list[dev_id].name, pid);
		int32_t SlotInit = 1;

		if(QuerySlot != 0)
		{
			uint32_t checkslot = check_slot(dev_id, QuerySlot, NULL);
			if(checkslot > 0)
			{
				filter->SlotHandle[k] = QuerySlot;
				filter->BufferHandle[k] = checkslot;
				SlotInit = 0;
			}
			else
			{
				cs_log("overtake: clear pid: %d", oscam_stapi_SlotClearPid(QuerySlot));
				SlotInit = 1;
			}
		}

		if(SlotInit == 1)
		{
			ret = oscam_stapi_SlotInit(dev_list[dev_id].SessionHandle, dev_list[dev_id].SignalHandle, &filter->BufferHandle[k], &filter->SlotHandle[k], pid);
		}

		FilterAssociateError = oscam_stapi_FilterAssociate(filter->fd, filter->SlotHandle[k]);
		filter->NumSlots++;
	}

	uint32_t FilterSetError = oscam_stapi_FilterSet(filter->fd, filt, mask);

	if(ret || FilterAllocateError || FilterAssociateError || FilterSetError)
	{
		cs_log("set_filter: dev: %d FAl: %d FAs: %d FS: %d",
				dev_id, FilterAllocateError, FilterAssociateError, FilterSetError);
		stapi_do_remove_filter(demux_id, filter, dev_id);
		return 0;
	}
	else
	{
		return filter->fd; // return fd of filter
	}
}

static int32_t stapi_do_remove_filter(int32_t UNUSED(demux_id), FILTERTYPE *filter, int32_t dev_id)
{
	if(filter->fd == 0) { return 0; }

	uint32_t BufferDeallocateError = 0, SlotDeallocateError = 0;

	if(dev_list[dev_id].SessionHandle == 0) { return 0; }

	int32_t k;
	for(k = 0; k < filter->NumSlots; k++)
	{
		uint32_t checkslot = check_slot(dev_id, filter->SlotHandle[k], filter);

		if(checkslot == 0)
		{
			BufferDeallocateError = oscam_stapi_BufferDeallocate(filter->BufferHandle[k]);
			SlotDeallocateError = oscam_stapi_SlotDeallocate(filter->SlotHandle[k]);
		}
	}
	uint32_t FilterDeallocateError = oscam_stapi_FilterDeallocate(filter->fd);

	memset(filter, 0, sizeof(FILTERTYPE));

	if(BufferDeallocateError || SlotDeallocateError || FilterDeallocateError)
	{
		cs_log("remove_filter: dev: %d BD: %d SD: %d FDe: %d",
				dev_id, BufferDeallocateError, SlotDeallocateError, FilterDeallocateError);
		return 0;
	}
	else
	{
		return 1;
	}
}

static void stapi_cleanup_thread(void *dev)
{
	int32_t dev_index = (int)dev;

	int32_t ErrorCode;
	ErrorCode = oscam_stapi_Close(dev_list[dev_index].SessionHandle);

	cs_log("liboscam_stapi: PTI %s closed - %d\n", dev_list[dev_index].name, ErrorCode);
	dev_list[dev_index].SessionHandle = 0;
}

static void *stapi_read_thread(void *sparam)
{
	int32_t dev_index, ErrorCode, i, j, CRCValid;
	uint32_t QueryBufferHandle = 0, DataSize = 0;
	uint8_t buf[BUFFLEN];

	struct read_thread_param *para = sparam;
	dev_index = para->id;

	SAFE_SETSPECIFIC(getclient, para->cli);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_cleanup_push(stapi_cleanup_thread, (void *) dev_index);

	int32_t error_count = 0;

	while(!exit_oscam)
	{
		QueryBufferHandle = 0;
		ErrorCode = oscam_stapi_SignalWaitBuffer(dev_list[dev_index].SignalHandle, &QueryBufferHandle, 1000);

		switch(ErrorCode)
		{
		case 0: // NO_ERROR:
			break;
		case 852042: // ERROR_SIGNAL_ABORTED
			cs_log("Caught abort signal");
			pthread_exit(NULL);
			break;
		case 11: // ERROR_TIMEOUT:
			//cs_log("timeout %d", dev_index);
			//TODO: if pidindex == -1 try next
			continue;
			break;
		default:
			if(QueryBufferHandle != 0)
			{
				cs_log("SignalWaitBuffer error: %d", ErrorCode);
				oscam_stapi_BufferFlush(QueryBufferHandle);
				continue;
			}
			cs_log("SignalWaitBuffer: index %d ErrorCode: %d - QueryBuffer: %x", dev_index, ErrorCode, QueryBufferHandle);
			error_count++;
			if(error_count > 10)
			{
				cs_log("Too many errors in reader thread %d, quitting.", dev_index);
				pthread_exit(NULL);
			}
			continue;
			break;
		}

		uint32_t NumFilterMatches = 0;
		int32_t demux_id = 0, filter_num = 0;
		DataSize = 0;
		uint32_t k;

		uint32_t MatchedFilterList[10];
		ErrorCode = oscam_stapi_BufferReadSection(QueryBufferHandle, MatchedFilterList, 10, &NumFilterMatches, &CRCValid, buf, BUFFLEN, &DataSize);

		if(ErrorCode != 0)
		{
			cs_log("BufferRead: index: %d ErrorCode: %d", dev_index, ErrorCode);
			cs_sleepms(1000);
			continue;
		}

		if(DataSize <= 0)
			{ continue; }

		SAFE_MUTEX_LOCK(&filter_lock); // don't use cs_lock() here; multiple threads using same s_client struct
		for(k = 0; k < NumFilterMatches; k++)
		{
			for(i = 0; i < MAX_DEMUX; i++)
			{
				for(j = 0; j < MAX_FILTER; j++)
				{
					if(dev_list[dev_index].demux_fd[i][j].fd == MatchedFilterList[k])
					{
						demux_id = i;
						filter_num = j;

						dvbapi_process_input(demux_id, filter_num, buf, DataSize, 0);
					}
				}
			}
		}
		SAFE_MUTEX_UNLOCK(&filter_lock);
	}

	pthread_cleanup_pop(0);

	return NULL;
}

#define ASSOCIATE 1
#define DISASSOCIATE 0

#define DE_START 0
#define DE_STOP 1

static void stapi_DescramblerAssociate(int32_t demux_id, uint16_t pid, int32_t mode, int32_t n)
{
	uint32_t Slot = 0;
	int32_t ErrorCode = 0;

	if(dev_list[n].SessionHandle == 0) { return; }

	Slot = oscam_stapi_PidQuery(dev_list[n].name, pid);
	if(!Slot) { return; }

	if(demux[demux_id].DescramblerHandle[n] == 0) { return; }

	if(mode == ASSOCIATE)
	{
		int32_t k;
		for(k = 0; k < SLOTNUM; k++)
		{
			if(demux[demux_id].slot_assc[n][k] == Slot)
			{
				return;
			}
		}

		ErrorCode = oscam_stapi_DescramblerAssociate(demux[demux_id].DescramblerHandle[n], Slot);
		cs_log_dbg(D_DVBAPI, "set pid %04x on %s", pid, dev_list[n].name);

		if(ErrorCode != 0)
			{ cs_log("DescramblerAssociate %d", ErrorCode); }

		for(k = 0; k < SLOTNUM; k++)
		{
			if(demux[demux_id].slot_assc[n][k] == 0)
			{
				demux[demux_id].slot_assc[n][k] = Slot;
				break;
			}
		}
	}
	else
	{
		ErrorCode = oscam_stapi_DescramblerDisassociate(demux[demux_id].DescramblerHandle[n], Slot);
		if(ErrorCode != 0)
			{ cs_log_dbg(D_DVBAPI, "DescramblerDisassociate %d", ErrorCode); }

		cs_log_dbg(D_DVBAPI, "unset pid %04x on %s", pid, dev_list[n].name);

		int32_t k;
		for(k = 0; k < SLOTNUM; k++)
		{
			if(demux[demux_id].slot_assc[n][k] == Slot)
			{
				demux[demux_id].slot_assc[n][k] = 0;
				return;
			}
		}
	}

	return;
}

static void stapi_startdescrambler(int32_t demux_id, int32_t dev_index, int32_t mode)
{
	int32_t ErrorCode;

	if(mode == DE_START && demux[demux_id].DescramblerHandle[dev_index] == 0)
	{
		uint32_t DescramblerHandle = 0;
		ErrorCode = oscam_stapi_DescramblerAllocate(dev_list[dev_index].SessionHandle, &DescramblerHandle);
		if(ErrorCode != 0)
		{
			cs_log("DescramblerAllocate: ErrorCode: %d SignalHandle: %x", ErrorCode, dev_list[dev_index].SignalHandle);
			return;
		}

		demux[demux_id].DescramblerHandle[dev_index] = DescramblerHandle;
	}

	if(mode == DE_STOP && demux[demux_id].DescramblerHandle[dev_index] > 0)
	{
		ErrorCode = oscam_stapi_DescramblerDeallocate(demux[demux_id].DescramblerHandle[dev_index]);

		if(ErrorCode != 0)
			{ cs_log("DescramblerDeallocate: ErrorCode: %d", ErrorCode); }

		demux[demux_id].DescramblerHandle[dev_index] = 0;
	}

	return;
}

int32_t stapi_set_pid(int32_t demux_id, int32_t UNUSED(num), uint32_t idx, uint16_t UNUSED(pid), char *UNUSED(pmtfile))
{
	int32_t n;

	if(idx == INDEX_INVALID)
	{
		for(n = 0; n < PTINUM; n++)
		{
			if(demux[demux_id].DescramblerHandle[n] == 0) { continue; }

			cs_log_dbg(D_DVBAPI, "stop descrambling PTI: %s", dev_list[n].name);
			stapi_startdescrambler(demux_id, n, DE_STOP);
			memset(demux[demux_id].slot_assc[n], 0, sizeof(demux[demux_id].slot_assc[n]));
		}
	}

	return 1;
}

int32_t stapi_write_cw(int32_t demux_id, uint8_t *cw, uint16_t *STREAMpids, int32_t STREAMpidcount, char *pmtfile)
{
	int32_t ErrorCode, l, n, k;
	uint8_t nullcw[8];
	memset(nullcw, 0, 8);
	char *text[] = { "even", "odd" };

	if(!pmtfile) { return 0; }

	for(n = 0; n < PTINUM; n++)
	{
		if(dev_list[n].SessionHandle == 0) { continue; }
		if(demux[demux_id].DescramblerHandle[n] == 0)
		{
			struct s_dvbapi_priority *p;

			for(p = dvbapi_priority; p != NULL; p = p->next)
			{
				if(p->type != 's') { continue; }
				if(strcmp(pmtfile, p->pmtfile) != 0)
					{ continue; }

				if(strcmp(dev_list[n].name, p->devname) == 0)
				{
					cs_log_dbg(D_DVBAPI, "start descrambling PTI: %s", dev_list[n].name);
					stapi_startdescrambler(demux_id, n, DE_START);
				}
			}
		}

		if(demux[demux_id].DescramblerHandle[n] == 0) { continue; }

		for(k = 0; k < STREAMpidcount; k++)
		{
			stapi_DescramblerAssociate(demux_id, STREAMpids[k], ASSOCIATE, n);
		}
	}

	int32_t pidnum = demux[demux_id].pidindex; // get current pidindex used for descrambling
	uint32_t idx = demux[demux_id].ECMpids[pidnum].index[0];

	if(idx == INDEX_INVALID) // if no indexer for this pid get one!
	{
		idx = dvbapi_get_desc_index(demux_id, pidnum, 0);
		cs_log_dbg(D_DVBAPI, "Demuxer %d PID: %d CAID: %04X ECMPID: %04X is using index %d", demux_id, pidnum,
			demux[demux_id].ECMpids[pidnum].CAID, demux[demux_id].ECMpids[pidnum].ECM_PID, idx);
	}

	for(l = 0; l < 2; l++)
	{
		// Skip check for BISS1 - cw could be indeed zero
		// Skip check for BISS2 - we use the extended cw, so the "simple" cw is always zero
		if(memcmp(cw + (l * 8), demux[demux_id].last_cw[0][l], 8) != 0
			&& (memcmp(cw + (l * 8), nullcw, 8) != 0 || caid_is_biss(demux[demux_id].ECMpids[pidnum].CAID)))
		{
			for(n = 0; n < PTINUM; n++)
			{
				if(demux[demux_id].DescramblerHandle[n] == 0) { continue; }

				ErrorCode = oscam_stapi_DescramblerSet(demux[demux_id].DescramblerHandle[n], l, cw + (l * 8));
				if(ErrorCode != 0)
					{ cs_log("DescramblerSet: ErrorCode: %d", ErrorCode); }

				memcpy(demux[demux_id].last_cw[0][l], cw + (l * 8), 8);
				cs_log_dbg(D_DVBAPI, "write cw %s index: %d %s", text[l], demux_id, dev_list[n].name);
			}
		}
	}

	return 1;
}

// Needed for compatability with liboscam_stapi.a
#undef cs_log
void cs_log(const char *fmt, ...)
{
	va_list params;
	char log_txt[512];

	va_start(params, fmt);
	vsnprintf(log_txt, sizeof(log_txt), fmt, params);
	va_end(params);

	cs_log_txt(MODULE_LOG_PREFIX, "%s", log_txt);
}

#endif
