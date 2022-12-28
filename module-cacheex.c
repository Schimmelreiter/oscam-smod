#define MODULE_LOG_PREFIX "cacheex"

#include "globals.h"

#ifdef CS_CACHEEX

#include "cscrypt/md5.h"
#include "module-cacheex.h"
#include "module-cw-cycle-check.h"
#include "oscam-cache.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-conf.h"
#include "oscam-ecm.h"
#include "oscam-hashtable.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"
#ifdef CS_CACHEEX_AIO
#include "oscam-array.h"
#endif

#define cs_cacheex_matcher "oscam.cacheex"

extern uint8_t cc_node_id[8];
extern uint8_t camd35_node_id[8];

uint8_t cacheex_peer_id[8];

extern CS_MUTEX_LOCK ecm_pushed_deleted_lock;
extern struct ecm_request_t	*ecm_pushed_deleted;
extern CS_MUTEX_LOCK ecmcache_lock;
extern struct ecm_request_t *ecmcwcache;

// HIT CACHE functions **************************************************************

typedef struct hit_key_t {
	uint16_t		caid;
	uint32_t		prid;
	uint16_t		srvid;
} HIT_KEY;

typedef struct cache_hit_t {
	HIT_KEY			key;
	struct timeb	time;
	struct timeb	max_hitcache_time;
	uint64_t		grp;
	uint64_t		grp_last_max_hitcache_time;
#ifdef CS_CACHEEX_AIO
	int32_t			waittime_block;
#endif
	node			ht_node;
	node			ll_node;
} CACHE_HIT;

static pthread_rwlock_t hitcache_lock;
static hash_table ht_hitcache;
static list ll_hitcache;
static bool cacheex_running;

void cacheex_init_hitcache(void)
{
	init_hash_table(&ht_hitcache, &ll_hitcache);
	if (pthread_rwlock_init(&hitcache_lock,NULL) != 0)
		cs_log("Error creating lock hitcache_lock!");
	cacheex_running = true;
}

void cacheex_free_hitcache(void)
{
	cacheex_running = false;
	cacheex_cleanup_hitcache(true);
	deinitialize_hash_table(&ht_hitcache);
	pthread_rwlock_destroy(&hitcache_lock);
}

static int cacheex_compare_hitkey(const void *arg, const void *obj)
{
	if(((const HIT_KEY*)arg)->caid==((const CACHE_HIT*)obj)->key.caid
		&& ((const HIT_KEY*)arg)->prid==((const CACHE_HIT*)obj)->key.prid
		&& ((const HIT_KEY*)arg)->srvid==((const CACHE_HIT*)obj)->key.srvid)
	{
		return 0;
	}
	return 1;
}

static int32_t cacheex_check_hitcache(ECM_REQUEST *er, struct s_client *cl)
{
	CACHE_HIT *result;
	HIT_KEY search;
	memset(&search, 0, sizeof(HIT_KEY));
	search.caid = er->caid;
	search.prid = er->prid;
	search.srvid = er->srvid;
	SAFE_RWLOCK_RDLOCK(&hitcache_lock);
	result = find_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &cacheex_compare_hitkey);
	if(result){
		struct timeb now;
		cs_ftime(&now);
		int64_t gone = comp_timeb(&now, &result->time);
		uint64_t grp = cl?cl->grp:0;

		if(
			gone <= (cfg.max_hitcache_time*1000)
			&&
			(!grp || !result->grp || (grp & result->grp))
#ifdef CS_CACHEEX_AIO
			&&
			result->waittime_block <= cfg.waittime_block_start
#endif
		)
		{
			SAFE_RWLOCK_UNLOCK(&hitcache_lock);
			return 1;
		}
	}
	SAFE_RWLOCK_UNLOCK(&hitcache_lock);
	return 0;
}

static void cacheex_add_hitcache(struct s_client *cl, ECM_REQUEST *er)
{
	if (!cfg.max_hitcache_time) // we don't want check/save hitcache
		return;
	if (!cfg.cacheex_wait_timetab.cevnum)
		return;
	uint32_t cacheex_wait_time = get_cacheex_wait_time(er,NULL);
	if (!cacheex_wait_time)
		return;

	CACHE_HIT *result;
	HIT_KEY search;

	memset(&search, 0, sizeof(HIT_KEY));
	search.caid = er->caid;
	search.prid = er->prid;
	search.srvid = er->srvid;

	SAFE_RWLOCK_WRLOCK(&hitcache_lock);

	result = find_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &cacheex_compare_hitkey);
	if(!result) // not found, add it!
	{
		if(cs_malloc(&result, sizeof(CACHE_HIT)))
		{
			memset(result, 0, sizeof(CACHE_HIT));
			result->key.caid = er->caid;
			result->key.prid = er->prid;
			result->key.srvid = er->srvid;
			cs_ftime(&result->max_hitcache_time);
#ifdef CS_CACHEEX_AIO
			result->waittime_block = 0;
#endif
			add_hash_table(&ht_hitcache, &result->ht_node, &ll_hitcache, &result->ll_node, result, &result->key, sizeof(HIT_KEY));
		}
	}

	if(result)
	{
		if(cl)
		{
			result->grp |= cl->grp;
			result->grp_last_max_hitcache_time |= cl->grp;
		}
		cs_ftime(&result->time); //always update time;
	}

	SAFE_RWLOCK_UNLOCK(&hitcache_lock);
}

static void cacheex_del_hitcache(struct s_client *cl, ECM_REQUEST *er)
{
	HIT_KEY search;
	CACHE_HIT *result;

	memset(&search, 0, sizeof(HIT_KEY));
	search.caid = er->caid;
	search.prid = er->prid;
	search.srvid = er->srvid;

	if(cl && cl->grp)
		{
			result = find_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &cacheex_compare_hitkey);
			while(result)
			{
				result->grp &= ~cl->grp;
				result->grp_last_max_hitcache_time &= ~cl->grp;
				result = find_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &cacheex_compare_hitkey);
			}
		}

	SAFE_RWLOCK_WRLOCK(&hitcache_lock);
	search_remove_elem_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &cacheex_compare_hitkey);
	SAFE_RWLOCK_UNLOCK(&hitcache_lock);
}

void cacheex_cleanup_hitcache(bool force)
{
	CACHE_HIT *cachehit;
	node *i,*i_next;
	struct timeb now;
	int64_t gone, gone_max_hitcache_time;
	int32_t timeout = (cfg.max_hitcache_time + (cfg.max_hitcache_time / 2)) * 1000; // 1,5
	int32_t clean_grp = (cfg.max_hitcache_time * 1000);

	SAFE_RWLOCK_WRLOCK(&hitcache_lock);
	i = get_first_node_list(&ll_hitcache);
	while (i)
	{
		i_next = i->next;
		cachehit = get_data_from_node(i);

		if(!cachehit)
		{
			i = i_next;
			continue;
		}

		cs_ftime(&now);
		gone = comp_timeb(&now, &cachehit->time);
		gone_max_hitcache_time = comp_timeb(&now, &cachehit->max_hitcache_time);

		if(force || gone>timeout
#ifdef CS_CACHEEX_AIO
			 || (cachehit->waittime_block > (cfg.waittime_block_time / 3 + 1))
#endif
		)
		{
			remove_elem_list(&ll_hitcache, &cachehit->ll_node);
			remove_elem_hash_table(&ht_hitcache, &cachehit->ht_node);
			NULLFREE(cachehit);
		}
		else if(gone_max_hitcache_time >= clean_grp){
			cachehit->grp = cachehit->grp_last_max_hitcache_time;
			cachehit->grp_last_max_hitcache_time = 0;
			cs_ftime(&cachehit->max_hitcache_time);
		}

#ifdef CS_CACHEEX_AIO
		if(cfg.waittime_block_start && (cachehit && cachehit->waittime_block >= cfg.waittime_block_start))
		{
			cachehit->waittime_block++;
		}
#endif
		i = i_next;
	}
	SAFE_RWLOCK_UNLOCK(&hitcache_lock);
}

static int32_t cacheex_ecm_hash_calc(uint8_t *buf, int32_t n)
{
	int32_t i, h = 0;
	for(i = 0; i < n; i++)
	{
		h = 31 * h + buf[i];
	}
	return h;
}

void cacheex_update_hash(ECM_REQUEST *er)
{
	er->csp_hash = cacheex_ecm_hash_calc(er->ecm + 3, er->ecmlen - 3);
}

void cacheex_free_csp_lastnodes(ECM_REQUEST *er)
{
	ll_destroy_free_data(&er->csp_lastnodes);
}

void cacheex_set_csp_lastnode(ECM_REQUEST *er)
{
	er->csp_lastnodes = NULL;
}

void cacheex_set_cacheex_src(ECM_REQUEST *ecm, struct s_client *cl)
{
	if(ecm->cacheex_src == cl)
		ecm->cacheex_src = NULL;
}

void cacheex_init_cacheex_src(ECM_REQUEST *ecm, ECM_REQUEST *er)
{
	if(!ecm->cacheex_src)
		ecm->cacheex_src = er->cacheex_src;
}

static void *chkcache_process(void)
{
	set_thread_name(__func__);

	time_t timeout;
	struct ecm_request_t *er, *ecm;
	uint8_t add_hitcache_er;
	struct s_reader *cl_rdr;
	struct s_reader *rdr;
	struct s_ecm_answer *ea;
	struct s_client *cex_src = NULL;
	struct s_write_from_cache *wfc = NULL;

	while(cacheex_running)
	{
		cs_readlock(__func__, &ecmcache_lock);
		for(er = ecmcwcache; er; er = er->next)
		{
			timeout = time(NULL) - ((cfg.ctimeout + 500) / 1000 + 1);
			if(er->tps.time < timeout)
				{ break; }

			if(er->rc < E_UNHANDLED || er->readers_timeout_check) // already answered
				{ continue; }

			// CHECK IF FOUND ECM IN CACHE
			ecm = check_cache(er, er->client);
			if(ecm) // found in cache
			{
				// check for add_hitcache
				if(ecm->cacheex_src) // cw from cacheex
				{
					// only when no wait_time expires (or not wait_time)
					if((er->cacheex_wait_time && !er->cacheex_wait_time_expired) || !er->cacheex_wait_time)
					{
						// add_hitcache already called, but we check if we have to call it for these (er) caid|prid|srvid
						if(ecm->prid!=er->prid || ecm->srvid!=er->srvid)
						{
							// here we should be sure cex client has not been freed!
							cex_src = ecm->cacheex_src && is_valid_client(ecm->cacheex_src) && !ecm->cacheex_src->kill ? ecm->cacheex_src : NULL;

							if(cex_src) // add_hitcache only if client is really active
							{
								add_hitcache_er = 1;
								cl_rdr = cex_src->reader;

								if(cl_rdr && cl_rdr->cacheex.mode == 2)
								{
									for(ea = er->matching_rdr; ea; ea = ea->next)
									{
										rdr = ea->reader;
										if(cl_rdr == rdr && ((ea->status & REQUEST_ANSWERED) == REQUEST_ANSWERED))
										{
											cs_log_dbg(D_CACHEEX | D_CSP | D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [CACHEEX] skip ADD self request!",
														(check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid);

											add_hitcache_er=0; // don't add hit cache, reader requested self
										}
									}
								}

								// USE cacheex client (to get correct group) and ecm
								// from requesting client (to get correct caid|prid|srvid)!!!
								if(add_hitcache_er)
								{
									cacheex_add_hitcache(cex_src, er);
								}
							}
						}

					}
					else
					{
						// add_hitcache already called, but we have to remove it because cacheex not coming before wait_time
						if(ecm->prid == er->prid && ecm->srvid == er->srvid)
							{ cacheex_del_hitcache(er->client, ecm); }
					}
				}
				// END check for add_hitcache

				if(check_client(er->client))
				{
					wfc = NULL;
					if(!cs_malloc(&wfc, sizeof(struct s_write_from_cache)))
					{
						NULLFREE(ecm);
						continue;
					}

					wfc->er_new = er;
					wfc->er_cache = ecm;

					if(!add_job(er->client, ACTION_ECM_ANSWER_CACHE, wfc, sizeof(struct s_write_from_cache))) // write_ecm_answer_fromcache
					{
						NULLFREE(ecm);
						continue;
					}
				}
				else
				{
					NULLFREE(ecm);
				}
			}
		}
		cs_readunlock(__func__, &ecmcache_lock);
		cs_sleepms(10);
	}

	return NULL;
}

void checkcache_process_thread_start(void)
{
	start_thread("chkcache_process", (void *)&chkcache_process, NULL, NULL, 1, 1);
}

void cacheex_init(void)
{
	// Init random node id
	get_random_bytes(cacheex_peer_id, 8);
#ifdef MODULE_CCCAM
	memcpy(cacheex_peer_id, cc_node_id, 8);
#endif
#ifdef MODULE_CAMD35_TCP
	memcpy(camd35_node_id, cacheex_peer_id, 8);
#endif
}

void cacheex_clear_account_stats(struct s_auth *account)
{
	account->cwcacheexgot = 0;
	account->cwcacheexpush = 0;
	account->cwcacheexhit = 0;
#ifdef CS_CACHEEX_AIO
	account->cwcacheexgotlg = 0;
	account->cwcacheexpushlg = 0;
#endif
}

void cacheex_clear_client_stats(struct s_client *client)
{
	client->cwcacheexgot = 0;
	client->cwcacheexpush = 0;
	client->cwcacheexhit = 0;
#ifdef CS_CACHEEX_AIO
	client->cwcacheexgotlg = 0;
	client->cwcacheexpushlg = 0;
#endif
}

int32_t cacheex_add_stats(struct s_client *cl, uint16_t caid, uint16_t srvid, uint32_t prid, uint8_t direction
#ifdef CS_CACHEEX_AIO
				, uint8_t localgenerated
#endif
)
{
	if(!cfg.cacheex_enable_stats)
		{ return -1; }

	// create list if doesn't exist
	if(!cl->ll_cacheex_stats)
		{ cl->ll_cacheex_stats = ll_create("ll_cacheex_stats"); }

	time_t now = time((time_t *)0);
	LL_ITER itr = ll_iter_create(cl->ll_cacheex_stats);
	S_CACHEEX_STAT_ENTRY *cacheex_stats_entry;

	// check for existing entry
	while((cacheex_stats_entry = ll_iter_next(&itr)))
	{
		if(cacheex_stats_entry->cache_srvid == srvid &&
				cacheex_stats_entry->cache_caid == caid &&
				cacheex_stats_entry->cache_prid == prid &&
				cacheex_stats_entry->cache_direction == direction)
		{
			// we already have this entry - just add count and time
			cacheex_stats_entry->cache_count++;
#ifdef CS_CACHEEX_AIO
			if(localgenerated)
				cacheex_stats_entry->cache_count_lg++;
#endif
			cacheex_stats_entry->cache_last = now;
			return cacheex_stats_entry->cache_count;
		}
	}

	// if we land here we have to add a new entry
	if(cs_malloc(&cacheex_stats_entry, sizeof(S_CACHEEX_STAT_ENTRY)))
	{
		cacheex_stats_entry->cache_caid = caid;
		cacheex_stats_entry->cache_srvid = srvid;
		cacheex_stats_entry->cache_prid = prid;
		cacheex_stats_entry->cache_count = 1;
#ifdef CS_CACHEEX_AIO
		if(localgenerated)
				cacheex_stats_entry->cache_count_lg = 1;
#endif
		cacheex_stats_entry->cache_last = now;
		cacheex_stats_entry->cache_direction = direction;
		ll_iter_insert(&itr, cacheex_stats_entry);
		return 1;
	}
	return 0;
}

int8_t cacheex_maxhop(struct s_client *cl)
{
	int maxhop = 10;
	if(cl->reader && cl->reader->cacheex.maxhop)
		{ maxhop = cl->reader->cacheex.maxhop; }
	else if(cl->account && cl->account->cacheex.maxhop)
		{ maxhop = cl->account->cacheex.maxhop; }
	return maxhop;
}

#ifdef CS_CACHEEX_AIO
int8_t cacheex_maxhop_lg(struct s_client *cl)
{
	int max = 10;
	int maxhop = cacheex_maxhop(cl);
	int maxhop_lg = maxhop;

	if(cl->reader && cl->reader->cacheex.maxhop_lg)
	{
		if(cl->reader->cacheex.maxhop_lg > max)
		{
			cl->reader->cacheex.maxhop_lg = max;
		}

		if(cl->reader->cacheex.maxhop_lg < maxhop)
		{
			maxhop_lg = maxhop;
		}
		else
		{
			maxhop_lg = cl->reader->cacheex.maxhop_lg;
		}

		cl->reader->cacheex.maxhop_lg = maxhop_lg;
	}
	else if(cl->account && cl->account->cacheex.maxhop_lg)
	{
		if(cl->account->cacheex.maxhop_lg > max)
		{
			cl->account->cacheex.maxhop_lg = max;
		}

		if(cl->account->cacheex.maxhop_lg < maxhop)
		{
			maxhop_lg = maxhop;
		}
		else
		{
			maxhop_lg = cl->account->cacheex.maxhop_lg;
		}

		cl->account->cacheex.maxhop_lg = maxhop_lg;
	}
	return maxhop_lg;
}
#endif

static void cacheex_cache_push_to_client(struct s_client *cl, ECM_REQUEST *er)
{
	add_job(cl, ACTION_CACHE_PUSH_OUT, er, 0);
}

/**
 * Check for NULL ecmd5
 **/
static uint8_t checkECMD5(ECM_REQUEST *er)
{
	int8_t i;
	for(i = 0; i < CS_ECMSTORESIZE; i++)
		if(er->ecmd5[i]) { return 1; }
	return 0;
}

#ifdef CS_CACHEEX_AIO
static uint8_t chk_cwcheck(ECM_REQUEST *er, uint8_t cw_check_for_push)
{
	if(!cw_check_for_push)
		return 1;

	CWCHECK check_cw;
	check_cw = get_cwcheck(er);

	if(check_cw.mode && check_cw.counter > 1)
	{
		if(er->cw_count >= check_cw.counter)
		{
			return 1;
		}
		else
		{
			cs_log_dbg(D_CACHEEX, "push denied - cacheex_check_cw.counter: %u > er->cw_count: %u", check_cw.counter, er->cw_count);
			return 0;
		}
	}
	else
	{
		return 1;
	}
}
#endif

/**
 * cacheex modes:
 *
 * cacheex=1 CACHE PULL:
 * Situation: oscam A reader1 has cacheex=1, oscam B account1 has cacheex=1
 *   oscam A gets a ECM request, reader1 send this request to oscam B, oscam B checks his cache
 *   a. not found in cache: return NOK
 *   a. found in cache: return OK+CW
 *   b. not found in cache, but found pending request: wait max cacheexwaittime and check again
 *   oscam B never requests new ECMs
 *
 *   CW-flow: B->A
 *
 * cacheex=2 CACHE PUSH:
 * Situation: oscam A reader1 has cacheex=2, oscam B account1 has cacheex=2
 *   if oscam B gets a CW, its pushed to oscam A
 *   reader has normal functionality and can request ECMs
 *
 *   Problem: oscam B can only push if oscam A is connected
 *   Problem or feature?: oscam A reader can request ecms from oscam B
 *
 *   CW-flow: B->A
 *
 */
void cacheex_cache_push(ECM_REQUEST *er)
{
	if(er->rc >= E_NOTFOUND) { return; }

	//cacheex=2 mode: push (server->remote)
	struct s_client *cl;
	cs_readlock(__func__, &clientlist_lock);
	for(cl = first_client->next; cl; cl = cl->next)
	{
		if(check_client(cl) && er->cacheex_src != cl)
		{
			if(get_module(cl)->num == R_CSP) // always send to csp cl
			{
				if(!er->cacheex_src || cfg.csp.allow_reforward) { cacheex_cache_push_to_client(cl, er); } // but not if the origin was cacheex (might loop)
			}
			else if(cl->typ == 'c' && !cl->dup && cl->account && cl->account->cacheex.mode == 2) // send cache over user
			{
				if(get_module(cl)->c_cache_push // cache-push able
						&& (!er->grp || (cl->grp & er->grp)
#ifdef CS_CACHEEX_AIO
							 || (er->localgenerated && ((cl->grp & cfg.cacheex_push_lg_groups) && strcmp(username(cl), username(er->cacheex_src))))
#endif
						) // Group-check
						/**** OUTGOING FILTER CHECK ***/
						&& (!er->selected_reader || !cacheex_reader(er->selected_reader) || !cfg.block_same_name || strcmp(username(cl), er->selected_reader->label)) // check reader mode-1 loopback by same name
						&& (!er->selected_reader || !cacheex_reader(er->selected_reader) || !cfg.block_same_ip || (check_client(er->selected_reader->client) && !IP_EQUAL(cl->ip, er->selected_reader->client->ip))) // check reader mode-1 loopback by same ip
						&& (!cl->account->cacheex.drop_csp || checkECMD5(er))                   // cacheex_drop_csp-check
						&& chk_ctab(er->caid, &cl->ctab)                                        // Caid-check
						&& (!checkECMD5(er) || chk_ident_filter(er->caid, er->prid, &cl->ftab)) // Ident-check (not for csp: prid=0 always!)
						&& chk_srvid(cl, er)                                                    // Service-check
						&& chk_csp_ctab(er, &cl->account->cacheex.filter_caidtab)               // cacheex_ecm_filter
#ifdef CS_CACHEEX_AIO
						&& (er->localgenerated 													//  lg-flag-check
						|| chk_srvid_localgenerated_only_exception(er)	 						//		lg-only-service-exception
						|| !(cl->account->cacheex.localgenerated_only						 	//		usr-lg-only
							|| (
							(cl->account->cacheex.feature_bitfield & 64)					 		// cx-aio >= 9.2.6 => check ftab
								&&	(chk_lg_only(er, &cl->account->cacheex.lg_only_tab) 			// usr-lg-only-ftab (feature 64)
									|| chk_lg_only(er, &cfg.cacheex_lg_only_tab)) 					// global-lg-only-ftab (feature 64)
							)
						)
					)
						&& (chk_cwcheck(er, cl->account->cacheex.cw_check_for_push))			// check cw_check-counter if enabled
						&& chk_nopushafter(er->caid, &cl->account->cacheex.cacheex_nopushafter_tab, er->ecm_time) // no push after check
#endif
				)
				{
					cacheex_cache_push_to_client(cl, er);
				}
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);

	//cacheex=3 mode: reverse push (reader->server)
	cs_readlock(__func__, &readerlist_lock);
	cs_readlock(__func__, &clientlist_lock);
	struct s_reader *rdr;
	for(rdr = first_active_reader; rdr; rdr = rdr->next)
	{
		cl = rdr->client;
		if(check_client(cl) && er->cacheex_src != cl && rdr->cacheex.mode == 3) // send cache over reader
		{
			if(rdr->ph.c_cache_push // cache-push able
					&& (!er->grp || (rdr->grp & er->grp)
#ifdef CS_CACHEEX_AIO
						 || (er->localgenerated && ((rdr->grp & cfg.cacheex_push_lg_groups) && strcmp(username(cl), username(er->cacheex_src))))
#endif
					) // Group-check
					/**** OUTGOING FILTER CHECK ***/
					&& (!er->selected_reader || !cacheex_reader(er->selected_reader) || !cfg.block_same_name || strcmp(username(cl), er->selected_reader->label)) // check reader mode-1 loopback by same name
					&& (!er->selected_reader || !cacheex_reader(er->selected_reader) || !cfg.block_same_ip || (check_client(er->selected_reader->client) && !IP_EQUAL(cl->ip, er->selected_reader->client->ip))) // check reader mode-1 loopback by same ip
					&& (!rdr->cacheex.drop_csp || checkECMD5(er))                            // cacheex_drop_csp-check
					&& chk_ctab(er->caid, &rdr->ctab)                                        // Caid-check
					&& (!checkECMD5(er) || chk_ident_filter(er->caid, er->prid, &rdr->ftab)) // Ident-check (not for csp: prid=0 always!)
					&& chk_srvid(cl, er)                                                     // Service-check
					&& chk_csp_ctab(er, &rdr->cacheex.filter_caidtab)                        // cacheex_ecm_filter
#ifdef CS_CACHEEX_AIO
					&& (er->localgenerated 													//  lg-only-check
						|| chk_srvid_localgenerated_only_exception(er)	 					//		service-exception
						|| !(rdr->cacheex.localgenerated_only							 	//		rdr-lg-only
							|| (
							(rdr->cacheex.feature_bitfield & 64)					 		// cx-aio >= 9.2.6 => check ftab
								&&	(chk_lg_only(er, &rdr->cacheex.lg_only_tab) 			// rdr-lg-only-ftab (feature 64)
									|| chk_lg_only(er, &cfg.cacheex_lg_only_tab)) 			// global-lg-only-ftab (feature 64)
							)
						)
					)
					&& (chk_cwcheck(er, rdr->cacheex.cw_check_for_push))                     // check cw_check-counter if enabled
					&& chk_nopushafter(er->caid, &rdr->cacheex.cacheex_nopushafter_tab, er->ecm_time)
#endif
			) // no push after check
			{
				cacheex_cache_push_to_client(cl, er);
			}
		}
	}
	cs_readunlock(__func__, &clientlist_lock);
	cs_readunlock(__func__, &readerlist_lock);
}

/**** INCOMING FILTER CHECK ***/
uint8_t check_cacheex_filter(struct s_client *cl, ECM_REQUEST *er)
{

	if(check_client(cl) && cl->typ == 'p' && cl->reader && cl->reader->cacheex.mode == 2
			&& (!cl->reader->cacheex.drop_csp || checkECMD5(er))                            // cacheex_drop_csp-check
			&& chk_ctab(er->caid, &cl->reader->ctab)                                        // Caid-check
			&& (!checkECMD5(er) || chk_ident_filter(er->caid, er->prid, &cl->reader->ftab)) // Ident-check (not for csp: prid=0 always!)
			&& chk_srvid(cl, er))                                                           // Service-check
	{
		return 1;
	}

	if(check_client(cl) && cl->typ == 'c' && cl->account && cl->account->cacheex.mode == 3
			&& (!cl->account->cacheex.drop_csp || checkECMD5(er))                   // cacheex_drop_csp-check
			&& chk_ctab(er->caid, &cl->ctab)                                        // Caid-check
			&& (!checkECMD5(er) || chk_ident_filter(er->caid, er->prid, &cl->ftab)) // Ident-check (not for csp: prid=0 always!)
			&& chk_srvid(cl, er))                                                   // Service-check
	{
		return 1;
	}
	free_ecm(er);
	return 0;
}

static struct s_cacheex_matcher *is_cacheex_matcher_matching(ECM_REQUEST *from_er, ECM_REQUEST *to_er)
{
	struct s_cacheex_matcher *entry = cfg.cacheex_matcher;
	int8_t v_ok = (from_er && to_er) ? 2 : 1;
	while(entry)
	{
		int8_t ok = 0;
		if(from_er
				&& (!entry->caid || entry->caid == from_er->caid)
				&& (!entry->provid || entry->provid == from_er->prid)
				&& (!entry->srvid || entry->srvid == from_er->srvid)
				&& (!entry->chid || entry->chid == from_er->chid)
				&& (!entry->pid || entry->pid == from_er->pid)
				&& (!entry->ecmlen || entry->ecmlen == from_er->ecmlen))
			{ ok++; }

		if(to_er
				&& (!entry->to_caid || entry->to_caid == to_er->caid)
				&& (!entry->to_provid || entry->to_provid == to_er->prid)
				&& (!entry->to_srvid || entry->to_srvid == to_er->srvid)
				&& (!entry->to_chid || entry->to_chid == to_er->chid)
				&& (!entry->to_pid || entry->to_pid == to_er->pid)
				&& (!entry->to_ecmlen || entry->to_ecmlen == to_er->ecmlen))
			{ ok++; }

		if(ok == v_ok)
		{
			if(!from_er || !to_er || from_er->srvid == to_er->srvid)
				{ return entry; }
		}
		entry = entry->next;
	}
	return NULL;
}

bool cacheex_is_match_alias(struct s_client *cl, ECM_REQUEST *er)
{
	return check_client(cl) && cl->account && cl->account->cacheex.mode == 1 && is_cacheex_matcher_matching(NULL, er);
}

#ifdef WITH_DEBUG
static void log_cacheex_cw(ECM_REQUEST *er, char *reason)
{
	uint8_t *data;
	uint8_t remotenodeid[8];
	data = ll_last_element(er->csp_lastnodes);
	if(data)
		{ memcpy(remotenodeid, data, 8); }
	else
		{ memset(remotenodeid, 0 , 8); }

	char buf_ecm[109];
	format_ecm(er, buf_ecm, 109);
	cs_log_dbg(D_CACHEEX,"got pushed ecm [%s]: %s - odd/even 0x%x - CSP cw: %s - pushed from %s, at hop %d, origin node-id %" PRIu64 "X",
			reason, buf_ecm, er->ecm[0], (checkECMD5(er)?"NO":"YES"), er->from_csp ? "csp" : username((er->cacheex_src?er->cacheex_src:er->client)), ll_count(er->csp_lastnodes), er->csp_lastnodes ? cacheex_node_id(remotenodeid): 0);
}
#endif

// check if sky_ger 64 bit CW has valid checksum bytes and therefore is probably invalid
uint8_t check_nds_cwex(ECM_REQUEST *er)
{
	uint8_t k, csum;
	uint8_t hit = 0;
	uint8_t oe = checkCWpart(er->cw, 0) ? 0 : 8;
	for(k = 0; k < 8; k += 4)
	{
		csum = ((er->cw[k + oe] + er->cw[k + oe + 1] + er->cw[k + oe + 2]) & 0xff);
		if(er->cw[k + oe + 3] == csum)
		{
			hit++;
		}
	}
	if(hit > 1)
	{
		return 1;
	}
	return 0;
}

static int32_t cacheex_add_to_cache_int(struct s_client *cl, ECM_REQUEST *er, int8_t csp)
{
	if(er->rc >= E_NOTFOUND) { return 0; }

	if(!cl)
		{ return 0; }
	if(!csp && cl->reader && cl->reader->cacheex.mode != 2)  //from reader
	{
		cs_log_dbg(D_CACHEEX, "CACHEX received, but disabled for %s", username(cl));
		return 0;
	}
	if(!csp && !cl->reader && cl->account && cl->account->cacheex.mode != 3)  //from user
	{
		cs_log_dbg(D_CACHEEX, "CACHEX received, but disabled for %s", username(cl));
		return 0;
	}
	if(!csp && !cl->reader && !cl->account)    //not active!
	{
		cs_log_dbg(D_CACHEEX, "CACHEX received, but invalid client state %s", username(cl));
		return 0;
	}

	if(!cfg.disablecrccws && ((cl->typ == 'c' && cl->account && !cl->account->disablecrccacheex) || ( cl->typ == 'p' && cl->reader && !cl->reader->disablecrccws)))
	{
		uint8_t selectedForIgnChecksum = chk_if_ignore_checksum(er, &cfg.disablecrccws_only_for);
		if(cl->typ == 'c')
		{
			selectedForIgnChecksum += chk_if_ignore_checksum(er, &cl->account->disablecrccacheex_only_for);
		}
		if(cl->typ == 'p')
		{
			selectedForIgnChecksum += chk_if_ignore_checksum(er, &cl->reader->disablecrccws_only_for);
		}
		if(!selectedForIgnChecksum)
		{
			uint8_t i, c;
			for(i = 0; i < 16; i += 4)
			{
				c = ((er->cw[i] + er->cw[i + 1] + er->cw[i + 2]) & 0xff);

				if(er->cw[i + 3] != c)
				{
					cs_log_dump_dbg(D_CACHEEX, er->cw, 16, "push received cw with chksum error from %s", csp ? "csp" : username(cl));
					cl->cwcacheexerr++;
					if(cl->account)
						{ cl->account->cwcacheexerr++; }
					return 0;
				}
			}
		}
	}

#ifdef CS_CACHEEX_AIO
	if(caid_is_videoguard(er->caid))
	{
		if(cl->typ == 'p' && chk_if_ignore_checksum(er, &cl->reader->disablecrccws_only_for))
		{
			if(check_nds_cwex(er))
			{
				if(cl->reader->dropbadcws)
				{
					cs_log_dbg(D_CACHEEX, "Probably got pushed bad CW to cacheex reader: %s, caid %04X, srvid %04X - dropping CW", cl->reader->label, er->caid, er->srvid);
					return 0;
				}
				else
				{
					cs_log_dbg(D_CACHEEX, "Probably got pushed bad CW to cacheex reader: %s, caid %04X, srvid %04X", cl->reader->label, er->caid, er->srvid);				
				}
			}
		}
	
		if(cl->typ == 'c' && chk_if_ignore_checksum(er, &cl->account->disablecrccacheex_only_for))
		{
			if(check_nds_cwex(er))
			{
				cs_log_dbg(D_CACHEEX, "Probably got bad CW from cacheex user: %s, caid %04X, srvid %04X", username(cl), er->caid, er->srvid);
			}
		}
	}

	if(caid_is_videoguard(er->caid))
	{
		if(cl->typ == 'p' && chk_if_ignore_checksum(er, &cl->reader->disablecrccws_only_for) && !chk_srvid_disablecrccws_only_for_exception(er))
		{
			if(check_nds_cwex(er))
			{
				if(check_client(cl) && cl->reader && cl->reader->dropbadcws)
				{
					if (((D_CACHEEX) & cs_dblevel)) // avoid useless operations if debug is not enabled
					{
						uint8_t remotenodeid[8];
						cacheex_get_srcnodeid(er, remotenodeid);

						cs_log_dbg(D_CACHEEX, "Probably got pushed bad CW from cacheex reader: %s, caid %04X, srvid %04X - dropping CW, lg: %i, hop: %i, src-nodeid %" PRIu64 "X", cl->reader->label, er->caid, er->srvid, er->localgenerated, ll_count(er->csp_lastnodes), er->csp_lastnodes ? cacheex_node_id(remotenodeid): 0);
					}
					return 0;
				}
				else
				{
					if (((D_CACHEEX) & cs_dblevel)) // avoid useless operations if debug is not enabled
					{
						uint8_t remotenodeid[8];
						cacheex_get_srcnodeid(er, remotenodeid);

						cs_log_dbg(D_CACHEEX, "Probably got pushed bad CW from cacheex reader: %s, caid %04X, srvid %04X, lg: %i, hop: %i, src-nodeid %" PRIu64 "X", cl->reader->label, er->caid, er->srvid, er->localgenerated, ll_count(er->csp_lastnodes), er->csp_lastnodes ? cacheex_node_id(remotenodeid): 0);
					}
				}
			}
		}

		if(cl->typ == 'c' && chk_if_ignore_checksum(er, &cl->account->disablecrccacheex_only_for) && !chk_srvid_disablecrccws_only_for_exception(er))
		{
			if(check_nds_cwex(er))
			{
				if (((D_CACHEEX) & cs_dblevel)) // avoid useless operations if debug is not enabled
				{
					uint8_t remotenodeid[8];
					cacheex_get_srcnodeid(er, remotenodeid);

					cs_log_dbg(D_CACHEEX, "Probably got bad CW from cacheex user: %s, caid %04X, srvid %04X, lg: %i, hop: %i, src-nodeid %" PRIu64 "X", username(cl), er->caid, er->srvid, er->localgenerated, ll_count(er->csp_lastnodes), er->csp_lastnodes ? cacheex_node_id(remotenodeid): 0);
				}
			}
		}
	}
#endif

	// Skip check for BISS1 - cw could be indeed zero
	// Skip check for BISS2 - we use the extended cw, so the "simple" cw is always zero
	if(chk_is_null_CW(er->cw) && !caid_is_biss(er->caid))
	{
		cs_log_dump_dbg(D_CACHEEX, er->cw, 16, "push received null cw from %s", csp ? "csp" : username(cl));
		cl->cwcacheexerr++;
		if(cl->account)
			{ cl->account->cwcacheexerr++; }
		return 0;
	}

	// Don't check for BISS1 and BISS2 mode 1/E or fake caid (ECM is fake for them)
	// Don't check for BISS2 mode CA (ECM table is always 0x80)
	if(!caid_is_biss(er->caid) && !caid_is_fake(er->caid) && get_odd_even(er) == 0)
	{
		cs_log_dbg(D_CACHEEX, "push received ecm with null odd/even byte from %s", csp ? "csp" : username(cl));
		cl->cwcacheexerr++;
		if(cl->account)
			{ cl->account->cwcacheexerr++; }
		return 0;
	}

	if(!chk_halfCW(er, er->cw))
	{
#ifdef WITH_DEBUG
		if(cs_dblevel & D_CACHEEX)
		{
			log_cacheex_cw(er, "bad half cw");
		}
#endif
		cl->cwcacheexerr++;
		if(cl->account)
			{ cl->account->cwcacheexerr++; }
		return 0;
	}

	if((csp && cfg.csp.block_fakecws) || (cl->reader && cl->reader->cacheex.block_fakecws)
			|| (!cl->reader && cl->account && cl->account->cacheex.block_fakecws))
	{
		if(chk_is_fakecw(er->cw))
		{
			cs_log_dbg(D_CACHEEX, "push received fake cw from %s", csp ? "csp" : username(cl));
			cl->cwcacheexerr++;
			if(cl->account)
				{ cl->account->cwcacheexerr++; }
			return 0;
		}
	}

	er->grp |= cl->grp; // ok for mode2 reader too: cl->reader->grp
	er->rc = E_CACHEEX;
	er->cacheex_src = cl;
	er->selected_reader = cl->reader;
	er->client = NULL; // No Owner! So no fallback!

	if(check_client(cl))
	{
		cl->cwcacheexgot++;
		if(cl->account)
			{ cl->account->cwcacheexgot++; }
		first_client->cwcacheexgot++;
#ifdef CS_CACHEEX_AIO
		if(er->localgenerated)
		{
			cl->cwcacheexgotlg++;
			if(cl->account)
				cl->account->cwcacheexgotlg++;
			first_client->cwcacheexgotlg++;
		}
#endif
	}

	cacheex_add_hitcache(cl, er); // we have to call it before add_cache, because in chk_process we could remove it!
	add_cache(er);
#ifdef CS_CACHEEX_AIO
	cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 1, er->localgenerated);
#else
	cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 1);
#endif

	cs_writelock(__func__, &ecm_pushed_deleted_lock);
	er->next = ecm_pushed_deleted;
	ecm_pushed_deleted = er;
	cs_writeunlock(__func__, &ecm_pushed_deleted_lock);

	return 1; // NO free, we have to wait cache push out stuff ends.
}

void cacheex_add_to_cache(struct s_client *cl, ECM_REQUEST *er)
{
	er->from_cacheex = 1;
	if(!cacheex_add_to_cache_int(cl, er, 0))
		{ free_push_in_ecm(er); }
}

void cacheex_add_to_cache_from_csp(struct s_client *cl, ECM_REQUEST *er)
{
	if(!cacheex_add_to_cache_int(cl, er, 1))
		{ free_push_in_ecm(er); }
}

//Format:
//caid:prov:srvid:pid:chid:ecmlen=caid:prov:srvid:pid:chid:ecmlen[,validfrom,validto]
//validfrom: default=-2000
//validto: default=4000
//valid time if found in cache
static struct s_cacheex_matcher *cacheex_matcher_read_int(void)
{
	FILE *fp = open_config_file(cs_cacheex_matcher);
	if(!fp)
		{ return NULL; }

	char token[1024];
	uint8_t type;
	int32_t i, ret, count = 0;
	struct s_cacheex_matcher *new_cacheex_matcher = NULL, *entry, *last = NULL;
	uint32_t line = 0;

	while(fgets(token, sizeof(token), fp))
	{
		line++;
		if(cs_strlen(token) <= 1) { continue; }
		if(token[0] == '#' || token[0] == '/') { continue; }
		if(cs_strlen(token) > 100) { continue; }

		for(i = 0; i < (int)cs_strlen(token); i++)
		{
			if((token[i] == ':' || token[i] == ' ') && token[i + 1] == ':')
			{
				memmove(token + i + 2, token + i + 1, cs_strlen(token) - i + 1);
				token[i + 1] = '0';
			}
			if(token[i] == '#' || token[i] == '/')
			{
				token[i] = '\0';
				break;
			}
		}

		type = 'm';
		uint32_t caid = 0, provid = 0, srvid = 0, pid = 0, chid = 0, ecmlen = 0;
		uint32_t to_caid = 0, to_provid = 0, to_srvid = 0, to_pid = 0, to_chid = 0, to_ecmlen = 0;
		int32_t valid_from = -2000, valid_to = 4000;

		ret = sscanf(token, "%c:%4x:%6x:%4x:%4x:%4x:%4X=%4x:%6x:%4x:%4x:%4x:%4X,%4d,%4d",
					 &type,
					 &caid, &provid, &srvid, &pid, &chid, &ecmlen,
					 &to_caid, &to_provid, &to_srvid, &to_pid, &to_chid, &to_ecmlen,
					 &valid_from, &valid_to);

		type = tolower(type);

		if(ret < 7 || type != 'm')
			{ continue; }

		if(!cs_malloc(&entry, sizeof(struct s_cacheex_matcher)))
		{
			fclose(fp);
			return new_cacheex_matcher;
		}
		count++;
		entry->line = line;
		entry->type = type;
		entry->caid = caid;
		entry->provid = provid;
		entry->srvid = srvid;
		entry->pid = pid;
		entry->chid = chid;
		entry->ecmlen = ecmlen;
		entry->to_caid = to_caid;
		entry->to_provid = to_provid;
		entry->to_srvid = to_srvid;
		entry->to_pid = to_pid;
		entry->to_chid = to_chid;
		entry->to_ecmlen = to_ecmlen;
		entry->valid_from = valid_from;
		entry->valid_to = valid_to;

		cs_log_dbg(D_TRACE, "cacheex-matcher: %c: %04X@%06X:%04X:%04X:%04X:%02X = %04X@%06X:%04X:%04X:%04X:%02X valid %d/%d",
					entry->type, entry->caid, entry->provid, entry->srvid, entry->pid, entry->chid, entry->ecmlen,
					entry->to_caid, entry->to_provid, entry->to_srvid, entry->to_pid, entry->to_chid, entry->to_ecmlen,
					entry->valid_from, entry->valid_to);

		if(!new_cacheex_matcher)
		{
			new_cacheex_matcher = entry;
			last = new_cacheex_matcher;
		}
		else
		{
			last->next = entry;
			last = entry;
		}
	}

	if(count)
		{ cs_log("%d entries read from %s", count, cs_cacheex_matcher); }

	fclose(fp);

	return new_cacheex_matcher;
}

void cacheex_load_config_file(void)
{
	struct s_cacheex_matcher *entry, *old_list;

	old_list = cfg.cacheex_matcher;
	cfg.cacheex_matcher = cacheex_matcher_read_int();

	while(old_list)
	{
		entry = old_list->next;
		NULLFREE(old_list);
		old_list = entry;
	}
}

CWCHECK get_cwcheck(ECM_REQUEST *er)
{
	int32_t i;
	int8_t mode = 0;
	int16_t counter = 1;

	for(i = 0; i < cfg.cacheex_cwcheck_tab.cwchecknum; i++)
	{
		CWCHECKTAB_DATA *d = &cfg.cacheex_cwcheck_tab.cwcheckdata[i];

		if(i == 0 && d->caid <= 0)
		{
			mode = d->mode;
			counter = d->counter;
			continue; //check other, only valid for unset
		}

		if(d->caid == er->caid || d->caid == er->caid >> 8 || ((d->cmask >= 0 && (er->caid & d->cmask) == d->caid) || d->caid == -1))
		{
			if((d->prid >= 0 && d->prid == (int32_t)er->prid) || d->prid == -1)
			{
				if((d->srvid >= 0 && d->srvid == er->srvid) || d->srvid == -1)
				{
					mode = d->mode;
					counter = d->counter;
					break;
				}
			}

		}
	}

	//check for correct values
	if(mode>2 || mode<0) mode=0;
	if(counter<1) counter=1;

	CWCHECK check_cw;
	memset(&check_cw, 0, sizeof(CWCHECK));
	check_cw.mode = mode;
	check_cw.counter = counter;

	return check_cw;
}

uint16_t get_cacheex_mode1_delay(ECM_REQUEST *er)
{
	return caidvaluetab_get_value(&cfg.cacheex_mode1_delay_tab, er->caid, 0);
}

uint32_t get_cacheex_wait_time(ECM_REQUEST *er, struct s_client *cl)
{
	int32_t i, dwtime = -1, awtime = -1;

	for(i = 0; i < cfg.cacheex_wait_timetab.cevnum; i++)
	{
		CECSPVALUETAB_DATA *d = &cfg.cacheex_wait_timetab.cevdata[i];

		if(i == 0 && d->caid <= 0)
		{
			dwtime = d->dwtime;
			awtime = d->awtime;
			continue; //check other, only valid for unset
		}

		if(d->caid == er->caid || d->caid == er->caid >> 8 || ((d->cmask >= 0 && (er->caid & d->cmask) == d->caid) || d->caid == -1))
		{
			if((d->prid >= 0 && d->prid == (int32_t)er->prid) || d->prid == -1)
			{
				if((d->srvid >= 0 && d->srvid == er->srvid) || d->srvid == -1)
				{
					dwtime = d->dwtime;
					awtime = d->awtime;
					break;
				}
			}

		}

	}
	if(awtime > 0 && (dwtime <= 0 || awtime==dwtime) ) //if awtime==dwtime useless check hitcache
	{
		return awtime;
	}
	if(cl == NULL)
	{
		if(dwtime < 0)
			{ dwtime = 0; }
		return dwtime;
	}
	if(awtime > 0 || dwtime > 0)
	{
		//if found last in cache return dynwaittime else alwayswaittime
		if(cacheex_check_hitcache(er,cl))
			{ return dwtime >= awtime ? dwtime : awtime; }
		else
			{ return awtime > 0 ? awtime : 0; }
	}
	return 0;
}


int32_t chk_csp_ctab(ECM_REQUEST *er, CECSPVALUETAB *tab)
{
	if(!er->caid || !tab->cevnum)
		{ return 1; } // nothing setup we add all
	int32_t i;
	for(i = 0; i < tab->cevnum; i++)
	{
		CECSPVALUETAB_DATA *d = &tab->cevdata[i];
		if(d->caid > 0)
		{
			if(d->caid == er->caid || d->caid == er->caid >> 8 || ((d->cmask >= 0 && (er->caid & d->cmask) == d->caid) || d->caid == -1))
			{
				if((d->prid >= 0 && d->prid == (int32_t)er->prid) || d->prid == -1)
				{
					if((d->srvid >= 0 && d->srvid == er->srvid) || d->srvid == -1)
					{
						return 1;
					}
				}
			}
		}
	}
	return 0;
}

void cacheex_push_out(struct s_client *cl, ECM_REQUEST *er)
{
	int32_t res = 0, stats = -1;
	struct s_reader *reader = cl->reader;
	struct s_module *module = get_module(cl);

	// cc-nodeid-list-check
	if(reader)
	{
		if(reader->ph.c_cache_push_chk && !reader->ph.c_cache_push_chk(cl, er))
			return;
		res = reader->ph.c_cache_push(cl, er);
#ifdef CS_CACHEEX_AIO
		stats = cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 0, er->localgenerated);
#else
		stats = cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 0);
#endif
	}
	else
	{
		if(module->c_cache_push_chk && !module->c_cache_push_chk(cl, er))
			return;
		res = module->c_cache_push(cl, er);
	}
	debug_ecm(D_CACHEEX, "pushed ECM %s to %s res %d stats %d", buf, username(cl), res, stats);
	cl->cwcacheexpush++;
	if(cl->account)
		{ cl->account->cwcacheexpush++; }
	first_client->cwcacheexpush++;

#ifdef CS_CACHEEX_AIO
	if(er->localgenerated)
	{
		cl->cwcacheexpushlg++;
		if(cl->account)
			cl->account->cwcacheexpushlg++;
		first_client->cwcacheexpushlg++;
	}
#endif
}

bool cacheex_check_queue_length(struct s_client *cl)
{
	// Avoid full running queues:
	if(ll_count(cl->joblist) <= 2000)
		return 0;

	cs_log_dbg(D_TRACE, "WARNING: job queue %s %s has more than 2000 jobs! count=%d, dropped!",
					cl->typ == 'c' ? "client" : "reader", username(cl), ll_count(cl->joblist));

	// Thread down???
	SAFE_MUTEX_LOCK(&cl->thread_lock);
	if(cl && !cl->kill && cl->thread && cl->thread_active)
	{
		// Just test for invalid thread id:
		if(pthread_detach(cl->thread) == ESRCH)
		{
			cl->thread_active = 0;
			cs_log_dbg(D_TRACE, "WARNING: %s %s thread died!", cl->typ == 'c' ? "client" : "reader", username(cl));
		}
	}
	SAFE_MUTEX_UNLOCK(&cl->thread_lock);
	return 1;
}

void cacheex_mode1_delay(ECM_REQUEST *er)
{
	if(!er->cacheex_wait_time_expired && er->cacheex_mode1_delay
		&& er->cacheex_reader_count > 0 && !er->stage && er->rc >= E_UNHANDLED)
	{
		cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} cacheex_mode1_delay timeout! ",
					(check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid);

		// setting stop_stage=1, we request only cacheex mode 1 readers. Others are requested at cacheex timeout!
		request_cw_from_readers(er, 1);
	}
}

void cacheex_timeout(ECM_REQUEST *er)
{
	if(er->cacheex_wait_time_expired)
		return;
	er->cacheex_wait_time_expired = 1;
	if(er->rc >= E_UNHANDLED)
	{
		cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} cacheex timeout! ",
					(check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid);

#ifdef CS_CACHEEX_AIO
		CACHE_HIT *result;
		HIT_KEY search;

		memset(&search, 0, sizeof(HIT_KEY));
		search.caid = er->caid;
		search.prid = er->prid;
		search.srvid = er->srvid;

		SAFE_RWLOCK_WRLOCK(&hitcache_lock);

		result = find_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &cacheex_compare_hitkey);
		if(result)
		{
			if(cfg.waittime_block_start && (result->waittime_block <= cfg.waittime_block_start))
			{
				result->waittime_block++;
				cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} waittime_block count: %u ",
					(check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, result->waittime_block);
			}
		}

		SAFE_RWLOCK_UNLOCK(&hitcache_lock);
#endif
		// if check_cw mode=0, first try to get cw from cache without check counter!
		CWCHECK check_cw = get_cwcheck(er);
		if(!check_cw.mode)
		{
			struct ecm_request_t *ecm = NULL;
			ecm = check_cache(er, er->client);

			if(ecm) // found in cache
			{
				struct s_write_from_cache *wfc = NULL;
				if(!cs_malloc(&wfc, sizeof(struct s_write_from_cache)))
				{
					NULLFREE(ecm);
					return;
				}
				wfc->er_new = er;
				wfc->er_cache = ecm;
				if(!add_job(er->client, ACTION_ECM_ANSWER_CACHE, wfc, sizeof(struct s_write_from_cache))) // write_ecm_answer_fromcache
					{ NULLFREE(ecm); }
				return;
			}
		}

		// check if "normal" readers selected, if not send NOT FOUND!
		// cacheex1-client (having always no "normal" reader),
		// or not-cacheex-1 client with no normal readers available (or filtered by LB)
		if((er->reader_count + er->fallback_reader_count - er->cacheex_reader_count) <= 0)
		{
			if(!cfg.wait_until_ctimeout)
			{
				er->rc = E_NOTFOUND;
				er->selected_reader = NULL;
				er->rcEx = 0;
				cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} cacheex timeout: NO \"normal\" readers... not_found! ",
							(check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid);

				send_dcw(er->client, er);
				return;
			}
		}
		else
		{
			if(er->stage < 2)
			{
				debug_ecm(D_TRACE, "request for %s %s", username(er->client), buf);
				request_cw_from_readers(er, 0);
			}
		}
	}
}

#ifdef CS_CACHEEX_AIO
char* cxaio_ftab_to_buf(FTAB *lg_only_ftab)
{
	int32_t i, k, l = 0, strncat_sz = 0;
	char *ret;
	char caid[5];
	char provid[7];
	char nprids[3];

	// get size of return-val
	for(i = 0; i < lg_only_ftab->nfilts; i++)
	{
		l += 4; // caid
		l += 2; // nprid-counter
		l += 6 * lg_only_ftab->filts[i].nprids; // prid/s

		if(!lg_only_ftab->filts[i].nprids)
		{
			l += 6;
		}
	}

	if(!cs_malloc(&ret, l * sizeof(char) + sizeof(char))) {
		return "";
		}

	strncat_sz += l * sizeof(char) + sizeof(char);

	for(i = 0; i < lg_only_ftab->nfilts; i++)
	{
		snprintf(caid, 5, "%04X", lg_only_ftab->filts[i].caid);
		if (!cs_strncat(ret, caid, strncat_sz)) {
			cs_log("FIXME!");
		}

		if(!lg_only_ftab->filts[i].nprids)
		{
			if (!cs_strncat(ret, "01", strncat_sz)) {
				cs_log("FIXME2!");
			}
			snprintf(provid, 7, "000000");
			if (!cs_strncat(ret, provid, strncat_sz)) {
				cs_log("FIXME3!");
			}
		}
		else
		{
			snprintf(nprids, 3, "%02X", lg_only_ftab->filts[i].nprids);
			if (!cs_strncat(ret, nprids, strncat_sz)) {
				cs_log("FIXME4!");
			}
		}

		for(k = 0; k < lg_only_ftab->filts[i].nprids; k++)
		{
			snprintf(provid, 7, "%06X", lg_only_ftab->filts[i].prids[k]);
			if (!cs_strncat(ret, provid, strncat_sz)) {
				cs_log("FIXME5!");
			}
		}
	}
	return ret;
}

FTAB caidtab2ftab(CAIDTAB *ctab)
{
	int i;
	FTAB ftab;
	memset(&ftab, 0, sizeof(ftab));

	for(i=0; i<ctab->ctnum; i++)
	{
		FILTER d;
		memset(&d, 0, sizeof(d));
		d.caid = ctab->ctdata[i].caid;
		d.prids[d.nprids] = NO_PROVID_VALUE;
		d.nprids++;
		ftab_add(&ftab, &d);
	}
	return ftab;
}

void caidtab2ftab_add(CAIDTAB *lgonly_ctab, FTAB *lgonly_tab)
{
	int j, k, l, rc;
	for(j = 0; j < lgonly_ctab->ctnum; j++)
	{
		CAIDTAB_DATA *d = &lgonly_ctab->ctdata[j];
		if(d->caid)
		{
			rc = 0;
			if(lgonly_tab->nfilts)
			{
				for(k = 0; (k < lgonly_tab->nfilts); k++)
				{
					if(lgonly_tab->filts[k].caid != 0 && lgonly_tab->filts[k].caid == d->caid)
					{
						for(l = 0; (l < lgonly_tab->filts[k].nprids); l++)
						{
							if(lgonly_tab->filts[k].prids[l] == NO_PROVID_VALUE)
							{
								rc = 1;
								break;
							}
						}
						if(!rc)
						{
							lgonly_tab->filts[k].nprids = 1;
							lgonly_tab->filts[k].prids[0] = NO_PROVID_VALUE;
							rc = 1;
						}
						break;
					}
				}
			}
			if(!rc)	// caid not found
				{
					FILTER df;
					memset(&df, 0, sizeof(df));
					df.caid = d->caid;
					df.prids[0] = NO_PROVID_VALUE;
					df.nprids++;
					ftab_add(lgonly_tab, &df);
				}
		}
	}
}
#endif
#endif
