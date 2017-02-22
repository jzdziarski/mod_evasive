/*
mod_dosevasive/1.8 for NSAPI
 
Copyright 2002 by Jonathan A. Zdziarski.  All rights reserved.
 
LICENSE
-------
 
This distribution may be freely distributed in its original form.  
License is granted to make modifications to the source for internal,
private use only, provided you retain this notice, disclaimers, author's
copyright, and credits.
 
 
DISCLAIMER
----------
 
THIS SOFTWARE IS PROVIDE "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO WAY SHALL THE
AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
 
*/

/* This is a port to NSAPI from mod_dosevasive/1.8 for Apache 2.0 
   2003-10-29 Reine Persson
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>

#include <nsapi.h>
 

/* BEGIN DoS Evasive Maneuvers Definitions */

#define DEFAULT_LOG_DIR "/tmp"
#define MAILER	"/bin/mail %s"
#define  LOG( A, ... ) { openlog("mod_dosevasive", LOG_PID, LOG_DAEMON); syslog( A, __VA_ARGS__ ); closelog(); }

#define DEFAULT_HASH_TBL_SIZE   3097ul  // Default hash table size
#define DEFAULT_PAGE_COUNT      2       // Default maximum page hit count per interval
#define DEFAULT_SITE_COUNT      50      // Default maximum site hit count per interval
#define DEFAULT_PAGE_INTERVAL   1       // Default 1 Second page interval
#define DEFAULT_SITE_INTERVAL   1       // Default 1 Second site interval
#define DEFAULT_BLOCKING_PERIOD 10      // Default for Detected IPs; blocked for 10 seconds

/* END DoS Evasive Maneuvers Definitions */

static CRITICAL mod_dosevasive_crit;

/* BEGIN NTT (Named Timestamp Tree) Headers */

enum { ntt_num_primes = 28 };

/* ntt root tree */
struct ntt {
    long size;
    long items;
    struct ntt_node **tbl;
};

/* ntt node (entry in the ntt root tree) */
struct ntt_node {
    char *key;
    time_t timestamp;
    long count;
    struct ntt_node *next;
};

/* ntt cursor */
struct ntt_c {
  long iter_index;
  struct ntt_node *iter_next;
};

struct ntt *ntt_create(long size);
int ntt_destroy(struct ntt *ntt);
struct ntt_node	*ntt_find(struct ntt *ntt, const char *key);
struct ntt_node	*ntt_insert(struct ntt *ntt, const char *key, time_t timestamp);
int ntt_delete(struct ntt *ntt, const char *key);
long ntt_hashcode(struct ntt *ntt, const char *key);	
struct ntt_node *c_ntt_first(struct ntt *ntt, struct ntt_c *c);
struct ntt_node *c_ntt_next(struct ntt *ntt, struct ntt_c *c);

/* END NTT (Named Timestamp Tree) Headers */


/* BEGIN DoS Evasive Maneuvers Globals */

struct ntt *hit_list;	// Our dynamic hash table

static unsigned long hash_table_size = DEFAULT_HASH_TBL_SIZE;
static int page_count = DEFAULT_PAGE_COUNT;
static int page_interval = DEFAULT_PAGE_INTERVAL;
static int site_count = DEFAULT_SITE_COUNT;
static int site_interval = DEFAULT_SITE_INTERVAL;
static int blocking_period = DEFAULT_BLOCKING_PERIOD;
static char *log_dir = NULL;
static char *email_notify = NULL;
static char *system_command = NULL;

static const char * whitelist(const char *ip);
int is_whitelisted(const char *ip);
static int destroy_hit_list(void *not_used);

/* END DoS Evasive Maneuvers Globals */

static char *
itemize(char *str,char delim)
{
    static char *nextitem = NULL;
    char *result;
 
    if(str)
        nextitem=str;
    if(!nextitem)
        return(NULL);
    result=nextitem;
    while(*nextitem && *nextitem!=delim) 
        ++nextitem;
    if(*nextitem) 
        *nextitem++='\0';
    else 
        nextitem=NULL;
    return(result);
}

 
NSAPI_PUBLIC int
mod_dosevasive_init(pblock *pb, Session *sn, Request *rq)
{
  char *ip,*stmp,*white_list=NULL;
  int itmp;

  mod_dosevasive_crit = crit_init();
  if ((itmp=atoi(pblock_findval("DOSHashTableSize", pb))) != 0 )
    hash_table_size=itmp;
  if ((itmp=atoi(pblock_findval("DOSPageCount", pb))) != 0 )
    page_count=itmp;
  if ((itmp=atoi(pblock_findval("DOSSiteCount", pb))) != 0 )
    site_count=itmp;
  if ((itmp=atoi(pblock_findval("DOSPageInterval", pb))) != 0 )
    page_interval=itmp;
  if ((itmp=atoi(pblock_findval("DOSSiteInterval", pb))) != 0 )
    site_interval=itmp;
  if ((itmp=atoi(pblock_findval("DOSBlockingPeriod", pb))) != 0 )
    blocking_period=itmp;
  if ((stmp=pblock_findval("DOSLogDir", pb)) != NULL )
    log_dir=stmp;
  if ((stmp=pblock_findval("DOSEmailNotify", pb)) != NULL )
    email_notify=stmp;
  if ((stmp=pblock_findval("DOSSystemCommand", pb)) != NULL )
    system_command=stmp;

  white_list=pblock_findval("DOSWhitelist", pb);

  hit_list = ntt_create(hash_table_size);

  if ( white_list != NULL ) {
    ip=itemize(white_list,',');
    while( ip != NULL ) {
      whitelist(ip);
      ip=itemize(NULL,',');
    }
  }
  return REQ_PROCEED;
}
 
NSAPI_PUBLIC int
mod_dosevasive_check(pblock *pb, Session *sn, Request *rq)
{
  int ret = REQ_PROCEED;

  /* BEGIN DoS Evasive Maneuvers Code */
  
  if (pblock_findval("NS_original_uri",rq->vars) == NULL && pblock_findval("referer",rq->headers) == NULL && hit_list != NULL) {
    char hash_key[2048];
    struct ntt_node *n;
    time_t t = time(NULL);

    /* Check whitelist */
    if (is_whitelisted(pblock_findval("ip",sn->client))) 
      return REQ_PROCEED;
    
    /* First see if the IP itself is on "hold" */
    n = ntt_find(hit_list, pblock_findval("ip",sn->client));
    
    if (n != NULL && t-n->timestamp<blocking_period) {
      
      /* If the IP is on "hold", make it wait longer in 403 land */
      ret = REQ_ABORTED;
      n->timestamp = time(NULL);
      
      /* Not on hold, check hit stats */
    } else {
      
      /* Has URI been hit too much? */
      snprintf(hash_key, 2048, "%s_%s", pblock_findval("ip",sn->client), pblock_findval("uri",rq->reqpb));
      n = ntt_find(hit_list, hash_key);
      if (n != NULL) {
	
	/* If URI is being hit too much, add to "hold" list and 403 */
	if (t-n->timestamp<page_interval && n->count>=page_count) {
	  ret = REQ_ABORTED;
	  ntt_insert(hit_list, pblock_findval("ip",sn->client), time(NULL));
	} else {
	  
	  /* Reset our hit count list as necessary */
	  if (t-n->timestamp>=page_interval) {
	    n->count=0;
	  }
	}
	n->timestamp = t;
	n->count++;
      } else {
	
	ntt_insert(hit_list, hash_key, t);
      }
      
      /* Has site been hit too much? */
      snprintf(hash_key, 2048, "%s_SITE", pblock_findval("ip",sn->client));
      n = ntt_find(hit_list, hash_key);
      if (n != NULL) {
	
	/* If site is being hit too much, add to "hold" list and 403 */
	if (t-n->timestamp<site_interval && n->count>=site_count) {
	  ret = REQ_ABORTED;
	  ntt_insert(hit_list, pblock_findval("ip",sn->client), time(NULL));
	} else {
	  
	  /* Reset our hit count list as necessary */
	  if (t-n->timestamp>=site_interval) {
	    n->count=0;
	  }
	}
	n->timestamp = t;
	n->count++;
      } else {
	ntt_insert(hit_list, hash_key, t);
      }
    }
    
    /* Perform email notification and system functions */
    if (ret == REQ_ABORTED) {
      char filename[1024];
      struct stat s;
      FILE *file;
      
      snprintf(filename, sizeof(filename), "%s/dos-%s", log_dir != NULL ? log_dir : DEFAULT_LOG_DIR, pblock_findval("ip",sn->client));
      if (stat(filename, &s)) {
	file = fopen(filename, "w");
	if (file != NULL) {
	  fprintf(file, "%ld\n", getpid());
	  fclose(file);
	  
	  LOG(LOG_ALERT, "Blacklisting address %s: possible DoS attack.",pblock_findval("ip",sn->client));
	  if (email_notify != NULL) {
	    snprintf(filename, sizeof(filename), MAILER, email_notify);
	    file = popen(filename, "w");
	    if (file != NULL) {
	      fprintf(file, "To: %s\n", email_notify);
	      fprintf(file, "Subject: HTTP BLACKLIST %s\n\n", pblock_findval("ip",sn->client));
	      fprintf(file, "mod_dosevasive HTTP Blacklisted %s\n", pblock_findval("ip",sn->client));
	      pclose(file);
	    } else {
	      LOG(LOG_ALERT, "Couldn't open logfile %s: %s",filename, strerror(errno));
	    }
	  }
	  
	  if (system_command != NULL) {
	    snprintf(filename, sizeof(filename), system_command, pblock_findval("ip",sn->client));
	    system(filename);
	  }
	  
	}
	
      } /* if (temp file does not exist) */
      
    } /* if (ret == REQ_ABORTED) */
    
  } /* if (vars->NS_Original_uri == NULL && headers->referer == NULL && hit_list != NULL) */
  
  /* END DoS Evasive Maneuvers Code */
  
  if (ret == REQ_ABORTED ) {
    log_error(LOG_SECURITY,"mod_dosevasive_check",sn,rq,"client denied by server configuration: %s",pblock_findval("uri",rq->reqpb));
    protocol_status(sn, rq, PROTOCOL_FORBIDDEN, NULL);
  }
  return ret;
}


static const char *whitelist(const char *ip)
{
  char entry[128];
  snprintf(entry, sizeof(entry), "WHITELIST_%s", ip);
  ntt_insert(hit_list, entry, time(NULL));
  
  return NULL;
}


int is_whitelisted(const char *ip) {
  char hashkey[128];
  char octet[4][4];
  char *dip;
  char *oct;
  int i = 0;
  
  memset(octet, 0, 16);
  dip = strdup(ip);
  if (dip == NULL)
    return 0;
  
  oct = strtok(dip, ".");
  while(oct != NULL && i<4) {
    if (strlen(oct)<=3) 
      strcpy(octet[i], oct);
    i++;
    oct = strtok(NULL, ".");
  }
  free(dip);
  
  /* Exact Match */
  snprintf(hashkey, sizeof(hashkey), "WHITELIST_%s", ip); 
  if (ntt_find(hit_list, hashkey)!=NULL)
    return 1;
  
  /* IPv4 Wildcards */ 
  snprintf(hashkey, sizeof(hashkey), "WHITELIST_%s.*.*.*", octet[0]);
  if (ntt_find(hit_list, hashkey)!=NULL)
    return 1;

  snprintf(hashkey, sizeof(hashkey), "WHITELIST_%s.%s.*.*", octet[0], octet[1]);
  if (ntt_find(hit_list, hashkey)!=NULL)
    return 1;
  
  snprintf(hashkey, sizeof(hashkey), "WHITELIST_%s.%s.%s.*", octet[0], octet[1], octet[2]);
  if (ntt_find(hit_list, hashkey)!=NULL)
    return 1;
  
  /* No match */
  return 0;
}

static int destroy_hit_list(void *not_used) {
  ntt_destroy(hit_list);
  free(log_dir);
  free(email_notify);
  free(system_command);
  return 0;
}


/* BEGIN NTT (Named Timestamp Tree) Functions */

static unsigned long ntt_prime_list[ntt_num_primes] = 
{
  53ul,         97ul,         193ul,       389ul,       769ul,
  1543ul,       3079ul,       6151ul,      12289ul,     24593ul,
  49157ul,      98317ul,      196613ul,    393241ul,    786433ul,
  1572869ul,    3145739ul,    6291469ul,   12582917ul,  25165843ul,
  50331653ul,   100663319ul,  201326611ul, 402653189ul, 805306457ul,
  1610612741ul, 3221225473ul, 4294967291ul
};


/* Find the numeric position in the hash table based on key and modulus */

long ntt_hashcode(struct ntt *ntt, const char *key) {
  unsigned long val = 0;
  for (; *key; ++key) val = 5 * val + *key;
  return(val % ntt->size);
}

/* Creates a single node in the tree */

struct ntt_node *ntt_node_create(const char *key) {
  char *node_key;
  struct ntt_node* node;
  
  node = (struct ntt_node *) malloc(sizeof(struct ntt_node));
  if (node == NULL) {
    return NULL;
  }
  if ((node_key = strdup(key)) == NULL) {
    free(node);
    return NULL;
  }
  node->key = node_key;
  node->timestamp = time(NULL);
  node->next = NULL;
  return(node);
}

/* Tree initializer */

struct ntt *ntt_create(long size) {
  long i = 0;
  struct ntt *ntt = (struct ntt *) malloc(sizeof(struct ntt));
  
  if (ntt == NULL)
    return NULL;
  while (ntt_prime_list[i] < size) { i++; }
  ntt->size  = ntt_prime_list[i];
  ntt->items = 0;
  ntt->tbl   = (struct ntt_node **) calloc(ntt->size, sizeof(struct ntt_node *));
  if (ntt->tbl == NULL) {
        free(ntt);
        return NULL;
  }
  return(ntt);
}

/* Find an object in the tree */

struct ntt_node *ntt_find(struct ntt *ntt, const char *key) {
  long hash_code;
  struct ntt_node *node;
  
  if (ntt == NULL) return NULL;
  
  hash_code = ntt_hashcode(ntt, key);
  node = ntt->tbl[hash_code];
  
  while (node) {
    if (!strcmp(key, node->key)) {
      return(node);
    }
    node = node->next;
  }
  return((struct ntt_node *)NULL);
}

/* Insert a node into the tree */

struct ntt_node *ntt_insert(struct ntt *ntt, const char *key, time_t timestamp) {
  long hash_code;
  struct ntt_node *parent;
  struct ntt_node *node;
  struct ntt_node *new_node = NULL;
  
  if (ntt == NULL) return NULL;
  
  hash_code = ntt_hashcode(ntt, key);
  parent	= NULL;
  node	= ntt->tbl[hash_code];
  
  crit_enter(mod_dosevasive_crit); /*Lock*/

  while (node != NULL) {
    if (strcmp(key, node->key) == 0) { 
      new_node = node;
      node = NULL;
    }
    
    if (new_node == NULL) {
      parent = node;
      node = node->next;
    }
  }
  
  if (new_node != NULL) {
    new_node->timestamp = timestamp;
    new_node->count = 0;
    crit_exit(mod_dosevasive_crit); /*Unlock*/
    return new_node; 
  }
  
  /* Create a new node */
  new_node = ntt_node_create(key);
  new_node->timestamp = timestamp;
  new_node->timestamp = 0;
  
  ntt->items++;
  
  /* Insert */
  if (parent) {  /* Existing parent */
    parent->next = new_node;
    crit_exit(mod_dosevasive_crit); /*Unlock*/
    return new_node;  /* Return the locked node */
  }
  
  /* No existing parent; add directly to hash table */
  ntt->tbl[hash_code] = new_node;
  crit_exit(mod_dosevasive_crit); /*Unlock*/
  return new_node;
}

/* Tree destructor */

int ntt_destroy(struct ntt *ntt) {
  struct ntt_node *node, *next;
  struct ntt_c c;
  
  if (ntt == NULL) return -1;
  
  node = c_ntt_first(ntt, &c);
  while(node != NULL) {
    next = c_ntt_next(ntt, &c);
    ntt_delete(ntt, node->key);
    node = next;
  }
  
  free(ntt->tbl);
  free(ntt);
  ntt = (struct ntt *) NULL;
  
  return 0;
}

/* Delete a single node in the tree */

int ntt_delete(struct ntt *ntt, const char *key) {
  long hash_code;
  struct ntt_node *parent = NULL;
  struct ntt_node *node;
  struct ntt_node *del_node = NULL;
  
  if (ntt == NULL) return -1;
  
  hash_code = ntt_hashcode(ntt, key);
  node        = ntt->tbl[hash_code];
  
  while (node != NULL) {
    if (strcmp(key, node->key) == 0) {
      del_node = node;
      node = NULL;
    }
    
    if (del_node == NULL) {
      parent = node;
      node = node->next;
    }
  }
  
  if (del_node != NULL) {
    
    if (parent) {
      parent->next = del_node->next;
    } else {
      ntt->tbl[hash_code] = del_node->next;
    }
    
    free(del_node->key);
    free(del_node);
    ntt->items--;
    
    return 0;
  }
  
  return -5;
}

/* Point cursor to first item in tree */

struct ntt_node *c_ntt_first(struct ntt *ntt, struct ntt_c *c) {
  
  c->iter_index = 0;
  c->iter_next = (struct ntt_node *)NULL;
  return(c_ntt_next(ntt, c));
}

/* Point cursor to next iteration in tree */

struct ntt_node *c_ntt_next(struct ntt *ntt, struct ntt_c *c) {
  long index;
  struct ntt_node *node = c->iter_next;
  
  if (ntt == NULL) return NULL;
  
  if (node) {
    if (node != NULL) {
      c->iter_next = node->next;
      return (node);
    }
  }
  
  if (! node) {
    while (c->iter_index < ntt->size) {
      index = c->iter_index++;
      
      if (ntt->tbl[index]) {
	c->iter_next = ntt->tbl[index]->next;
	return(ntt->tbl[index]);
      }
    }
  }
  return((struct ntt_node *)NULL);
}

/* END NTT (Named Pointer Tree) Functions */
