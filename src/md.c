/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2005-2006, 2010, 2019-2024 Rami Lehti,
 *               Pablo Virolainen, Richard van den Berg, Hannes von Haugwitz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "attributes.h"
#include "db_line.h"
#include "db_config.h"
#include "base64.h"
#include "hashsum.h"
#include "log.h"
#include "md.h"
#include "util.h"
#include "errorcodes.h"

#ifdef WITH_GCRYPT
#include <gcrypt.h>
#endif

#ifdef WITH_NETTLE
#include <nettle/nettle-types.h>
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/sha3.h>
#include <nettle/ripemd160.h>
#include <nettle/gosthash94.h>
#include <nettle/streebog.h>

typedef struct {
  nettle_hash_init_func *init;
  nettle_hash_update_func *update;
  nettle_hash_digest_func *digest;
} nettle_fucntions_t;

nettle_fucntions_t nettle_functions[] = {  /* order must match hashsums array */
    { (nettle_hash_init_func*) md5_init,    (nettle_hash_update_func*) md5_update,    (nettle_hash_digest_func*) md5_digest    },
    { (nettle_hash_init_func*) sha1_init,   (nettle_hash_update_func*) sha1_update,   (nettle_hash_digest_func*) sha1_digest   },
    { (nettle_hash_init_func*) sha256_init, (nettle_hash_update_func*) sha256_update, (nettle_hash_digest_func*) sha256_digest },
    { (nettle_hash_init_func*) sha512_init, (nettle_hash_update_func*) sha512_update, (nettle_hash_digest_func*) sha512_digest },
    { (nettle_hash_init_func*) ripemd160_init, (nettle_hash_update_func*) ripemd160_update, (nettle_hash_digest_func*) ripemd160_digest },
    { NULL,                                 NULL,                                     NULL                                     },
    { NULL,                                 NULL,                                     NULL                                     },
    { NULL,                                 NULL,                                     NULL                                     },
    { NULL,                                 NULL,                                     NULL                                     },
    { NULL,                                 NULL,                                     NULL                                     },
    { (nettle_hash_init_func*) gosthash94_init, (nettle_hash_update_func*) gosthash94_update, (nettle_hash_digest_func*) gosthash94_digest },
    { (nettle_hash_init_func*) streebog256_init, (nettle_hash_update_func*) streebog256_update, (nettle_hash_digest_func*) streebog256_digest },
    { (nettle_hash_init_func*) streebog512_init, (nettle_hash_update_func*) streebog512_update, (nettle_hash_digest_func*) streebog512_digest },
    { (nettle_hash_init_func*) sha512_256_init, (nettle_hash_update_func*) sha512_256_update, (nettle_hash_digest_func*) sha512_256_digest },
    { (nettle_hash_init_func*) sha3_256_init, (nettle_hash_update_func*) sha3_256_update, (nettle_hash_digest_func*) sha3_256_digest },
    { (nettle_hash_init_func*) sha3_512_init, (nettle_hash_update_func*) sha3_512_update, (nettle_hash_digest_func*) sha3_512_digest },
};
#endif

/*
  Initialise md_container according its todo_attr field
 */

int init_md(struct md_container* md, const char *filename) {
  
  /*    First we check the parameter..   */
#ifdef _PARAMETER_CHECK_
  if (md==NULL) {
    return RETFAIL;  
  }
#endif
  /*
    We don't have calculator for this yet :)
  */
  md->calc_attr=0;
#ifdef WITH_NETTLE
   for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
       DB_ATTR_TYPE h = ATTR(hashsums[i].attribute);
       if (h&md->todo_attr) {
           nettle_functions[i].init(&md->ctx[i]);
           md->calc_attr|=h;
       }
   }
#endif
#ifdef WITH_GCRYPT
	if(gcry_md_open(&md->mdh,0,0)!=GPG_ERR_NO_ERROR){
		log_msg(LOG_LEVEL_ERROR,"gcrypt_md_open failed");
		exit(IO_ERROR);
	}

   for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
        DB_ATTR_TYPE h = ATTR(hashsums[i].attribute);
            if (h&md->todo_attr) {
                if(gcry_md_enable(md->mdh,algorithms[i])==GPG_ERR_NO_ERROR){
                    md->calc_attr|=h;
                } else {
                    log_msg(LOG_LEVEL_WARNING,"%s: gcry_md_enable (%s) failed for '%s'", filename, attributes[hashsums[i].attribute].db_name, filename);
                    md->todo_attr&=~h;
                }
            }
  }
#endif
  char *str;
  log_msg(LOG_LEVEL_DEBUG, "%s> initialized md_container: %s (%p)", filename, str = diff_attributes(0, md->calc_attr), (void*) md);
  free(str);
  return RETOK;
}

/*
  update :)
  Just call this when you have more data.
 */

int update_md(struct md_container* md,void* data,ssize_t size) {
  log_msg(LOG_LEVEL_TRACE,"update_md(md=%p, data=%p, size=%zi)", (void*) md, (void*) data, size);

#ifdef _PARAMETER_CHECK_
  if (md==NULL||data==NULL) {
    return RETFAIL;
  }
#endif

#ifdef WITH_NETTLE
   for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
       DB_ATTR_TYPE h = ATTR(hashsums[i].attribute);
       if (h&md->calc_attr) {
           nettle_functions[i].update(&md->ctx[i], size, data);
       }
   }
#endif
#ifdef WITH_GCRYPT
	gcry_md_write(md->mdh, data, size);
#endif
  return RETOK;
}

/*
  close.. Does some magic.
  After this calling update_db is not a good idea.
*/

int close_md(struct md_container* md, md_hashsums * hs, const char *filename) {
#ifdef _PARAMETER_CHECK_
  if (md==NULL) {
    return RETFAIL;
  }
#endif
  log_msg(LOG_LEVEL_DEBUG, "%s> free md_container (%p)", filename, (void*) md);
#ifdef WITH_GCRYPT
  gcry_md_final(md->mdh); 

  if (hs) {
      for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
          if (md->calc_attr&ATTR(hashsums[i].attribute)) {
              memcpy(hs->hashsums[i],gcry_md_read(md->mdh, algorithms[i]), hashsums[i].length);
          }
      }
  }

  gcry_md_reset(md->mdh);
#endif  

#ifdef WITH_NETTLE
  if (hs) {
      for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
          DB_ATTR_TYPE h = ATTR(hashsums[i].attribute);
          if (h&md->calc_attr) {
              nettle_functions[i].digest(&md->ctx[i].md5, hashsums[i].length, hs->hashsums[i]);
          }
      }
  }
#endif
  if (hs) {
      hs->attrs = md->calc_attr;
  }
  return RETOK;
}

DB_ATTR_TYPE copy_hashsums(char *context, md_hashsums *hs, byte* (*target)[num_hashes]) {
    DB_ATTR_TYPE disabled_hashsums = 0LL;
    for (int i = 0 ; i < num_hashes ; ++i) {
        DB_ATTR_TYPE attr = ATTR(hashsums[i].attribute);
        if (hs->attrs&attr) {
            (*target)[i] = checked_malloc(hashsums[i].length);
            memcpy((*target)[i],hs->hashsums[i],hashsums[i].length);
            char* hashsum_str = encode_base64((*target)[i], hashsums[i].length);
            log_msg(LOG_LEVEL_TRACE, "%s: copy %s hashsum (%s) to %p", context, attributes[hashsums[i].attribute].db_name, hashsum_str, (void*) (*target)[i]);
            free (hashsum_str);
        } else {
            disabled_hashsums |= attr;
            (*target)[i] = NULL;
        }
    }
    return disabled_hashsums;
}

/*
  Writes md_container to db_line.
 */

void hashsums2line(md_hashsums *hs, struct db_line* line) {
  
#ifdef _PARAMETER_CHECK_
  if (md==NULL||line==NULL) {
    return RETFAIL;
  }
#endif

  line->attr &= ~(copy_hashsums(line->filename, hs, &line->hashsums));

}
