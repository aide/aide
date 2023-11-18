/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2005-2006, 2010, 2019-2023 Rami Lehti,
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
#include "hashsum.h"
#include "log.h"
#include "md.h"
#include "util.h"
#include "errorcodes.h"

#ifdef WITH_MHASH
#include <mhash.h>
#endif

#ifdef WITH_GCRYPT
#include <gcrypt.h>
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
#ifdef WITH_MHASH
   for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
       DB_ATTR_TYPE h = ATTR(hashsums[i].attribute);
       if (h&md->todo_attr) {
           md->mhash_mdh[i]=mhash_init(algorithms[i]);
           if (md->mhash_mdh[i]!=MHASH_FAILED) {
               md->calc_attr|=h;
           } else {
               log_msg(LOG_LEVEL_WARNING,"%s: mhash_init (%s) failed for '%s'", filename, attributes[hashsums[i].attribute].db_name, filename);
               md->todo_attr&=~h;
           }
       } else {
           md->mhash_mdh[i]=MHASH_FAILED;
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
  log_msg(LOG_LEVEL_DEBUG, "%s> initialized md_container: %s (%p)", filename, str = diff_attributes(0, md->calc_attr), md);
  free(str);
  return RETOK;
}

/*
  update :)
  Just call this when you have more data.
 */

int update_md(struct md_container* md,void* data,ssize_t size) {
  log_msg(LOG_LEVEL_TRACE,"update_md(md=%p, data=%p, size=%zi)", md, data, size);

#ifdef _PARAMETER_CHECK_
  if (md==NULL||data==NULL) {
    return RETFAIL;
  }
#endif

#ifdef WITH_MHASH
  for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
      if(md->mhash_mdh[i] != MHASH_FAILED){
          mhash(md->mhash_mdh[i], data, size);
      }
  }
#endif /* WITH_MHASH */
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
  log_msg(LOG_LEVEL_DEBUG, "%s> free md_container (%p)", filename, md);
#ifdef WITH_MHASH
  for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
      if(md->mhash_mdh[i] != MHASH_FAILED){
          mhash(md->mhash_mdh[i], NULL, 0);
      }
  }
#endif /* WITH_MHASH */
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

#ifdef WITH_MHASH
  for (HASHSUM i = 0 ; i < num_hashes ; ++i) {
      if(md->mhash_mdh[i]!=MHASH_FAILED){
          mhash_deinit(md->mhash_mdh[i],hs?hs->hashsums[i]:NULL);
      }
  }
#endif
  if (hs) {
      hs->attrs = md->calc_attr;
  }
  return RETOK;
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

   for (int i = 0 ; i < num_hashes ; ++i) {
       DB_ATTR_TYPE attr = ATTR(hashsums[i].attribute);
       if (line->attr&attr) {
           if (hs->attrs&attr) {
               line->hashsums[i] = checked_malloc(hashsums[i].length);
               memcpy(line->hashsums[i],hs->hashsums[i],hashsums[i].length);
           } else {
               line->attr&=~attr;
               line->hashsums[i] = NULL;
           }
       } else {
            line->hashsums[i] = NULL;
        }
   }

}
