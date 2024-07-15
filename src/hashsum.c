/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2020,2022,2024 Hannes von Haugwitz
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

#include <stdbool.h>
#include <stdlib.h>
#include "config.h"
#include "attributes.h"
#include "hashsum.h"
#include "log.h"
#include "errorcodes.h"

#ifdef WITH_GCRYPT
#include <gcrypt.h>
#define NEED_LIBGCRYPT_VERSION "1.8.0"
#endif

hashsum_t hashsums[] = {
    { attr_md5,             16 },
    { attr_sha1,            20 },
    { attr_sha256,          32 },
    { attr_sha512,          64 },
    { attr_rmd160,          20 },
    { attr_tiger,           24 },
    { attr_crc32,           4  },
    { attr_crc32b,          4  },
    { attr_haval,           32 },
    { attr_whirlpool,       64 },
    { attr_gostr3411_94,    32 },
    { attr_stribog256,      32 },
    { attr_stribog512,      64 },
    { attr_sha512_256,      32 },
    { attr_sha3_256,        32 },
    { attr_sha3_512,        64 },
};

DB_ATTR_TYPE DEPRECATED_HASHES = ATTR(attr_md5)|ATTR(attr_sha1)|ATTR(attr_rmd160)|ATTR(attr_gostr3411_94);
DB_ATTR_TYPE UNSUPPORTED_HASHES = ATTR(attr_crc32)|ATTR(attr_crc32b)|ATTR(attr_haval)|ATTR(attr_tiger)|ATTR(attr_whirlpool);

#ifdef WITH_NETTLE
int algorithms[] = { /* order must match hashsums array */
   1,  /* md5 */
   1,  /* sha1 */
   1,  /* sha256 */
   1,  /* sha512 */
   1,  /* rmd160 */
  -1,  /* tiger NOT available */
  -1,  /* crc32 NOT available */
  -1,  /* crc32b NOT available */
  -1,  /* haval NOT available */
  -1,  /* whirlpool NOT available */
   1,  /* gost */
   1,  /* stribog256 */
   1,  /* stribog512 */
   1,  /* sha512_256 */
   1,  /* sha3-256 */
   1,  /* sha3-512 */
};
#endif

#ifdef WITH_GCRYPT
int algorithms[] = { /* order must match hashsums array */
  GCRY_MD_MD5,
  GCRY_MD_SHA1,
  GCRY_MD_SHA256,
  GCRY_MD_SHA512,
  GCRY_MD_RMD160,
  GCRY_MD_TIGER,
  GCRY_MD_CRC32,
  -1, /* CRC32B is not available */
  -1, /* GCRY_MD_HAVAL is not (yet) implemented */
  GCRY_MD_WHIRLPOOL,
  GCRY_MD_GOSTR3411_94,
  GCRY_MD_STRIBOG256,
  GCRY_MD_STRIBOG512,
  GCRY_MD_SHA512_256,
  GCRY_MD_SHA3_256,
  GCRY_MD_SHA3_512,
};
#endif

void init_hashsum_lib(void) {
#ifdef WITH_GCRYPT
  if(!gcry_check_version(NEED_LIBGCRYPT_VERSION)) {
      log_msg(LOG_LEVEL_ERROR, "libgcrypt is too old (need %s, have %s)", NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
      exit(VERSION_MISMATCH_ERROR);
  }
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (gcry_fips_mode_active()) {
      char* str;
      log_msg(LOG_LEVEL_NOTICE, "libgcrypt is running in FIPS mode, the following hash(es) are not available: %s", str = diff_attributes(0, ATTR(attr_md5)));
      free(str);
  }
#endif
}

DB_ATTR_TYPE get_hashes(bool include_unsupported) {
    DB_ATTR_TYPE attr = 0LLU;
    for (int i = 0; i < num_hashes; ++i) {
        if (include_unsupported || (algorithms[i] >= 0
#ifdef WITH_GCRYPT
            && (algorithms[i] != GCRY_MD_MD5 || ! gcry_fips_mode_active())
#endif
)) {
            attr |= ATTR(hashsums[i].attribute);
        }
    }
    return attr;
}

DB_ATTR_TYPE validate_hashes(DB_ATTR_TYPE attrs, int linenumber, char *filename, char* linebuf) {
    char *attr_str;

    DB_ATTR_TYPE requested_hashes = attrs&get_hashes(true);

    DB_ATTR_TYPE requested_deprecated = requested_hashes&DEPRECATED_HASHES;
    if (requested_deprecated) {
        attr_str = diff_attributes(0, requested_deprecated);
        LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_NOTICE, "hashsum(s) '%s' are DEPRECATED and will be removed in the release after next, please update your config", attr_str)
        free(attr_str);
    }
    DB_ATTR_TYPE requested_unsupported = requested_hashes&UNSUPPORTED_HASHES;
    if (requested_unsupported) {
        DB_ATTR_TYPE remaining_hashes = requested_hashes & ~requested_unsupported;
        if (remaining_hashes) {
            attr_str = diff_attributes(0, requested_unsupported);
            char *remaining_str = diff_attributes(0, remaining_hashes);
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_WARNING, "ignore unsupported hashsum(s): %s (remaining hashsum(s): %s), please update your config", attr_str, remaining_str);
            attrs &= ~requested_unsupported;
            free(remaining_str);
            free(attr_str);
        } else {
            attr_str = diff_attributes(0, requested_unsupported);
            LOG_CONFIG_FORMAT_LINE(LOG_LEVEL_ERROR, "no hashsum(s) left after ignoring unsupported hashsum(s): %s", attr_str);
            free(attr_str);
            exit(INVALID_CONFIGURELINE_ERROR);
        }
    }
    return attrs;
}

DB_ATTR_TYPE get_transition_hashsums(char *old_filename, DB_ATTR_TYPE old_attr, char *new_filename, DB_ATTR_TYPE new_attr) {
    DB_ATTR_TYPE transition_hashsums = 0LL;

    DB_ATTR_TYPE all_hashsums = get_hashes(true);
    DB_ATTR_TYPE available_hashsums = get_hashes(false);

    DB_ATTR_TYPE added_hashsums = (~old_attr)&new_attr&all_hashsums;
    DB_ATTR_TYPE removed_hashsums = old_attr&~(new_attr)&all_hashsums;
    if (added_hashsums && removed_hashsums) {
        char *diff_str = diff_attributes(old_attr&all_hashsums, new_attr&all_hashsums);
        DB_ATTR_TYPE common_hashsums = old_attr&new_attr&available_hashsums;
        if (common_hashsums == 0) {
            transition_hashsums = removed_hashsums&available_hashsums;
            if (transition_hashsums) {
                char *trans_str = diff_attributes(0, transition_hashsums);
                log_msg(LOG_LEVEL_COMPARE, "hashsum transition (%s) for old:'%s' and new:'%s': transition hashsum(s): %s", diff_str, old_filename, new_filename, trans_str);
                free(trans_str);
            } else {
                log_msg(LOG_LEVEL_WARNING, "hashsum transition (%s) for old:'%s' and new:'%s': no common or transition hashsum(s) available", diff_str, old_filename, new_filename);
            }
        } else {
            transition_hashsums = common_hashsums;
            char *common_str = diff_attributes(0, common_hashsums);
            log_msg(LOG_LEVEL_COMPARE, "hashsum transition (%s) for old:'%s' and new:'%s': common hashsum(s): %s", diff_str, old_filename, new_filename, common_str);
            free(common_str);
        }
        free(diff_str);
    }
    return transition_hashsums;
}

DB_ATTR_TYPE get_hashsums_to_ignore(char *old_filename, DB_ATTR_TYPE old_attr, char *new_filename, DB_ATTR_TYPE new_attr) {
    DB_ATTR_TYPE hashsums_to_ignore = 0LL;

    DB_ATTR_TYPE all_hashsums = get_hashes(true);
    DB_ATTR_TYPE available_hashsums = get_hashes(false);

    DB_ATTR_TYPE added_hashsums = (~old_attr)&new_attr&all_hashsums;
    DB_ATTR_TYPE removed_hashsums = old_attr&~(new_attr)&all_hashsums;
    if (added_hashsums && removed_hashsums) {
        char *diff_str = diff_attributes(old_attr&all_hashsums, new_attr&all_hashsums);
        DB_ATTR_TYPE common_hashsums = old_attr&new_attr&available_hashsums;
        if (common_hashsums) {
            hashsums_to_ignore = added_hashsums^removed_hashsums;
            char *common_str = diff_attributes(0, common_hashsums);
            log_msg(LOG_LEVEL_COMPARE, "│ hashsum transition (%s) for old:'%s' and new:'%s', common hashsum(s): %s", diff_str, old_filename, new_filename, common_str);
            free(common_str);
        } else {
            log_msg(LOG_LEVEL_DEBUG, "│ hashsum transition (%s) for old:'%s' and new:'%s', no common hashsum available", diff_str, old_filename, new_filename);
        }
        free(diff_str);
    }
    return hashsums_to_ignore;
}
