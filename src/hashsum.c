/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2020 Hannes von Haugwitz
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
#include "hashsum.h"

#ifdef WITH_MHASH
#include <mhash.h>
#endif
#ifdef WITH_GCRYPT
#include <gcrypt.h>
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
};

#ifdef WITH_MHASH
int algorithms[] = { /* order must match hashsums array */
  MHASH_MD5,
  MHASH_SHA1,
  MHASH_SHA256,
  MHASH_SHA512,
  MHASH_RIPEMD160,
  MHASH_TIGER,
  MHASH_CRC32,
  MHASH_CRC32B,
  MHASH_HAVAL,
#ifdef HAVE_MHASH_WHIRLPOOL
  MHASH_WHIRLPOOL,
#else
  -1,
#endif
  MHASH_GOST,
  -1, /* stribog256 not available */
  -1, /* stribog512 not available */
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
};
#endif

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
};
