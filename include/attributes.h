/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002,2004,2006,2019 Rami Lehti, Pablo Virolainen, Richard
 * van den Berg, Hannes von Haugwitz
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _ATTRIBUTES_H_INCLUDED
#define  _ATTRIBUTES_H_INCLUDED

#define DB_ATTR_TYPE unsigned long long
#define DB_ATTR_UNDEF ((DB_ATTR_TYPE) -1)

#define DB_FILENAME     (1LLU<<0)   /* "name",          */
#define DB_LINKNAME     (1LLU<<1)   /* "lname",         */
#define DB_PERM         (1LLU<<2)   /* "perm",          */
#define DB_UID          (1LLU<<3)   /* "uid",           */
#define DB_GID          (1LLU<<4)   /* "gid",           */
#define DB_SIZE         (1LLU<<5)   /* "size",          */
#define DB_ATIME        (1LLU<<6)   /* "atime",         */
#define DB_CTIME        (1LLU<<7)   /* "ctime",         */
#define DB_MTIME        (1LLU<<8)   /* "mtime",         */
#define DB_INODE        (1LLU<<9)   /* "inode",         */
#define DB_BCOUNT       (1LLU<<10)  /* "bcount",        */
#define DB_LNKCOUNT     (1LLU<<11)  /* "lcount",        */
#define DB_MD5          (1LLU<<12)  /* "md5",           */
#define DB_SHA1         (1LLU<<13)  /* "sha1",          */
#define DB_RMD160       (1LLU<<14)  /* "rmd160",        */
#define DB_TIGER        (1LLU<<15)  /* "tiger",         */
#define DB_CRC32        (1LLU<<16)  /* "crc32",         */
#define DB_HAVAL        (1LLU<<17)  /* "haval",         */
#define DB_GOST         (1LLU<<18)  /* "gost",          */
#define DB_CRC32B       (1LLU<<19)  /* "crc32b",        */
#define DB_ATTR         (1LLU<<20)  /* "attr"           */
#define DB_ACL          (1LLU<<21)  /* "acl"            */
#define DB_BSIZE        (1LLU<<22)  /* "bsize"          */
#define DB_RDEV         (1LLU<<23)  /* "rdev"           */
#define DB_DEV          (1LLU<<24)  /* "dev"            */
#define DB_CHECKMASK    (1LLU<<25) /* "checkmask"       */
#define DB_SIZEG        (1LLU<<26) /* "unknown"         */
#define DB_CHECKINODE   (1LLU<<27) /* "checkinode"      */
#define DB_NEWFILE      (1LLU<<28) /* "allow new file"  */
#define DB_RMFILE       (1LLU<<29) /* "allot rm file"   */
#define DB_SHA256       (1LLU<<30) /* "sha256",         */
#define DB_SHA512       (1LLU<<31) /* "sha512",         */
#define DB_SELINUX      (1LLU<<32) /* "selinux",        */
#define DB_XATTRS       (1LLU<<33) /* "xattrs",         */
#define DB_WHIRLPOOL    (1LLU<<34) /* "whirlpool",      */
#define DB_FTYPE        (1LLU<<35) /* "file type",      */
#define DB_E2FSATTRS    (1LLU<<36) /* "e2fs attributes" */
#define DB_CAPABILITIES (1LLU<<37) /* "capabilities"    */

/* memory for the returned string is obtained with malloc(3), and should be freed with free(3). */
char *diff_attributes(DB_ATTR_TYPE, DB_ATTR_TYPE);
#endif
