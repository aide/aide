/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2004-2006, 2009-2011, 2013, 2018-2025 Rami Lehti,
 *               Pablo Virolainen, Mike Markley, Richard van den Berg,
 *               Hannes von Haugwitz
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
#include <stdbool.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#ifdef WITH_XATTR
#include <sys/xattr.h>
#include <attr/attributes.h>
#ifndef ENOATTR
# define ENOATTR ENODATA
#endif
#endif
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#ifndef ENOATTR
# define ENOATTR ENODATA
#endif
#endif
#ifdef WITH_POSIX_ACL
#include <sys/acl.h>
#endif
#ifdef WITH_E2FSATTRS
#include <e2p/e2p.h>
#endif
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef WITH_CAPABILITIES
#include <sys/capability.h>
#endif


#include "md.h"
#include "do_md.h"

#include "hashsum.h"
#include "db_line.h"
#include "db_config.h"
#include "util.h"
#include "log.h"
#include "attributes.h"

/* This define should be somewhere else */
#define READ_BLOCK_SIZE 16777216

typedef union fd {
    int plain;
#ifdef WITH_ZLIB
    gzFile gzip;
#endif
} fd;

typedef enum compression {
    COMPRESSION_PLAIN,
#ifdef WITH_ZLIB
    COMPRESSION_GZIP,
#endif
    COMPRESSION_ERROR
} compression;

typedef struct hashsums_file {
    fd fd;
    compression compression;
} hashsums_file;

int stat_cmp(struct stat* f1,struct stat* f2, bool growing) {
  if (f1==NULL || f2==NULL) {
    return RETFAIL;
  }
#define stat_cmp_helper(n,attribute) ((f1->n!=f2->n)*ATTR(attribute))

#define stat_growing_cmp_helper(n,attribute) ((growing?f1->n<f2->n:f1->n!=f2->n)*ATTR(attribute))

  return (stat_cmp_helper(st_ino,attr_inode)|
	  stat_cmp_helper(st_mode,attr_perm)|
	  stat_cmp_helper(st_nlink,attr_linkcount)|
	  stat_growing_cmp_helper(st_size,attr_size)|
	  stat_growing_cmp_helper(st_mtime,attr_mtime)|
	  stat_growing_cmp_helper(st_ctime,attr_ctime)|
	  stat_growing_cmp_helper(st_blocks,attr_bcount)|
	  stat_cmp_helper(st_blksize,attr_bsize)|
	  stat_cmp_helper(st_rdev,attr_rdev)|
	  stat_cmp_helper(st_gid,attr_gid)|
	  stat_cmp_helper(st_uid,attr_uid)|
	  stat_cmp_helper(st_dev,attr_dev));
}

static hashsums_file hashsum_open(int filedes, char* fullpath, bool uncompress) {
    hashsums_file file;

    if (uncompress) {
        char head[2];
        char *magic_gzip = "\037\213";
        ssize_t magic_length = strlen(magic_gzip);
        ssize_t bytes = read(filedes, head, magic_length);
        if (bytes == magic_length && strncmp(head, magic_gzip, magic_length) == 0) {
            log_msg(LOG_LEVEL_COMPARE, "│ '%s' is gzip compressed", fullpath);
            lseek(filedes, 0, SEEK_SET);
#ifdef WITH_ZLIB
            file.fd.gzip = gzdopen(filedes, "rb");
            if (file.fd.gzip == NULL){
                log_msg(LOG_LEVEL_WARNING, "hash calculation: gzdopen() failed for %s (uncompressed hashsums could not be calculated)", fullpath);
                file.compression = COMPRESSION_ERROR;
                return file;
            }
            file.compression = COMPRESSION_GZIP;
            return file;
#else
            log_msg(LOG_LEVEL_WARNING, "'%s': gzip support not compiled in, recompile AIDE with '--with-zlib' (uncompressed hashsums could not be calculated)", fullpath);
            file.compression = COMPRESSION_ERROR;
            return file;
#endif
        } else {
            log_msg(LOG_LEVEL_NOTICE, "'%s': no supported compression algorithm found (uncompressed hashsums could not be calculated)", fullpath);
            file.compression = COMPRESSION_ERROR;
            return file;
        }
    } else {
        file.fd.plain = filedes;
        file.compression = COMPRESSION_PLAIN;
        return file;
    }
}

static off_t hashsum_read(hashsums_file file, void *buf, size_t count) {
    off_t size = -1;
    do {
        switch (file.compression) {
        case COMPRESSION_PLAIN:
             size = read(file.fd.plain, buf, count);
             break;
#ifdef WITH_ZLIB
        case COMPRESSION_GZIP:
             size = gzread(file.fd.gzip, buf, count);
             break;
#endif
        case COMPRESSION_ERROR:
             size = -2;
             break;
        }
    } while (size == -1 && errno == EINTR); /* retry on EINTR */
    return size;
}

static int hashsum_close(hashsums_file file) {
    switch (file.compression) {
        case COMPRESSION_PLAIN:
             return close(file.fd.plain);
#ifdef WITH_ZLIB
        case COMPRESSION_GZIP:
             return gzclose(file.fd.gzip);
#endif
        case COMPRESSION_ERROR:
             return -1;
    }
    return -1;
}

md_hashsums calc_hashsums(char* fullpath, DB_ATTR_TYPE attr, struct stat* old_fs, ssize_t limit_size, bool uncompress) {
    md_hashsums md_hash;
    md_hash.attrs = 0LU;

        struct stat new_fs;
        int sres=0;
        int stat_diff,filedes;

#ifdef HAVE_O_NOATIME
        filedes=open(fullpath,O_RDONLY|O_NOATIME);
        if(filedes<0) {
#endif
            filedes=open(fullpath,O_RDONLY);
#ifdef HAVE_O_NOATIME
        }
#endif
        if (filedes==-1) {
            log_msg(LOG_LEVEL_WARNING, "hash calculation: open() failed for %s: %s (hashsums could not be calculated)", fullpath, strerror(errno));
            return md_hash;
        }
        sres=fstat(filedes,&new_fs);
        if (sres != 0) {
            log_msg(LOG_LEVEL_WARNING, "hash calculation: fstat() failed for '%s': %s (hashsums could not be calculated)", fullpath, strerror(errno));
            return md_hash;
        }
        if(!(attr&ATTR(attr_rdev))) {
            new_fs.st_rdev=0;
        }
#ifdef HAVE_POSIX_FADVISE
        if (posix_fadvise(filedes,0,new_fs.st_size,POSIX_FADV_NOREUSE)!=0) {
            log_msg(LOG_LEVEL_DEBUG, "%s> calc_hashsums: posix_fadvise error for '%s': %s", fullpath, fullpath, strerror(errno));
        }
#endif
        if ((stat_diff=stat_cmp(&new_fs, old_fs, attr&ATTR(attr_growing))) != RETOK) {
            DB_ATTR_TYPE changed_attribures = 0ULL;
            for(ATTRIBUTE i=0;i<num_attrs;i++) {
                if (((1<<i)&stat_diff)!=0) {
                    changed_attribures |= 1<<i;
                }
            }
            char *str;
            log_msg(LOG_LEVEL_WARNING, "hash calculation: '%s' has been changed (changed attributes: %s, hash could not be calculated)", fullpath, str = diff_attributes(0, changed_attribures));
            free(str);
            close(filedes);
            return md_hash;
        } else {
            hashsums_file file = hashsum_open(filedes, fullpath, uncompress);
            if (file.compression == COMPRESSION_ERROR) {
                close(filedes);
                return md_hash;
            }

            off_t r_size=0;
            off_t size=0;
            char* buf;

            struct md_container mdc;
            mdc.todo_attr = attr;
            if (init_md(&mdc, fullpath)==RETOK) {
                log_msg(LOG_LEVEL_DEBUG, "%s> calculate hashes for '%s'", fullpath, fullpath);
                buf=checked_malloc(READ_BLOCK_SIZE);
#if READ_BLOCK_SIZE>SSIZE_MAX
#error "READ_BLOCK_SIZE" is too large. Max value is SSIZE_MAX, and current is READ_BLOCK_SIZE
#endif
                while ((size = hashsum_read(file,buf,READ_BLOCK_SIZE)) > 0) {

                    off_t update_md_size;
                    if (limit_size > 0 && r_size+size > limit_size) {
                        update_md_size = limit_size-r_size;
                    } else if(attr&ATTR(attr_growing) && r_size+size > old_fs->st_size) {
                        update_md_size = old_fs->st_size-r_size;
                    } else {
                        update_md_size = size;
                    }

                    if (update_md(&mdc,buf,update_md_size)!=RETOK) {
                        log_msg(LOG_LEVEL_WARNING, "hash calculation: update_md() failed for '%s' (hashsums could not be calculated)", fullpath);
                        free(buf);
                        hashsum_close(file);
                        close_md(&mdc, NULL, fullpath);
                        return md_hash;
                    }
                    r_size+=update_md_size;
                    if (limit_size > 0 && r_size == limit_size) {
                        log_msg(LOG_LEVEL_DEBUG, "hash calculation: limited size (%zi) reached for '%s'", limit_size, fullpath);
                        break;
                    } else if (attr&ATTR(attr_growing) && r_size == old_fs->st_size) {
                        log_msg(LOG_LEVEL_DEBUG, "hash calculation: stat size (%zi) reached for growing file '%s'", old_fs->st_size, fullpath);
                        break;
                    }
                }
                if (uncompress == false) {
                    bool mismatch = false;
                    bool lower = false;
                    long long target_size = old_fs->st_size;
                    if (limit_size > 0) {
                        if (r_size < limit_size) {
                            target_size = limit_size;
                            lower = true;
                            mismatch = true;
                        }
                    } else if (attr&ATTR(attr_growing)) {
                        if (r_size < old_fs->st_size) {
                            lower = true;
                            mismatch = true;
                        }
                    } else {
                        if (r_size != old_fs->st_size) {
                            lower = r_size<old_fs->st_size;
                            mismatch = true;
                        }
                    }
                    if (mismatch) {
                        log_msg(LOG_LEVEL_WARNING, "hash calculation: number of bytes read (%lld) mismatches %s size (%lld) for '%s'%s (hashsums could not be calculated)",
                                (long long) r_size, limit_size > 0?"limited":"stat", target_size, fullpath,
                                lower?", was file truncated while AIDE was running?":", was file growing while AIDE was running? (consider adding 'growing' attribute)"
                               );
                        free(buf);
                        hashsum_close(file);
                        close_md(&mdc, NULL, fullpath);
                        return md_hash;
                    }
                }
                free(buf);
                close_md(&mdc, &md_hash, fullpath);
                hashsum_close(file);
                return md_hash;
            } else {
                log_msg(LOG_LEVEL_WARNING, "hash calculation: init_md() failed for '%s' (hashsums could not be calculated)", fullpath);
                hashsum_close(file);
                return md_hash;
            }
        }
}

void fs2db_line(struct stat* fs,db_line* line) {
  
  /* inode is always needed for ignoring changed filename */
  line->inode=fs->st_ino;

  if(ATTR(attr_uid)&line->attr) {
    line->uid=fs->st_uid;
  }else {
    line->uid=0;
  }

  if(ATTR(attr_gid)&line->attr){
    line->gid=fs->st_gid;
  }else{
    line->gid=0;
  }

  /* permissions are always needed for file type detection */
  line->perm=fs->st_mode;

  if(ATTR(attr_size)&line->attr
    || ATTR(attr_sizeg)&line->attr
    || (ATTR(attr_growing)&line->attr && line->attr&get_hashes(true))
  ){
    line->size=fs->st_size;
  }else{
    line->size=0;
  }
  
  if(ATTR(attr_linkcount)&line->attr){
    line->nlink=fs->st_nlink;
  }else {
    line->nlink=0;
  }

  if(ATTR(attr_mtime)&line->attr){
    line->mtime=fs->st_mtime;
  }else{
    line->mtime=0;
  }

  if(ATTR(attr_ctime)&line->attr){
    line->ctime=fs->st_ctime;
  }else{
    line->ctime=0;
  }
  
  if(ATTR(attr_atime)&line->attr){
    line->atime=fs->st_atime;
  }else{
    line->atime=0;
  }

  if(ATTR(attr_bcount)&line->attr){
    line->bcount=fs->st_blocks;
  } else {
    line->bcount=0;
  }
  
}

#ifdef WITH_ACL
void acl2line(db_line* line) {
  acl_type *ret = NULL;
  
#ifdef WITH_POSIX_ACL
  if(ATTR(attr_acl)&line->attr) {
    acl_t acl_a = NULL;
    acl_t acl_d = NULL;
    char *tmp = NULL;

    acl_a = acl_get_file(line->fullpath, ACL_TYPE_ACCESS);
    if (acl_a == NULL) {
        if (errno == ENOTSUP) {
            log_msg(LOG_LEVEL_TRACE, "failed to get acl of %s: file system does not support ACLs or ACLs are disabled", line->fullpath);
        } else {
            log_msg(LOG_LEVEL_WARNING, "failed to get ACL of %s: %s", line->fullpath, strerror(errno));
        }
        line->attr&=(~ATTR(attr_acl));
        return;
    }
    if (S_ISDIR(line->perm)) {
        acl_d = acl_get_file(line->fullpath, ACL_TYPE_DEFAULT);
        if (acl_d == NULL) {
            log_msg(LOG_LEVEL_WARNING, "failed to get default ACL of %s: %s", line->fullpath, strerror(errno));
            acl_free(acl_a);
            line->attr&=(~ATTR(attr_acl));
            return;
        }
    }

    ret = checked_malloc(sizeof(acl_type));

    /* use tmp, so free() can be called instead of acl_free() */
    tmp = acl_to_text(acl_a, NULL);
    if (!tmp || !*tmp)
      ret->acl_a = NULL;
    else
      ret->acl_a = checked_strdup(tmp);
    acl_free(tmp);

    if (!acl_d)
      ret->acl_d = NULL;
    else
    {
      tmp = acl_to_text(acl_d, NULL);
      if (!tmp || !*tmp)
        ret->acl_d = NULL;
      else
        ret->acl_d = checked_strdup(tmp);
      acl_free(tmp);
    }

    acl_free(acl_a);
    acl_free(acl_d);
  }
  line->acl = ret;
#endif  
}
#endif

#ifdef WITH_XATTR
static xattrs_type *xattr_new(void) {
    xattrs_type *ret = NULL;

    ret = checked_malloc(sizeof(xattrs_type));
    ret->num = 0;
    ret->sz  = 2;
    ret->ents = checked_malloc(sizeof(xattr_node) * ret->sz);

    return (ret);
}

static void *xzmemdup(const void *ptr, size_t len) {
    /* always keeps a 0 at the end... */
    void *ret = NULL;

    ret = checked_malloc(len+1);
    memcpy(ret, ptr, len);
    ((char*)ret)[len] = 0;

    return (ret);
}

static void xattr_add(xattrs_type *xattrs, const char *key, const char
        *val, size_t vsz) {
    if (xattrs->num >= xattrs->sz) {
        xattrs->sz <<= 1;
        xattrs->ents = checked_realloc(xattrs->ents, sizeof(xattr_node) * xattrs->sz);
    }

    xattrs->ents[xattrs->num].key = checked_strdup(key);
    xattrs->ents[xattrs->num].val = xzmemdup(val, vsz);
    xattrs->ents[xattrs->num].vsz = vsz;

    xattrs->num += 1;
}

void xattrs2line(db_line *line) {
    /* get all generic user xattrs. */
    xattrs_type *xattrs = NULL;
    ssize_t xret = -1;

    if ((ATTR(attr_xattrs)&line->attr)) {
        ssize_t xsz = 1024;
        char *xatrs = xatrs = checked_malloc(xsz);

    while (((xret = llistxattr(line->fullpath, xatrs, xsz)) == -1) && (errno == ERANGE)) {
        xsz <<= 1;
        xatrs = checked_realloc(xatrs, xsz);
    }

    if ((xret == -1) && ((errno == ENOSYS) || (errno == ENOTSUP))) {
        line->attr&=(~ATTR(attr_xattrs));
    } else if (xret == -1) {
        log_msg(LOG_LEVEL_WARNING, "listxattrs failed for %s:%s", line->fullpath, strerror(errno));
    } else if (xret) {
        const char *attr = xatrs;
        ssize_t asz = 1024;
        char *val = checked_malloc(asz);

        xattrs = xattr_new();

        while (xret > 0) {
            size_t len = strlen(attr);
            ssize_t aret = 0;

            if (strncmp(attr, "user.", strlen("user.")) &&
                    strncmp(attr, "security.", strlen("security.")) &&
                    strncmp(attr, "trusted.", strlen("trusted.")))
                goto next_attr; /* only store normal xattrs, and SELinux */

            while (((aret = lgetxattr(line->fullpath, attr, val, asz)) ==
                        -1) && (errno == ERANGE)) {
                asz <<= 1;
                val = checked_realloc (val, asz);
            }

            if (aret != -1)
                xattr_add(xattrs, attr, val, aret);
            else if (errno != ENOATTR)
                log_msg(LOG_LEVEL_WARNING, "lgetxattr failed for %s:%s", line->fullpath, strerror(errno));

next_attr:
            attr += len + 1;
            xret -= len + 1;
        }
        free(val);
    }
        free(xatrs);
    }

    line->xattrs = xattrs;
}
#endif

#ifdef WITH_SELINUX
void selinux2line(db_line *line) {
    char *cntx = NULL;

    if ((ATTR(attr_selinux)&line->attr)) {

    if (lgetfilecon_raw(line->fullpath, &cntx) == -1) {
        line->attr&=(~ATTR(attr_selinux));
        if ((errno != ENOATTR) && (errno != EOPNOTSUPP))
            log_msg(LOG_LEVEL_WARNING, "lgetfilecon_raw failed for %s: %s", line->fullpath, strerror(errno));
        return;
    }

    line->cntx = checked_strdup(cntx);

    freecon(cntx);

    } else {
        line->cntx = NULL;
    }
}
#endif

#ifdef WITH_E2FSATTRS
void e2fsattrs2line(db_line* line) {
    unsigned long flags;
    if (ATTR(attr_e2fsattrs)&line->attr) {
        if (fgetflags(line->fullpath, &flags) == 0) {
            line->e2fsattrs=flags;
        } else {
            line->attr&=(~ATTR(attr_e2fsattrs));
            line->e2fsattrs=0;
        }
    } else {
        line->e2fsattrs=0;
    }
}
#endif

#ifdef WITH_CAPABILITIES
void capabilities2line(db_line* line) {
    cap_t caps;
    char *txt_caps;

    if ((ATTR(attr_capabilities)&line->attr)) {
       if (S_ISREG(line->perm)) {
          caps = cap_get_file(line->fullpath);
          if (caps != NULL) {
              txt_caps = cap_to_text(caps, NULL);
              line->capabilities = checked_strdup(txt_caps);
              cap_free(txt_caps);
              cap_free(caps);
          } else {
              line->attr&=(~ATTR(attr_capabilities));
              line->capabilities=NULL;
          }
       } else {
           line->attr&=(~ATTR(attr_capabilities));
           line->capabilities=NULL;
       }
    } else {
        line->capabilities=NULL;
    }
}
#endif

void no_hash(db_line* line) {
  line->attr&=~get_hashes(true);
}

