/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2007, 2010-2013, 2016, 2018-2025 Rami Lehti,
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
#include "aide.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include "db_config.h"
#include "gen_list.h"
#include "hashsum.h"
#include "log.h"
#include "progress.h"
#include "url.h"
#include "db.h"
#ifdef WITH_CURL
#include "fopen.h"
#endif

#include "attributes.h"

#include <errno.h>

#include "base64.h"
#include "db_line.h"
#include "db_file.h"
#include "util.h"
#include "errorcodes.h"

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#define BUFSIZE 16384

#include "md.h"



static bool db_parse_spec(database* db, char **saveptr){
  char *token = NULL;

  DB_ATTR_TYPE seen_attrs = 0LLU;

  db->fields = checked_malloc(1*sizeof(ATTRIBUTE));
  
  while ((token = strtok_r(NULL, " ", saveptr)) != NULL) {
    if (strncmp("@@", token, 2) == 0) {
      LOG_DB_FORMAT_LINE(LOG_LEVEL_ERROR, "unexpected token while reading db_spec: '%s'", token);
      return false;
    } else {
        ATTRIBUTE l;
        db->fields = checked_realloc(db->fields, (db->num_fields+1)*sizeof(ATTRIBUTE));
        db->fields[db->num_fields]=attr_unknown;
        for (l=0;l<num_attrs;l++){
            if (attributes[l].db_name && strcmp(attributes[l].db_name,token)==0) {
                if (ATTR(l)&seen_attrs) {
                    LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "@@db_spec: skip redefined field '%s' at position %i", token, db->num_fields)
                        db->fields[db->num_fields]=attr_unknown;
                } else {
                    db->fields[db->num_fields]=l;
                    seen_attrs |= ATTR(l);
                    LOG_DB_FORMAT_LINE(LOG_LEVEL_DEBUG, "@@db_spec: define field '%s' at position %i", token, db->num_fields)
                }
                db->num_fields++;
                break;
            }
        }
        if(l==attr_unknown){
            LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "@@db_spec: skip unknown field '%s' at position %i", token, db->num_fields);
            db->fields[db->num_fields]=attr_unknown;
            db->num_fields++;
        }
    }
  }

  /* Lets generate attr from db_order if database does not have attr */
  conf->attr=DB_ATTR_UNDEF;

  for (int i=0;i<db->num_fields;i++) {
    if (db->fields[i] == attr_attr) {
      conf->attr=1;
    }
  }
  if (conf->attr==DB_ATTR_UNDEF) {
    conf->attr=0;
    for(int i=0;i<db->num_fields;i++) {
      conf->attr|=1LL<<db->fields[i];
    }
    char *str;
    LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "missing attr field, generated attr field from dbspec: %s (comparison may be incorrect)", str = diff_database_attributes(0, conf->attr))
    free(str);
  }
  return true;
}

static char *fgets_wrapper(char *ptr, size_t size, database *db) {
    char * buf = NULL;

#ifdef WITH_CURL
  switch ((db->url)->type) {
  case url_http:
  case url_https:
  case url_ftp: {
    buf = url_fgets(ptr, size, (URL_FILE *)db->fp);
    if (!buf) {
        log_msg(LOG_LEVEL_ERROR, "url_fgets failed for %s", (db->url)->raw);
        exit(IO_ERROR);
    }
    break;
  }
  default:
#endif

#ifdef WITH_ZLIB
        if (db->gzp == NULL) {
            db->gzp=gzdopen(fileno((FILE *)db->fp),"rb");
            if (db->gzp == NULL) {
                log_msg(LOG_LEVEL_ERROR, "gzdopen failed for %s", (db->url)->raw);
                exit(IO_ERROR);
            }
        }
        buf = gzgets(db->gzp, ptr, size);
        if (!buf && !gzeof(db->gzp)) {
            int gzerrnum;
            log_msg(LOG_LEVEL_ERROR, "gzgets failed for %s: %s", (db->url)->raw, gzerror(db->gzp, &gzerrnum));
            exit(IO_ERROR);
        }
#else
        buf = fgets(ptr, size, db->fp);
        if (ferror(db->fp)) {
            log_msg(LOG_LEVEL_ERROR, "fgets failed for %s: %s", (db->url)->raw, strerror(errno));
            exit(IO_ERROR);
        }
#endif
#ifdef WITH_CURL
  }
#endif
  if (buf && db->mdc) {
      update_md(db->mdc, buf, strlen(buf));
  }
  return buf;
}

static char *get_next_dbline(database *db) {
    char buffer[2048];
    char *line = NULL;
    size_t len = 0;

    while (fgets_wrapper(buffer, sizeof(buffer), db) != NULL) {
        size_t buffer_len = strlen(buffer);
        line = checked_realloc(line, buffer_len + len + 1);
        strncpy(line + len, buffer, buffer_len+1);
        len += buffer_len;
        /* remove newline character */
        if (line[len-1] == '\n') {
            line[len-1] = '\0';
            break;
        }
    }
    return line;
}

db_entry_t db_readline_file(database* db, bool include_limited_entries) {
    char **s = NULL;
    char *saveptr, *token;
    char *line = NULL;

    db_entry_t entry = { .line = NULL, .limit = false };

    while ((line = get_next_dbline(db)) != NULL) {
        db->lineno++;
        LOG_LEVEL db_parse_log_level = LOG_LEVEL_DEBUG;
        switch (line[0]) {
            case '#':
                LOG_DB_FORMAT_LINE(db_parse_log_level, "db_read_file: skip comment line: '%s'", line)
                break;
            case '\0':
                LOG_DB_FORMAT_LINE(db_parse_log_level, "%s", "db_read_file: skip empty line")
                break;
            default:
                saveptr = NULL;
                token = strtok_r(line, " ", &saveptr);
                if (strcmp("@@db_spec", token) == 0) {
                    if (db->fields) {
                        LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "skip additional '%s' line", token)
                    } else {
                        LOG_DB_FORMAT_LINE(db_parse_log_level, "db_read_file: parse '%s'", token)
                        db_parse_spec(db, &saveptr);
                    }
                } else if (strcmp("@@begin_db", token) == 0) {
                    if (db->flags&DB_FLAG_PARSE) {
                        LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "skip additional '%s' line", token)
                    } else {
                        LOG_DB_FORMAT_LINE(db_parse_log_level, "%s", "db_read_file: start reading database (found '@@begin_db')")
                        db->flags |= DB_FLAG_PARSE;
                    }
                    if ((token = strtok_r(NULL, "\n", &saveptr)) != NULL) {
                        LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "skip unexpected string after '@@begin_db': '%s'", token)
                    }
                } else if (strcmp("@@end_db", token) == 0) {
                    if (db->flags&DB_FLAG_PARSE) {
                        db->flags &= ~(DB_FLAG_PARSE);
                        LOG_DB_FORMAT_LINE(db_parse_log_level, "%s", "db_read_file: stop reading database (found '@@end_db')")
                        if ((token = strtok_r(NULL, "\n", &saveptr)) != NULL) {
                            LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "skip unexpected string after '@@end_db': '%s'", token)
                        }
                        return entry;
                    } else {
                        LOG_DB_FORMAT_LINE(LOG_LEVEL_ERROR, "%s", "unexpected '@@end_db', expected '@@begin_db'")
                        exit(DATABASE_ERROR);
                    }
                } else if (db->flags&DB_FLAG_PARSE) {
                    if (*token != '/') {
                        LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "skip line with invalid path: '%s'", token)
                        break;
                    } else {
                        if (check_limit(token, true, NULL)) {
                            if (include_limited_entries) {
                                entry.limit = true;
                                db_parse_log_level = LOG_LEVEL_LIMIT;
                            } else {
                                update_progress_status(PROGRESS_SKIPPED, NULL);
                                break;
                            }
                        }
                        LOG_DB_FORMAT_LINE(db_parse_log_level, "db_read_file: parse '%s'", token)
                        s = checked_malloc(sizeof(char*)*num_attrs);
                        for(ATTRIBUTE j=0; j<num_attrs; j++){
                            s[j]=NULL;
                        }
                        int i = 0;
                        while(token != NULL) {
                            if (token[0] == '#') {
                                LOG_DB_FORMAT_LINE(db_parse_log_level, "%s", "db_read_file: skip inline comment")
                                    break;
                            } else if (i >= db->num_fields) {
                                LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "skip unexpected string '%s')", token);
                            } else if (db->fields[i] != attr_unknown) {
                                s[db->fields[i]] = checked_strdup(token);
                                LOG_DB_FORMAT_LINE(db_parse_log_level, "db_read_file: '%s' set field '%s' (position %d): '%s'", s[0], attributes[db->fields[i]].db_name, i, token)
                            } else {
                                LOG_DB_FORMAT_LINE(db_parse_log_level, "skip unknown/redefined field at position: %d: '%s'", i, token);
                            }
                            token = strtok_r(NULL, " ", &saveptr);
                            i++;
                        }
                        if (i<db->num_fields) {
                            LOG_DB_FORMAT_LINE(LOG_LEVEL_WARNING, "skip cutoff database line '%s' found (field '%s' (position: %d) is missing)", s[0], attributes[db->fields[i]].db_name, i)
                            for(int a=0;a<i;a++){
                                free(s[db->fields[a]]);
                                s[db->fields[a]] = NULL;
                            }
                            free(s);
                            s = NULL;
                        } else {
                             entry.line = db_char2line(s, db);
                             for(int j=0;j<db->num_fields;j++){
                                 if(db->fields[j]!=attr_unknown &&
                                         s[db->fields[j]]!=NULL){
                                     free(s[db->fields[j]]);
                                     s[db->fields[j]]=NULL;
                                 }
                             }
                             free(s);
                            return entry;
                        }
                    }
                } else {
                    LOG_DB_FORMAT_LINE(db_parse_log_level, "skip line '%s' ('@@begin_db' not (yet) found)", line)
                }
        }
        free(line);
        line = NULL;
    }
    if (db->flags&DB_FLAG_PARSE) {
        LOG_DB_FORMAT_LINE(LOG_LEVEL_ERROR, "%s", "missing '@@end_db' (incomplete database file)")
        exit(DATABASE_ERROR);
    } else {
        /* empty database */
        return entry;
    }
}

static int str_format(char *, int n, const char*, ...)
#ifdef __GNUC__
        __attribute__ ((format (printf, 3, 4)))
#endif
;
static int str_format(char *str, int n, const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    int len = vsnprintf(NULL, 0, format, ap);
    va_end(ap);
    if (str) {
        va_start(ap, format);
        vsnprintf(&str[n], len+1, format, ap);
        va_end(ap);
    }
    return len;
}

static int str_filename(char *str, int n, char *path) {
    char *safe_path = NULL;
    int len = 0;
    if (contains_unsafe(path)) {
        safe_path = encode_string(path);
    }
    len = str_format(str, n+len, "%s", safe_path?safe_path:path);
    free(safe_path);
    return len;
}

static int str_linkname(char *str, int n, char *path) {
    char *safe_path = NULL;
    int len = 0;
    if (path == NULL) {
        len = str_format(str, n, " %s", "0");
        return len;
    }
    if (*path == '\0') {
        len = str_format(str, n, " %s", "0-");
        return len;
    }
    if (contains_unsafe(path)) {
        safe_path = encode_string(path);
    }
    len += str_format(str, n, " %s%s", *path == '0'?"0":"", safe_path?safe_path:path);
    free(safe_path);
    return len;
}

static int byte_base64(char *str, int n, byte *src, int src_len) {
    char *enc = src ? encode_base64(src, src_len) : NULL;
    int len = str_format(str, n, " %s", enc ? enc : "0");
    free(enc);
    return len;
}

#define CASE_BYTE_BASE64(attr, src, src_len) case attr : { n += byte_base64(str, n, src, src_len); break; }

#define CASE_HASHSUM(x) CASE_BYTE_BASE64(attr_ ##x, line->hashsums[hash_ ##x], hashsums[hash_ ##x].length)

#ifdef WITH_XATTR
static int str_xattr(char *str, int n, xattrs_type *xattrs) {
    if (xattrs) {
        size_t m = 0;
        m = str_format(str, n, " %lu", xattrs->num);
        xattr_node *xattr = xattrs->ents;
        for (size_t i = xattrs->num; i > 0; --i) {
            char *enc_key = NULL;
            if (contains_unsafe(xattr->key)) {
                enc_key = encode_string(xattr->key);
            }
            char *enc_value = encode_base64(xattr->val, xattr->vsz);
            m += str_format(str, n + m, ",%s,%s", enc_key?enc_key:xattr->key, enc_value?enc_value:"0");
            free(enc_key);
            free(enc_value);
            ++xattr;
        }
        return m;
    } else {
        return str_format(str, n, " %lu", 0LU);
    }
}
#endif

#ifdef WITH_ACL
static int str_acl(char *str, int n, acl_type *acl) {
#ifdef WITH_POSIX_ACL
    if (acl) {
        char *enc_acl_a = acl->acl_a ? encode_base64((byte *)acl->acl_a, strlen(acl->acl_a)) : NULL;
        char *enc_acl_d = acl->acl_d ? encode_base64((byte *)acl->acl_d, strlen(acl->acl_d)) : NULL;
        int len = str_format(str, n, " %s,%s,%s", "POSIX", enc_acl_a ? enc_acl_a : "0", enc_acl_d ? enc_acl_d : "0");
        free(enc_acl_d);
        free(enc_acl_a);
        return len;
    } else {
        return str_format(str, n, " %lu", 0LU);
    }
#endif
}
#endif

static int construct_database_line(db_line *line, char *str) {
    int n = 0;

    for (ATTRIBUTE i = 0; i < num_attrs; ++i) {
        if (attributes[i].db_name && ATTR(i) & conf->db_out_attrs) {
            switch (i) {
            case attr_filename: {
                n += str_filename(str, n, line->filename);
                break;
            }
            case attr_attr: {
                n += str_format(str, n, " %llu", line->attr);
                break;
            }
            case attr_inode: {
                n += str_format(str, n, " %li", line->inode);
                break;
            }
            case attr_size: {
                n += str_format(str, n, " %lli", line->size);
                break;
            }
            case attr_bcount: {
                n += str_format(str, n, " %lli", line->bcount);
                break;
            }
            case attr_perm: {
                n += str_format(str, n, " %lo", (long)line->perm);
                break;
            }
            case attr_uid: {
                n += str_format(str, n, " %li", line->uid);
                break;
            }
            case attr_gid: {
                n += str_format(str, n, " %li", line->gid);
                break;
            }
            case attr_atime: {
                n += str_format(str, n, " %ld", (long)line->atime);
                break;
            }
            case attr_ctime: {
                n += str_format(str, n, " %ld", (long)line->ctime);
                break;
            }
            case attr_mtime: {
                n += str_format(str, n, " %ld", (long)line->mtime);
                break;
            }
            case attr_linkname: {
                n += str_linkname(str, n, line->linkname);
                break;
                ;
            }
            case attr_linkcount: {
                n += str_format(str, n, " %li", line->nlink);
                break;
            }
            CASE_HASHSUM(md5)
            CASE_HASHSUM(sha1)
            CASE_HASHSUM(rmd160)
            CASE_HASHSUM(tiger)
            CASE_HASHSUM(crc32)
            CASE_HASHSUM(crc32b)
            CASE_HASHSUM(haval)
            CASE_HASHSUM(gostr3411_94)
            CASE_HASHSUM(stribog256)
            CASE_HASHSUM(stribog512)
            CASE_HASHSUM(sha256)
            CASE_HASHSUM(sha512)
            CASE_HASHSUM(whirlpool)
            CASE_HASHSUM(sha512_256)
            CASE_HASHSUM(sha3_256)
            CASE_HASHSUM(sha3_512)
            case attr_acl: {
#ifdef WITH_ACL
                n += str_acl(str, n, line->acl);
#endif
                break;
            }
            case attr_xattrs: {
#ifdef WITH_XATTR
                n += str_xattr(str, n, line->xattrs);
#endif
                break;
            }
            case attr_selinux: {
#ifdef WITH_SELINUX
                n += byte_base64(str, n, (byte *)line->cntx, line->cntx ? strlen(line->cntx) : 0);
#endif
                break;
            }
            case attr_e2fsattrs: {
#ifdef WITH_E2FSATTRS
                n += str_format(str, n, " %lu", line->e2fsattrs);
#endif
                break;
            }
            case attr_capabilities: {
#ifdef WITH_CAPABILITIES
                n += byte_base64(str, n, (byte *)line->capabilities,
                 line->capabilities ? strlen(line->capabilities) : 0);
#endif
                break;
            }
            case attr_fs_type : {
#ifdef HAVE_FSTYPE
                n += str_format(str, n, " %llu", (unsigned long long) line->fs_type);
#endif
                break;
            }
            case attr_ftype:
            case attr_bsize:
            case attr_rdev:
            case attr_dev:
            case attr_allhashsums:
            case attr_sizeg:
            case attr_checkinode:
            case attr_allownewfile:
            case attr_allowrmfile:
            case attr_growing:
            case attr_compressed:
            case attr_unknown: {
                /* nothing to write to database */
                break;
            }
            }
        }
    }
    if (str) {
        snprintf(&str[n], 2, "\n");
    }
    n++;

    return n;
}

static void handle_io_error_on_write(char *function_str) {
    if (conf->database_out.url->type == url_file && conf->database_out.flags&DB_FLAG_CREATED) {
        log_msg(LOG_LEVEL_ERROR, "%s failed for %s (remove incompletely written database)", function_str, ((conf->database_out).url)->raw);
        unlink(conf->database_out.url->value);
    } else {
        log_msg(LOG_LEVEL_ERROR, "%s failed for %s", function_str, ((conf->database_out).url)->raw);
    }
    exit(IO_ERROR);
}

static void db_out_write(char * str, size_t len) {
    if ((conf->database_out).mdc) {
        update_md((conf->database_out).mdc, str, len);
    }

#ifdef WITH_ZLIB
    if(conf->gzip_dbout) {
        if (gzwrite((conf->database_out).gzp, str, len) < (int) len) {
            handle_io_error_on_write("gzwrite");
        }
    } else {
#endif
        if (fwrite(str, sizeof(char), len, conf->database_out.fp) < len) {
            handle_io_error_on_write("fwrite");
        }
        if (fflush(conf->database_out.fp) != 0) {
            handle_io_error_on_write("fflush");
        }
#ifdef WITH_ZLIB
    }
#endif
}

int db_writeline_file(db_line* line) {

    char *str = NULL;
    int n = construct_database_line(line, str);

    str = checked_malloc(n+1);
    construct_database_line(line, str);

    db_out_write(str, n);

    free(str);

    return RETOK;
}

static int construct_database_header(db_config *dbconf, char *str) {
    int n = 0;

    n += str_format(str, n, "%s", "@@begin_db\n");
    if (dbconf->database_add_metadata) {
        time_t db_gen_time = time(NULL);
        char *time_str = get_time_string(&db_gen_time);
        n += str_format(str, n,
             "# This file was generated by Aide, version %s\n"
             "# Time of generation was %s\n",
             conf->aide_version, time_str);
        free(time_str);
    }
    if (dbconf->config_version) {
        n += str_format(str, n,
                        "# The config version used to generate this file was:\n"
                        "# %s\n",
                        dbconf->config_version);
    }
    n += str_format(str, n, "%s", "@@db_spec");
    for (ATTRIBUTE i = 0; i < num_attrs; ++i) {
        if (attributes[i].db_name && attributes[i].attr & conf->db_out_attrs) {
            n += str_format(str, n, " %s", attributes[i].db_name);
        }
    }
    n += str_format(str, n, "%s", "\n");
    return n;
}

int db_writespec_file(db_config* dbconf) {
    char *str = NULL;
    int n = construct_database_header(dbconf, str);

    str = checked_malloc(n+1);
    construct_database_header(dbconf, str);

    db_out_write(str, n);

    free(str);

    return RETOK;
}

int db_close_file(db_config* dbconf){
  
  if(dbconf->database_out.fp
#ifdef WITH_ZLIB
     || dbconf->database_out.gzp
#endif
     ){
      char *end_db_str = "@@end_db\n";
      db_out_write(end_db_str, strlen(end_db_str));
  }

#ifdef WITH_ZLIB
  if(dbconf->gzip_dbout){
    if(gzclose(dbconf->database_out.gzp)){
      log_msg(LOG_LEVEL_ERROR,"unable to gzclose database '%s': %s", (dbconf->database_out.url)->raw, strerror(errno));
      return RETFAIL;
    }
    dbconf->database_out.gzp = NULL;
  }else {
#endif
    if(fclose(dbconf->database_out.fp)){
      log_msg(LOG_LEVEL_ERROR,"unable to close database '%s': %s",  (dbconf->database_out.url)->raw, strerror(errno));
      return RETFAIL;
    }
    dbconf->database_out.fp = NULL;
#ifdef WITH_ZLIB
  }
#endif

  return RETOK;
}
// vi: ts=8 sw=8
