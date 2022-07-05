/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 1999-2002, 2004-2006, 2009-2011, 2013, 2018-2022 Rami Lehti,
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
#include <stdbool.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

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

#include "hashsum.h"
#include "db_line.h"
#include "db_config.h"
#include "util.h"
#include "log.h"
#include "attributes.h"

/* This define should be somewhere else */
#define READ_BLOCK_SIZE 16777216

/* Redhat 5.0 needs this */
#ifdef HAVE_MMAP
#ifndef MAP_FAILED
#define MAP_FAILED  (-1)
#endif /* MAP_FAILED */
#define MMAP_BLOCK_SIZE 16777216
#endif /* HAVE_MMAP */

/*
#include <gcrypt.h>
*/

#ifdef WITH_PRELINK
#include <sys/wait.h>
#include <gelf.h>

/*
 *  Is file descriptor prelinked binary/library?
 *  Return: 1(yes) / 0(no)
 *  
 */
int is_prelinked(int fd) {
        Elf *elf = NULL;
        Elf_Scn *scn = NULL;
        Elf_Data *data = NULL;
        GElf_Ehdr ehdr;
        GElf_Shdr shdr;
        GElf_Dyn dyn;
        int bingo;

        (void) elf_version(EV_CURRENT);

        if ((elf = elf_begin (fd, ELF_C_READ, NULL)) == NULL
            || elf_kind(elf) != ELF_K_ELF
            || gelf_getehdr(elf, &ehdr) == NULL
            || !(ehdr.e_type == ET_DYN || ehdr.e_type == ET_EXEC)) {
                elf_end(elf);
                return 0;
        }

        bingo = 0;
        while (!bingo && (scn = elf_nextscn(elf, scn)) != NULL) {
                (void) gelf_getshdr(scn, &shdr);

                if (shdr.sh_type != SHT_DYNAMIC || shdr.sh_entsize == 0)
                        continue;

                while (!bingo && (data = elf_getdata (scn, data)) != NULL) {
                        int maxndx = data->d_size / shdr.sh_entsize;
                        int ndx;

                        for (ndx = 0; ndx < maxndx; ++ndx) {
                                (void) gelf_getdyn (data, ndx, &dyn);
                                if (!(dyn.d_tag == DT_GNU_PRELINKED || dyn.d_tag == DT_GNU_LIBLIST))
                                        continue;
                                bingo = 1;
                                break;
                        }
                }
        }
        elf_end(elf);

        return bingo;
}

/*
 * Open path via prelink -y, set fd
 * Return: 0 failure / > 0 success
 *
 */
pid_t open_prelinked(const char * path, int * fd) {
        const char *cmd = PRELINK_PATH;
        pid_t pid = 0;
        int pipes[2];

        pipes[0] = pipes[1] = -1;
        if (pipe(pipes) < 0)
           return 0;
        pid = fork();
        switch (pid) {
           case 0:
              /* child */
              close(pipes[0]);
              dup2(pipes[1], STDOUT_FILENO);
              close(pipes[1]);
              unsetenv("MALLOC_CHECK_");
              execl(cmd, cmd, "--verify", path, (char *) NULL);
              exit(1);
              break;
           case -1:
              close(pipes[0]);
              close(pipes[1]);
              return 0;
        }
        /* parent */
        close(pipes[1]);
        *fd = pipes[0];
        return pid;
}

#endif

pid_t pid = -1;
int p_parent_to_child[2];
int p_child_to_parent[2];
int p_stderr[2];

static void write_empty_md_hashsums(int fd) {
    md_hashsums md_hash;
    md_hash.attrs = 0LU;
    write(fd, &md_hash, sizeof(md_hash));
}

int stat_cmp(struct stat* f1,struct stat* f2) {
  if (f1==NULL || f2==NULL) {
    return RETFAIL;
  }
#define stat_cmp_helper(n,attribute) ((f1->n!=f2->n)*ATTR(attribute))

  return (stat_cmp_helper(st_ino,attr_inode)|
	  stat_cmp_helper(st_mode,attr_perm)|
	  stat_cmp_helper(st_nlink,attr_linkcount)|
	  stat_cmp_helper(st_size,attr_size)|
	  stat_cmp_helper(st_mtime,attr_mtime)|
	  stat_cmp_helper(st_ctime,attr_ctime)|
	  stat_cmp_helper(st_blocks,attr_bcount)|
	  stat_cmp_helper(st_blksize,attr_bsize)|
	  stat_cmp_helper(st_rdev,attr_rdev)|
	  stat_cmp_helper(st_gid,attr_gid)|
	  stat_cmp_helper(st_uid,attr_uid)|
	  stat_cmp_helper(st_dev,attr_dev));
}

#ifdef WITH_PRELINK
/*
 * Timeout handler
 */
void timeout(int signum) {
	error(0, "Timeout of prelink child process\n");
}
#endif

md_hashsums calc_hashsums(char* fullpath, DB_ATTR_TYPE attr, struct stat* old_fs) {
    int wstatus;
    md_hashsums md_hash;
    md_hash.attrs = 0LU;

    bool fork_child = false;
    if (pid == -1) {
        log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(parent): child not yet started", pid);
        fork_child = true;
    } else if (waitpid(pid, &wstatus, WNOHANG) < 0) {
        if (WTERMSIG(wstatus) == SIGBUS) {
#ifdef HAVE_SIGABBREV_NP
            log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(parent): child process %d caught signal 'SIG%s'", pid, sigabbrev_np(WTERMSIG(wstatus)));
#else
            log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(parent): child process %d caught signal '%s'", pid, strsignal(WTERMSIG(wstatus)));
#endif
        }
        close(p_parent_to_child[1]);
        close(p_child_to_parent[0]);
        close(p_stderr[0]);
        log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(parent): child process %d not running, forking new child", pid);
        fork_child = true;
    } else {
        log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(parent): child process %d running", pid);
    }
    if (fork_child) {
        if (pipe(p_parent_to_child) == -1) {
            log_msg(LOG_LEVEL_WARNING, "calc_hashsums(parent): pipe() (parent_to_child) failed: %s (hashsums for '%s' could not be calculated)", strerror(errno), fullpath);
            return md_hash;
        }
        if (pipe(p_child_to_parent) == -1) {
            log_msg(LOG_LEVEL_WARNING, "calc_hashsums(parent): pipe() (child_to_parent) failed: %s (hashsums for '%s' could not be calculated)", strerror(errno), fullpath);
            return md_hash;
        }
        if (pipe(p_stderr) == -1) {
            log_msg(LOG_LEVEL_WARNING, "calc_hashsums(parent): pipe() (stderr) failed: %s (hashsums for '%s' could not be calculated)", strerror(errno), fullpath);
            return md_hash;
        }
        if (fcntl(p_stderr[0], F_SETFL, O_NONBLOCK) == -1) {
            log_msg(LOG_LEVEL_WARNING, "calc_hashsums(parent): fcntl() for stderr pipe failed: %s (hashsums for '%s' could not be calculated)", strerror(errno), fullpath);
            return md_hash;
        }
        if ((pid = fork()) == -1) {
            log_msg(LOG_LEVEL_WARNING, "calc_hashsums(parent): fork failed: %s (hashsums for '%s' could not be calculated)", strerror(errno), fullpath);
            return md_hash;
        }
    }
    if(pid == 0) { /* child */
        pid_t child_pid = getpid();
#ifdef HAVE_SYS_PRCTL_H
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() == 1) {
            exit(0);
        }
#endif
        close(p_parent_to_child[1]);
        close(p_child_to_parent[0]);
        close(p_stderr[0]);
        dup2 (p_stderr[1], STDERR_FILENO);
        close(p_stderr[1]);

        char child_fullpath[PATH_MAX];
        struct stat child_old_fs;
        DB_ATTR_TYPE child_attr;
        log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(child:%d): forked child", child_pid);

        while(true) {
            read(p_parent_to_child[0], &child_attr, sizeof(DB_ATTR_TYPE));
            read(p_parent_to_child[0], &child_old_fs, sizeof(struct stat));
            read(p_parent_to_child[0], child_fullpath,  PATH_MAX);
            log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(child:%d): got filename: '%s' (attr: %lu)", child_pid, child_fullpath, child_attr);

            struct stat new_fs;
            int sres=0;
            int stat_diff,filedes;

#ifdef WITH_PRELINK
            pid_t prelink_pid;
#endif

#ifdef HAVE_O_NOATIME
            filedes=open(child_fullpath,O_RDONLY|O_NOATIME);
            if(filedes<0) {
#endif
                filedes=open(child_fullpath,O_RDONLY);
#ifdef HAVE_O_NOATIME
            }
#endif
            if (filedes==-1) {
                log_msg(LOG_LEVEL_WARNING, "hash calculation(child:%d): open() failed for %s: %s (hashsums could not be calculated)", child_pid, child_fullpath, strerror(errno));
                write_empty_md_hashsums(p_child_to_parent[1]);
                continue;
            }
            sres=fstat(filedes,&new_fs);
            if (sres != 0) {
                log_msg(LOG_LEVEL_WARNING, "hash calculation(child:%d): fstat() failed for '%s': %s (hashsums could not be calculated)", child_pid, child_fullpath, strerror(errno));
                write_empty_md_hashsums(p_child_to_parent[1]);
                continue;
            }
            if(!(child_attr&ATTR(attr_rdev))) {
                new_fs.st_rdev=0;
            }
#ifdef HAVE_POSIX_FADVISE
            if (posix_fadvise(filedes,0,new_fs.st_size,POSIX_FADV_NOREUSE)!=0) {
                log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(child:%d): posix_fadvise error for '%s': %s", child_pid, child_fullpath, strerror(errno));
            }
#endif
            if ((stat_diff=stat_cmp(&new_fs,&child_old_fs)) != RETOK) {
                DB_ATTR_TYPE changed_attribures = 0ULL;
                for(ATTRIBUTE i=0;i<num_attrs;i++) {
                    if (((1<<i)&stat_diff)!=0) {
                        changed_attribures |= 1<<i;
                    }
                }
                char *str;
                log_msg(LOG_LEVEL_WARNING, "hash calculation(child:%d): '%s' has been changed (changed attributes: %s, hash could not be calculated)", child_pid, child_fullpath, str = diff_attributes(0, changed_attribures));
                free(str);
                close(filedes);
                write_empty_md_hashsums(p_child_to_parent[1]);
                continue;
            } else {
#ifdef WITH_PRELINK
                prelink_pid=0;
                log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(child:%d): check if '%s' is prelinked", child_pid, child_fullpath);
                if ( is_prelinked(filedes) ) {
                    close(filedes);
                    log_msg(LOG_LEVEL_DEBUG, " calc_hashsums(child:%d): open prelinked file '%s'", child_pid, child_fullpath);
                    prelink_pid = open_prelinked(child_fullpath, &filedes);
                    if (prelink_pid == 0) {
                        log_msg(LOG_LEVEL_WARNING, "hash calculation(child:%d): error on starting prelink for '%s' (hashsums could not be calculated)", child_pid, child_fullpath);
                        write_empty_md_hashsums(p_child_to_parent[1]);
                        continue;
                    }
                }
#endif
                off_t r_size=0;
                off_t size=0;
                char* buf;

                struct md_container mdc;
                mdc.todo_attr = child_attr;
                if (init_md(&mdc, child_fullpath)==RETOK) {
                    log_msg(LOG_LEVEL_DEBUG, " calculate hashes for '%s'", child_fullpath);
#ifdef HAVE_MMAP
#ifdef WITH_PRELINK
                    if (prelink_pid == 0) {
#endif
                        off_t curpos=0;

                        r_size=new_fs.st_size; /* in mmap branch r_size is used as size remaining */
                        while (r_size>0) {
                            if (r_size<MMAP_BLOCK_SIZE) {
#ifdef __hpux
                                buf = mmap(0,r_size,PROT_READ,MAP_PRIVATE,filedes,curpos);
#else
                                buf = mmap(0,r_size,PROT_READ,MAP_SHARED,filedes,curpos);
#endif
                                curpos+=r_size;
                                size=r_size;
                                r_size=0;
                            } else {
#ifdef __hpux
                                buf = mmap(0,MMAP_BLOCK_SIZE,PROT_READ,MAP_PRIVATE,filedes,curpos);
#else
                                buf = mmap(0,MMAP_BLOCK_SIZE,PROT_READ,MAP_SHARED,filedes,curpos);
#endif
                                curpos+=MMAP_BLOCK_SIZE;
                                size=MMAP_BLOCK_SIZE;
                                r_size-=MMAP_BLOCK_SIZE;
                            }
                            if ( buf == MAP_FAILED ) {
                                log_msg(LOG_LEVEL_WARNING, "hash calculation(child:%d): error mmap'ing '%s': %s (hashsums could not be calculated)", child_pid, child_fullpath, strerror(errno));
                                close(filedes);
                                close_md(&mdc, NULL);
                                write_empty_md_hashsums(p_child_to_parent[1]);
                                continue;
                            }

                            if (update_md(&mdc,buf,size)!=RETOK) {
                                log_msg(LOG_LEVEL_WARNING, "hash calculation(child:%d): update_md() failed for '%s' (hashsums could not be calculated)", child_pid, child_fullpath);
                                close(filedes);
                                close_md(&mdc, NULL);
                                munmap(buf,size);
                                write_empty_md_hashsums(p_child_to_parent[1]);
                                continue;
                            }
                            munmap(buf,size);
                        }
                        close_md(&mdc, &md_hash);
                        close(filedes);
                        write(p_child_to_parent[1], &md_hash, sizeof(md_hash));
                        continue;
#ifdef WITH_PRELINK
                    }
#endif
#endif /* HAVE_MMAP */
                    buf=checked_malloc(READ_BLOCK_SIZE);
#if READ_BLOCK_SIZE>SSIZE_MAX
#error "READ_BLOCK_SIZE" is too large. Max value is SSIZE_MAX, and current is READ_BLOCK_SIZE
#endif
                    while ((size=TEMP_FAILURE_RETRY(read(filedes,buf,READ_BLOCK_SIZE)))>0) {
                        if (update_md(&mdc,buf,size)!=RETOK) {
                            log_msg(LOG_LEVEL_WARNING, "hash calculation: update_md() failed for '%s' (hashsums could not be calculated)", fullpath);
                            free(buf);
                            close(filedes);
                            close_md(&mdc, NULL);
                            write_empty_md_hashsums(p_child_to_parent[1]);
                            continue;
                        }
                        r_size+=size;
                    }

#ifdef WITH_PRELINK
                    if (prelink_pid) {
                        int status;
			struct sigaction newhandler;

			newhandler.sa_handler = timeout;
			sigemptyset(&newhandler.sa_mask);
			newhandler.sa_flags = 0;

			sigaction(SIGALRM, &newhandler, NULL);

			alarm(10);

                        (void) waitpid(prelink_pid, &status, 0);
                        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			    alarm(0);
                            log_msg(LOG_LEVEL_WARNING, "hash calculation: error on exit of prelink child process for '%s' (hashsums could not be calculated)", fullpath);
                            free(buf);
                            close(filedes);
                            close_md(&mdc, NULL);
                            write_empty_md_hashsums(p_child_to_parent[1]);
                            continue;
                        }
			alarm(0);
                    }
#endif
                    free(buf);
                    close_md(&mdc, &md_hash);
                    write(p_child_to_parent[1], &md_hash, sizeof(md_hash));
                } else {
                    log_msg(LOG_LEVEL_WARNING, "hash calculation(child:%d): init_md() failed for '%s' (hashsums could not be calculated)", child_pid, child_fullpath);
                    close(filedes);
                    write_empty_md_hashsums(p_child_to_parent[1]);
                    continue;
                }
            }
            close(filedes);
        }
    } else { /* parent */
        if (fork_child) {
            close(p_parent_to_child[0]);
            close(p_child_to_parent[1]);
            close(p_stderr[1]);
        }

        log_msg(LOG_LEVEL_DEBUG, " hash calculation(parent): send filename '%s' (attr: %lu) to child process %d", fullpath, attr, pid);
        write(p_parent_to_child[1], &attr, sizeof(DB_ATTR_TYPE));
        write(p_parent_to_child[1], old_fs, sizeof(struct stat));
        write(p_parent_to_child[1], fullpath, strlen(fullpath)+1);

        read(p_child_to_parent[0], &md_hash, sizeof(md_hash));

        char* child_stderr = pipe2string(p_stderr[0]);

        char* newline;
        char* buffer = child_stderr;
        while (buffer && *buffer != '\0') {
            newline = strchr(buffer, '\n');
            if (newline != NULL) {
                stderr_msg("%.*s\n", newline-buffer, buffer);
                buffer = newline+1;
            } else {
                stderr_msg("%s\n", buffer);
                break;
            }
        }
        free(child_stderr);

        int wpid_result = waitpid(pid, &wstatus, WNOHANG);
        log_msg(LOG_LEVEL_TRACE, " calc_hashsums(parent): waitpid returns %d for child pid %d", wpid_result, pid);
        if (wpid_result > 0 && WIFSIGNALED(wstatus)) {
            if (WTERMSIG(wstatus) == SIGBUS) {
                log_msg(LOG_LEVEL_WARNING, "hash calculation failed for '%s': child process %d caught 'SIGBUS' (was file truncated while AIDE was running?, hash could not be calculated)", fullpath, pid);
            } else {
#ifdef HAVE_SIGABBREV_NP
                log_msg(LOG_LEVEL_WARNING, "hash calculation failed for '%s': child process %d caught signal 'SIG%s' (hash could not be calculated)", fullpath, pid, sigabbrev_np(WTERMSIG(wstatus)));
#else
                log_msg(LOG_LEVEL_WARNING, "hash calculation failed for '%s': child process %d caught signal '%s' (hash could not be calculated)", fullpath, pid, strsignal(WTERMSIG(wstatus)));
#endif
            }
        }
    }
    return md_hash;
}

void fs2db_line(struct stat* fs,db_line* line) {
  
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

  line->perm=fs->st_mode;

  if(ATTR(attr_size)&line->attr||ATTR(attr_sizeg)&line->attr){
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
    acl_t acl_a;
    acl_t acl_d;
    char *tmp = NULL;

    acl_a = acl_get_file(line->fullpath, ACL_TYPE_ACCESS);
    acl_d = acl_get_file(line->fullpath, ACL_TYPE_DEFAULT);
    if ((acl_a == NULL) && (errno == ENOTSUP)) {
      line->attr&=(~ATTR(attr_acl));
      return;
    }
    if (acl_a == NULL)
      log_msg(LOG_LEVEL_WARNING, "tried to read access ACL on %s but failed with: %s",
            line->fullpath, strerror(errno));
    if ((acl_d == NULL) && (errno != EACCES)) /* ignore DEFAULT on files */
    {
      acl_free(acl_a);
      log_msg(LOG_LEVEL_WARNING, "tried to read default ACL on %s but failed with: %s",
            line->fullpath, strerror(errno));
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
    static ssize_t xsz = 1024;
    static char *xatrs = NULL;
    ssize_t xret = -1;

    if (!(ATTR(attr_xattrs)&line->attr))
        return;

    if (!xatrs) xatrs = checked_malloc(xsz);

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
        static ssize_t asz = 1024;
        static char *val = NULL;

        if (!val) val = checked_malloc(asz);

        xattrs = xattr_new();

        while (xret > 0) {
            size_t len = strlen(attr);
            ssize_t aret = 0;

            if (strncmp(attr, "user.", strlen("user.")) &&
                    strncmp(attr, "security.", strlen("security.")) &&
                    strncmp(attr, "trusted.", strlen("trusted.")))
                goto next_attr; /* only store normal xattrs, and SELinux */

            while (((aret = getxattr(line->fullpath, attr, val, asz)) ==
                        -1) && (errno == ERANGE)) {
                asz <<= 1;
                val = checked_realloc (val, asz);
            }

            if (aret != -1)
                xattr_add(xattrs, attr, val, aret);
            else if (errno != ENOATTR)
                log_msg(LOG_LEVEL_WARNING, "getxattr failed for %s:%s", line->fullpath, strerror(errno));

next_attr:
            attr += len + 1;
            xret -= len + 1;
        }
    }

    line->xattrs = xattrs;
}
#endif

#ifdef WITH_SELINUX
void selinux2line(db_line *line) {
    char *cntx = NULL;

    if (!(ATTR(attr_selinux)&line->attr))
        return;

    if (lgetfilecon_raw(line->fullpath, &cntx) == -1) {
        line->attr&=(~ATTR(attr_selinux));
        if ((errno != ENOATTR) && (errno != EOPNOTSUPP))
            log_msg(LOG_LEVEL_WARNING, "lgetfilecon_raw failed for %s: %s", line->fullpath, strerror(errno));
        return;
    }

    line->cntx = checked_strdup(cntx);

    freecon(cntx);
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

    if (!(ATTR(attr_capabilities)&line->attr))
        return;

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
}
#endif

void no_hash(db_line* line) {
  line->attr&=~get_hashes(true);
}

