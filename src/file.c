/*
 * AIDE (Advanced Intrusion Detection Environment)
 *
 * Copyright (C) 2016,2020,2021,2024,2025 Hannes von Haugwitz
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
#include "file.h"
#ifdef HAVE_FSTYPE
#include <string.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <stdio.h>
#include "util.h"
#endif
#include <limits.h>

#ifdef HAVE_FSTYPE
filesystem_t filesystems[] = {
    { "9p",             V9FS_MAGIC              },
    { "autofs",         AUTOFS_SUPER_MAGIC      },
    { "bcachefs",       0xca451a4e              },
    { "binfmt",         BINFMTFS_MAGIC          },
    { "bpf",            BPF_FS_MAGIC            },
    { "btrfs",          BTRFS_SUPER_MAGIC       },
    { "cgroup",         CGROUP_SUPER_MAGIC      },
    { "cgroup2",        CGROUP2_SUPER_MAGIC     },
    { "configfs",       0x62656570              },
    { "debugfs",        DEBUGFS_MAGIC           },
    { "devpts",         DEVPTS_SUPER_MAGIC      },
    { "efivarfs",       EFIVARFS_MAGIC          },
    { "exfat",          EXFAT_SUPER_MAGIC       },
    { "ext",            EXT2_SUPER_MAGIC        }, /* ext2/ext3/ext4 */
    { "f2fs",           F2FS_SUPER_MAGIC        },
    { "fuse",           FUSE_SUPER_MAGIC        },
    { "fusectl",        0x65735543              },
    { "hugetlbfs",      HUGETLBFS_MAGIC         },
    { "mqueue",         0x19800202              },
    { "nfs",            NFS_SUPER_MAGIC         },
    { "nilfs",          NILFS_SUPER_MAGIC       },
    { "overlayfs",      OVERLAYFS_SUPER_MAGIC   },
    { "proc",           PROC_SUPER_MAGIC        },
    { "pstore",         PSTOREFS_MAGIC          },
    { "ramfs",          RAMFS_MAGIC             },
    { "securityfs",     SECURITYFS_MAGIC        },
    { "selinuxfs",      SELINUX_MAGIC           },
    { "squashfs",       SQUASHFS_MAGIC          },
    { "sysfs",          SYSFS_MAGIC             },
    { "tmpfs",          TMPFS_MAGIC             },
    { "tracefs",        TRACEFS_MAGIC           },
    { "udf",            UDF_SUPER_MAGIC         },
    { "vfat",           MSDOS_SUPER_MAGIC       },
    { "xfs",            XFS_SUPER_MAGIC         },
};
int num_filesystems = sizeof(filesystems)/sizeof(filesystem_t);
#endif

typedef struct {
    char c;
    char *s;
    FT_TYPE r;
    mode_t ft;
} f_type_t;

static f_type_t filetypes[] = {
    { 'f', "regular file", FT_REG, S_IFREG },
    { 'd', "directory", FT_DIR, S_IFDIR },
#ifdef S_IFIFO
    { 'p', "FIFO", FT_FIFO, S_IFIFO },
#endif
    { 'l', "symbolic link",    FT_LNK, S_IFLNK },
    { 'b', "block device",     FT_BLK, S_IFBLK },
    { 'c', "character device", FT_CHR, S_IFCHR },
#ifdef S_IFSOCK
    { 's', "socket", FT_SOCK, S_IFSOCK },
#endif
#ifdef S_IFDOOR
    { 'D', "door", FT_DOOR, S_IFDOOR },
#endif
#ifdef S_IFPORT
    { 'P', "port", FT_PORT, S_IFPORT },
#endif
};

static int num_filetypes = sizeof(filetypes)/sizeof(f_type_t);

char get_f_type_char_from_f_type(FT_TYPE r) {
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (r == filetypes[i].r) {
            return filetypes[i].c;
        }
    }
    return '?';
}

char *get_f_type_string_from_f_type(FT_TYPE r) {
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (r == filetypes[i].r) {
            return filetypes[i].s;
        }
    }
    return "unknown file type";
}

char get_f_type_char_from_perm(mode_t mode) {
    mode_t ft = mode & S_IFMT;
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (ft == filetypes[i].ft) {
            return filetypes[i].c;
        }
    }
    return '?';
}

char *get_f_type_string_from_perm(mode_t mode) {
    mode_t ft = mode & S_IFMT;
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (ft == filetypes[i].ft) {
            return filetypes[i].s;
        }
    }
    return "unknown file type";
}

FT_TYPE get_f_type_from_char(char c) {
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (c == filetypes[i].c) {
            return filetypes[i].r;
        }
    }
    return FT_NULL;
}

FT_TYPE get_f_type_from_perm(mode_t mode) {
    mode_t ft = mode & S_IFMT;
    for (int i = 0 ; i < num_filetypes; ++i) {
        if (ft == filetypes[i].ft) {
            return filetypes[i].r;
        }
    }
    return FT_NULL;
}

#ifdef HAVE_FSTYPE
FS_TYPE get_fs_type_from_string(const char *fs_type_str) {
    for (int i = 0 ; i < num_filesystems; ++i) {
        if (strcmp(filesystems[i].str, fs_type_str) == 0) {
            return filesystems[i].magic;
        }
    }
    if (strncmp(fs_type_str, "0x", 2) == 0) {
        long long ll;
        char* e;
        ll = strtoll(fs_type_str, &e, 16);
        if (*e =='\0' && ll > 0 && ll <= UINT_MAX) {
            return (FS_TYPE) ll;
        }
    }
    return 0;
}

int generate_fs_type_string(FS_TYPE magic, char* str) {
    for (int i = 0 ; i < num_filesystems; ++i) {
        if (filesystems[i].magic == magic) {
            size_t length = strlen(filesystems[i].str)+1;
            if (str) { sprintf(str, "%s", filesystems[i].str); }
            return length;
        }
    }
    size_t length = snprintf(NULL, 0, "0x%lx", magic)+1;
    if (str) { sprintf(str, "0x%lx", magic); }
    return length;
}

char *get_fs_type_string_from_magic(FS_TYPE magic) {
    char *str = NULL;
    int n = generate_fs_type_string(magic, str);
    str = checked_malloc(n);
    generate_fs_type_string(magic, str);;
    return str;
}
#endif
