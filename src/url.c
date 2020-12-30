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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "url.h"

#include <string.h>

struct url_type {
    URL_TYPE type;
    const char *string;
};

static struct url_type url_type_array[] = {
 { url_file, "file" },
 { url_stdout, "stdout" },
 { url_stdin, "stdin" },
 { url_stderr, "stderr" },
 { url_fd, "fd" },
 { url_ftp, "ftp" },
 { url_http, "http" },
 { url_https, "https" },
 { url_syslog, "syslog" },
};

int num_url_types = sizeof(url_type_array)/sizeof(struct url_type);

URL_TYPE get_url_type(char * str) {

    for (int i = 0; i < num_url_types; ++i) {
        if (strcmp(str, url_type_array[i].string) == 0) {
            return url_type_array[i].type;
        }
    }
    return 0;
}

const char* get_url_type_string(URL_TYPE type) {
    return url_type_array[type-1].string;
}
