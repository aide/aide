#!/bin/bash

# Copyright © 2010 Hannes von Haugwitz <hannes@vonhaugwitz.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

set -e
set -u

attributes=( "filename" "linkname" "perm" "uid" "gid" "size" "atime" \
    "ctime" "mtime" "inode" "bcount" "lnkcount" "md5" "sha1" \
    "rmd160" "tiger" "crc32" "haval" "gost" "crc32b" "attr" \
    "acl" "bsize" "rdev" "dev" "checkmask" "growingsize" "checkinode" \
    "allownewfile" "allowrmfile" "sha256" "sha512"  "selinux" \
    "xattrs" "whirlpool" "ftype" "e2fsattrs" )

NAME="aide-attributes"

err() {
    echo "$NAME: $1!" >&2
    echo "usage: $NAME HEX_NUMBER [HEX_NUMBER]"
    exit $2
}

dec2hex() {
    let hex=0x$1 2> /dev/null || err "argument '$1' is no valid hex number" 2
    if [ "$hex" -lt "0" ] || [ "$hex" -gt "$((2**${#attributes[@]}))" ] ; then
        err "argument '$1' too large (> 2^${#attributes[@]})" 3
    fi
    echo "$hex"
}

COMPARE=false

if [ -n "${1:-}" ] ; then
    a=$(dec2hex $1)
    if [ -n "${2:-}" ] ; then
        COMPARE=true
        b=$(dec2hex $2)
        [ -n "${3:-}" ] && err "Too much arguments provided" 4
    fi
else
    err "Not enough arguments provided" 1;
fi

for (( i=0; i<${#attributes[@]}; i++ )) ; do
    if $COMPARE ; then
        if (( 2**$i & $a )) && ! (( 2**$i & $b )) ; then
            echo "-"${attributes[$i]}
        elif ! (( 2**$i & $a )) && (( 2**$i & $b )) ; then
            echo "+"${attributes[$i]}
        fi
    else
        if (( 2**$i & $a )) ; then
            echo "${attributes[$i]}"
        fi
    fi
done

exit 0
