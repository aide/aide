#!/bin/sh
#
# Simple script to generate daily aide release from git
#
# Copyright © 2011 Hannes von Haugwitz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

if [ -n "$1" ] ; then
    SCP_USER="$1"
    SCP_TARGET="web.sourceforge.net:htdocs/snapshots/aide-daily-snapshot.tar.gz"
    SAVED_PWD=`pwd`
    TMP=/tmp/aide-daily-release.$$
    mkdir $TMP
    cd $TMP
    if git clone -q git://aide.git.sourceforge.net/gitroot/aide/aide; then
        cd aide
        if sh autogen.sh >/dev/null 2>&1; then
            if ./configure >/dev/null 2>&1; then
                if make distcheck  >/dev/null 2>&1; then
                    if GIT_VERSION=`git describe`; then
                        chmod 644 aide-${GIT_VERSION#v}.tar.gz
                        if ! scp -qp aide-${GIT_VERSION#v}.tar.gz $SCP_USER@$SCP_TARGET; then
                            echo "ERROR: 'scp' failed!"
                            exit 7
                        fi
                    else
                        echo "ERROR: 'git describe' failed!"
                        exit 6
                    fi
                else
                    echo "ERROR: 'make distcheck' failed!"
                    exit 5
                fi
            else
                echo "ERROR: './configure' failed!"
                exit 4
            fi
        else
            echo "ERROR: 'sh autogen.sh' failed!"
            exit 3
        fi
    else
        echo "ERROR: 'git clone' failed!"
        exit 2
    fi
    cd $SAVED_PWD
    rm -rf $TMP
else
    echo "ERROR: you must specify a username (e.g. ./mkdailyrelease.sh user,aide)"
    exit 1
fi
