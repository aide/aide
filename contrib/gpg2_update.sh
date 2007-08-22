#!/bin/sh
# $Id$
#
# script to update and rotate the AIDE database files and, optionally
# create a detached GPG signature to verify the database file
#
# written by Vincent Danen <vdanen-at-annvix.org> 01/21/2006

usegpg=0

if [ -f /root/.gnupg/secring.gpg ]; then
    usegpg=1
fi

if [ ! -d /var/lib/aide ]; then
    echo "The AIDE database directory /var/lib/aide does not exist!"
    exit 1
fi

pushd /var/lib/aide >/dev/null

# copy the old database
if [ -f aide.db ]; then
    newfile="aide-`hostname`-`date +%Y%m%d-%H%M%S`.db"
    if [ "${usegpg}" == 1 -a -f aide.db.sig ]; then
        # do an integrity check
	gpg --verify aide.db.sig
	if [ "$?" == "1" ]; then
	    echo "************************************************************"
	    echo "GPG signature FAILED!  Your database has been tampered with!"
	    echo "************************************************************"
	    exit 1
	fi
    fi
    cp -av aide.db ${newfile} 
    /usr/sbin/aide --update -B "database=file:/var/lib/aide/${newfile}" 
    if [ "${usegpg}" == "1" ]; then
	# create the signature file
	[[ -f aide.db.sig ]] && rm -f aide.db.sig
        gpg --detach-sign aide.db
	if [ "$?" == "1" ]; then
	    echo "FATAL:  Error occurred when creating the signature file!"
	    exit 1
	fi
    fi
    gzip -9f ${newfile}
else
    echo "The AIDE database does not exist, can't update!"
    exit 1
fi

popd >/dev/null
