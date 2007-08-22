#!/bin/sh
# $Id$

# Script by Vincent Danen <vdanen@linsec.ca>

hostname=`uname -n`
echo "AIDE integrity check for ${hostname} beginning (`date`)"
echo ""
if [ ! -e /var/lib/aide/aide.db ] ; then
    echo "**** Error: AIDE database for ${hostname} not found."
    echo "**** Run 'aide --init' and move the appropriate database file."
else
    if [ -f /etc/aide.conf ]; then
        if [ -f /var/lib/aide/aide.db.sig ]; then
	    pushd /var/lib/aide >/dev/null
	        echo "Verifying the GPG signature on the database..."
		echo ""
	        gpg --verify aide.db.sig
		echo ""
		if [ "$?" == "1" ]; then
		    echo "************************************************************"
		    echo "GPG signature FAILED!  Your database has been tampered with!"
		    echo "************************************************************"
		    exit 1
		fi
	    popd >/dev/null
	fi
        nice -20 /usr/sbin/aide --check 2>/dev/null
    fi
fi

exit 0
