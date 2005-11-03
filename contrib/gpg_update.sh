#!/bin/bash

# $Id$

# aide update script
# Written by: charlie heselton
# Email: echo "hfouvyAdpy/ofu" | perl -pe 's/(.)/chr(ord($1)-1)/ge'
# 09/23/2005

DBDIR="/etc/aide/db"
DBFILE="${DBDIR}/aide.db"
ENC_DBFILE="${DBDIR}/aide.db.gpg"

# make the assumption that the database exists and is encrypted
# but test for it  ;-)
[[ -f ${ENC_DBFILE} ]] && /usr/bin/gpg --batch -d ${ENC_DBFILE} > ${DBFILE}
rm -f ${ENC_DBFILE}

# (for now, we'll assume that encrypting the file includes an integrity check )
# Run the update.  
/usr/bin/aide --update > /tmp/aide_update.out 2>&1

# mail out the results
# set the "Reply-to" address
REPLYTO="root@charlesheselton.no-ip.org"
export REPLYTO
# send the mail
/usr/bin/cat /tmp/aide_update.out | /usr/bin/mutt -s "AIDE Update for `date`" your_valid_email@somewhere.com

# cleanup
# if the mailing was successful then delete the output file
if [ $? -eq 0 ]
then
	rm -f /tmp/aide_update.out
fi

# move the aide.db.new file to the aide.db
mv ${DBDIR}/aide.db.new ${DBFILE}

# encrypt the new db file and remove the unencrypted version
/usr/bin/gpg --batch -se -r gentoo_root ${DBFILE}
rm -f ${DBFILE}
