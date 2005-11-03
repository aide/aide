#!/bin/bash

# $Id$

# aide check script
# Written by: charlie heselton 
# Email: echo "hfouvyAdpy/ofu" | perl -pe 's/(.)/chr(ord($1)-1)/ge'
# 09/23/2005

# Set up some variables
DBDIR="/your/aide/db/directory"
DBFILE="${DBDIR}/aide.db"
ENC_DBFILE="${DBDIR}/aide.db.gpg"

# make the assumption that the database exists and is encrypted
# but test for it  ;-)
[[ -f ${ENC_DBFILE} ]] && /usr/bin/gpg --batch -d ${ENC_DBFILE} > ${DBFILE}
rm -f ${ENC_DBFILE}

# (for now, we'll assume that encrypting the file includes an integrity check )
# Run the check.
/usr/bin/aide -C > /tmp/aide_check.out 2>&1

# mail out the results
/usr/bin/cat /tmp/aide_check.out | /usr/bin/mutt -s "AIDE Check for `date`" your_valid_email@somewhere.com

# cleanup
# if the mail was successful, delete the output file
if [ $? -eq 0 ]
then
	rm -f /tmp/aide_check.out
fi

# re-encrypt the database and delete the unencrypted version
/usr/bin/gpg --batch -se -r gentoo_root ${DBFILE} 
rm -f ${DBFILE}
