#!/bin/sh
#
# Simple script to generate daily aide release from git
#
# 2010/08/08 Richard van den Berg <richard@vdberg.org>

TMP=/tmp/aide-git-snapshot.$$
cd $TMP
git clone -q git://aide.git.sourceforge.net/gitroot/aide/aide
NOW=`date +%Y%m%d`
AGIT="aide-git-$NOW"
mv aide $AGIT
cd $AGIT
# Get latest commit id
CID=`git rev-list -1 --abbrev-commit origin/master`
if [ "$CID" != "" ]; then
	# Append commit id to aide version
	sed -e "s/])/-git$CID])/" version.m4 > version.$$
	if [ -s version.$$ ]; then
		mv version.$$ version.m4
	fi
fi
# Generate configure script
bash autogen.sh > /dev/null 2>/dev/null
if [ ! -f configure ]; then
	echo "ERROR: configure script was not generated!"
	exit 1
fi
rm -rf autom4te.cache
cd ..
# Create tar.gz
tar czf $AGIT.tar.gz $AGIT
chmod 664 $AGIT.tar.gz
# Copy tar.gz to sf.net webserver
scp -qp $AGIT.tar.gz user,aide@web.sourceforge.net:htdocs/aide-git-snapshot.tar.gz
# Clean up
rm -rf $TMP
