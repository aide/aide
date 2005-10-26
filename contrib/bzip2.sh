#!/bin/bash
#
# Lifted from E-mails by Sven.Hartrumpf@fernuni-hagen.de
#
# The idea is to set database_out=stderr in aide.conf you can then use
# this one liner to decompress aide.db and recompress aide.db.new

bzcat aide.db.bz2 | ( /media/floppy/aide -c aide.conf --verbose=0 -u 1> /tmp/aideu.log ) 2>&1 | bzip2 -9 > aide.db.new
