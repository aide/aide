#!/bin/sh
# $Header$

find . -name CVS -exec rm -rf {} \;
find . -name .cvsignore -exec rm -f {} \;
rm -f $0
