#!/bin/sh

if GIT_VERSION=$(git describe --always); then
    echo "m4_define([AIDE_VERSION], [${GIT_VERSION#v}])" > version.m4.$$
    mv version.m4.$$ version.m4
    rm -f version.m4.$$
else
    echo "Error: 'git describe --always' failed"
    exit 1
fi
