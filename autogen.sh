#!/bin/sh

# Get version number
if sh ./version.sh; then
    # Run this to generate all the initial makefiles, etc.
    autoreconf -fv --install && echo "You can now run \"./configure\" and then \"make\"."
else
    echo "Error: ./version.sh failed."
    exit 1
fi
