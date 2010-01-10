#!/bin/sh
# Run this to generate all the initial makefiles, etc.
#
# Needs bash, Solaris sh will not work

PGM=AIDE

#libtool_vers=1.3

DIE=no
autoconf_vers=2.50
automake_vers=1.10
aclocal_vers=1.10

autoconf_guess=("autoconf" "autoconf2.50")
automake_guess=("automake")
aclocal_guess=("aclocal")

set -e 

function check_version() {
    if $1 --version | awk 'NR==1 { if( $NF >= '$2' ) exit 0; exit 1; }' ; then
	return 0;
    fi
    return 1;
}

function check_exists() {
    if $1 --version < /dev/null > /dev/null 2>&1  ; then
	return 0;
    fi
    return 1;
}

function print_error() {
    echo "**Error**: "\`$1\'" is too old or not installed"
    echo '           (version ' $2 ' or newer is required)'
		DIE="yes"
}

function my_try() {
    if check_exists $1 && \
	check_version $1 $2 ; then
	return 0;
    fi
    return 1;
}

function check() {
    eval vers=\$${1}_vers
    printf "checking "$1" for "$vers
    eval vals=\${${1}_guess[*]}
    for a in $vals
      do
      if my_try $a $vers ; then
	  echo " ok"
	  eval ${1}_bin=$a;
	  return 0
      fi
    done
    echo " No"
    print_error $a $vers
		return 1
}

check autoconf
check automake
check aclocal

if test "$DIE" = "yes"; then
    exit 1
fi

echo "Running aclocal..."
$aclocal_bin
echo "Running autoheader..."
autoheader
echo "Running automake --gnu ..."
$automake_bin --gnu;
echo "Running autoconf..."
$autoconf_bin

echo "You can now run \"./configure\" and then \"make\"."
