#!/bin/sh
#
# $Id$
#
# NAME
#       sshaide.sh - SSH/AIDE remote integrity monitoring script
#
# SYNOPSIS
#       sshaide.sh  -check|-init  ALL|<machine-list>
#
# DESCRIPTION
#       sshaide.sh uses AIDE and SSH to remotely run integrity checks
#       on ALL configured client systems or those specifically listed on
#       the command line from a centralized manager station.  sshaide.sh
#       stores all binaries, databases and reports on a secure, centralized
#       manager station.  Database initialization or periodic checks are
#       run on demand or via cron jobs from the manager stations based on
#       local policy requirements.
#
#       sshaide.sh requires a valid account on the remote system and uses
#       SSH RSA authentication with public/private password-less key pairs
#       to obtain automated, scripted access to a remote system.  Naturally
#       the account(s), sshaide.sh keys and manager system must be heavily
#       protected from compromise.  To minimize potential problems, it is
#       recommended that sshaide.sh use non-privileged accounts.  While
#       this limits access to verify some files and diretories on remote
#       systems, we believe it is an acceptable trade-off.  Most critical
#       files and directories can be effectively monitored without having
#       privileged access.  It is recommended that an unprivileged, but
#       dedicated account on the manager station also be setup to manage
#       AIDE databases, AIDE reports, remote logins and other sshaide.sh
#       requirements.
#
#       Remote clients must have the public SSH RSA key that will be used
#       by the sshaide.sh manager.  The sshaide.sh manager must have the
#       managed client's SSH server RSA public key in known_hosts or
#       hostkeys file.  Refer to your SSH documentation for instructions
#       on setting up public SSH RSA keys.
#
# OPTIONS
#       The option must be given in the proper order and with proper
#       syntax.
#
#       -init   Initialize or re-initialize the AIDE database for the
#               listed host or hosts.
#
#       -check  Run an integrity check on the specified system or systems.
#               The database for any host being checked must have already
#               been intialized.
#
# DIRECTORIES and FILES
#       ~/
#               This is the home directory of the user running sshaide.sh.
#               By default, this is retrieved from the $HOME environment
#               variable.
#
#       ~/bin
#               The directory where the sshaide.sh script and AIDE
#               binaries are stored.  Required.
#
#       ~/bin/sshaide.sh
#               The sshaide.sh program.  This file.  Required.
#
#       ~/bin/aide.[platform]
#               The AIDE binary for a [platform].  For example, a Linux
#               2.4 binary may be named aide.linux-2.4.  These binaries
#               will be linked to from the independent client directories
#               based on their platform requirements.  Required.
#
#       ~/configs
#               The directory where the AIDE configuration files are
#               stored.  Common AIDE configurations are stored here and
#               can be linked to from the independent client directories
#               based on policy requirements.  Required.
#
#       ~/reports
#               This directory will store the initialization logs and
#               integrity check reports.  Integrity reports will be
#               tar.gz'd by year-month-day-hour.  Required, but created
#               automatically by sshaide.sh.
#
#       ~/clients
#               This is the parent directory for all client hosts being
#               managed.  Required.
#
#       ~/clients/[client-host]
#               This directory is a specific client host to be managed by
#               sshaide.sh. [client-host] is a host name.  Short host name
#               is usually sufficient, but a fully qualified domain name
#               may be used if there may be host name overlap from different
#               subdomains.  Required for each client to be managed by
#               sshaide.sh.
#
#       ~/clients/[client-host]/aide.db_[client_host]
#               This file is the AIDE database for the [client-host] being
#               managed by sshaide.sh.  Required, but created automatically
#               by the -init process.
#
#       ~/clients/[client-host]/aide.db_[client-host].old
#               This file is the previous AIDE database before the last
#               -init process.  Not required.  Created automatically after
#               the second or additional database initialization.
#
#       ~/clients/[client-host]/sshaide.conf
#               This file contains client specific configuration information.
#               Optional.  The following three options are available:
#
#                 emaillist         comma-separated-list-of-addresses
#                       This option specifies the email addresses that
#                       sshaide.sh output should be delivered to.
#                 homedir           full-home-diretory-path-on-client
#                       This option specifies the fully qualified path
#                       used on the client host.  This would be equivalanet
#                       to the $HOME environment variable on the client
#                       system.
#                 userid             remote-user-id
#                       This option specifies the remote login id with
#                       which to login to the remote system with.
#
#               All configuration options are optional, but if present,
#               they must be begin in column 1 with whitespace separting
#               the desired value(s).
#
#       ~/clients/[client-host]/reinit
#               The existence of this file indicates that the AIDE database
#               for this client host should be reinitialized through the
#               -init process on the next run.  Simply `touch` this file
#               whenever you want to reinitialize the client host database.
#               This file will be automaticaly removed after the next -init
#               process.  Optional.
#
#       ~/clients/[client-host]/aide.conf
#               This is a soft link to the appropriate AIDE configuration
#               file in ~/configs.   The following two lines are required
#               for each configuration file:
#
#                 database=file:./aide.db
#                 database_out=file:./aide.newdb
#
#       ~/clients/[client-host]/aide
#               This is a soft link to the appropriate AIDE binary for
#               the client host platform in ~/bin.  Required.
#
#       ~/tmp
#               This is a temporary work directory for sshaide.sh.
#               Required.
#
# Original concept and coding from:
#   Judith A Freeman <jaf@uchicago.edu>
#   University of Chicago
#   Network Security Center <network-security@uchicago.edu>
#   <http://security.uchicago.edu>
#   28 June 1998 to 16 May 2000
#
# Updates by:
#   John Kristoff <jtk@northwestern.edu>
#   <http://aharp.ittns.northwestern.edu>
#   Northwestern University
#   Telecommunications and Network Services
#
# 2003-12-03,jtk: updated for AIDE v0.10 and Linux
#   newly packaged as sshaide.sh
#   adjusted default path to something more reasonable for linux
#   replaced tripwire references with aide naming conventions
#   replaced hard coded root user id with $userid variable from whoami
#   added LC_ALL=C for grep to work with traditional [] interpretations
#   added a cd to remote_aidedir on remote machine
#   forced remote_aidedir directory creation (with 'mkdir -p')
#   added quotes to ssh commands
#   changed the email subject and header format
#   changed mail delivery and email creation handling
#   minor commenting edits
#   adjusted wordlist for Linux and Solaris, exiting if file not found
#   removed $1 for wordlist
#   implemented config file for remote_aidedir and emaillist per machine
#   changed reinit check from read (-r) to write (-w) check
#   fixed tar/gzip'ing of reports only on -check mode
#   removed unncessary root directory variable, use just aidedir
# 2003-12-06,jtk:minor configuration updates
#   added userid option to config and created $useriddefault
#   set default remote home directory with $homedefault
# 2003-12-16,jtk: fixed sshaide.conf usage
#   added doc about userid config in sshaide.conf
#   changed order of sshaide.conf config options so remote_aidedir works
# 2004-02-12,jtk: minor doc editing
 
###
### Basic setup
###
 
# Get a limited path
PATH=/bin:/usr/bin:/usr/local/bin:/usr/ucb
 
# For debugging only
# set -x
 
###
### Local variable declarations
###
 
# set the remote username to login and run aide as
useriddefault=`whoami`
 
# Who gets the mail if not set in client dir?
maildefault=root@localhost
 
# remote home directory
homedefault=/home/${useriddefault}
 
# $date in the form year-month-day-hour
date=`date +%Y-%m-%d-%H`
 
# Where are we running out of
aidedir=${HOME}
 
# Setup local directories and files for use
clientdir=${aidedir}/clients
tmpdir=${aidedir}/tmp
 
progname=`basename $0`
 
###
### Functions
###
 
# Give usage statement
usage () {
    echo ""
    echo "Usage: `${progname}` <run-mode> ALL|<machine-list>"
    echo "  run-mode: -init | -check"
    echo "  machine-list: space separated list in quotes"
    echo ""
}
 
## gen_rand_word  - returns a semi-random word
##    only returns words that are all lowercase letters
 
gen_rand_word () {
    # Set the word list
    if test -r "/usr/share/dict/words" ; then
        # For Linux
        _wordlist="/usr/share/dict/words"
    elif test -r "/usr/dict/words" ; then
        # For Solaris
        _wordlist="/usr/dict/words"
    else
        echo ERROR: words file not found!  Exiting...
        exit 0
    fi
 
    _randnum=`date +%H%S%Y%m%H%d%S%S`
    _listlines=`cat ${_wordlist} | wc -l`
    _linenum=`expr ${_randnum} % ${_listlines}`
 
    # If we picked line 0, change it to 1 'cause line 0 doesn't exist
    if test ${_linenum} -eq 0 ; then
        _linenum=1
    fi
 
    _randword=`grep -n . ${_wordlist} | grep "^${_linenum}:" | cut -d: -f2`
 
    # If $_randword has anything other than lower-case chars, try again
    (echo ${_randword} | LC_ALL=C grep '[^a-z]' 2>&1 >> /dev/null \
            && gen_rand_word ) || \
 
    # Return the word
    echo ${_randword}
}
 
init_cmds () {
 
    if test ! -d ${aidedir}/reports/initlogs/ ; then
        mkdir -p ${aidedir}/reports/initlogs/
    fi
 
    ssh -l $userid $machine "(umask 077 ; cd ${remote_aidedir}; ${remote_aidedir}/aide --init --config=${remote_aidedir}/aide.conf 2>&1 | tee ${remote_aidedir}/initoutput >> /dev/null)"
 
    # Copy output back to file
    mkdir -p ${tmpdir}/initoutput/${date}
    scp -q ${userid}@${machine}:${remote_aidedir}/initoutput ${inittmp}/${machine}
    # backup old database if it exists
    if test -r ${clientdir}/${machine}/aide.db_${machine} ; then
        mv ${clientdir}/${machine}/aide.db_${machine} ${clientdir}/${machine}/aide.db_${machine}.old
    fi
 
    scp -q ${userid}@${machine}:${remote_aidedir}/aide.newdb ${clientdir}/${machine}/aide.db_${machine}
}
 
check_cmds () {
    scp -q $db ${userid}@${machine}:${remote_aidedir}/aide.db
    ssh -l $userid $machine "umask 077 && cd ${remote_aidedir} && ${remote_aidedir}/aide --config=${remote_aidedir}/aide.conf 2>&1 | tee ${remote_aidedir}/report >> /dev/null"
 
    # Copy output back to file
    if test ! -d ${aidedir}/reports/${date} ; then
        mkdir ${aidedir}/reports/${date}
    fi
    scp -q ${userid}@${machine}:${remote_aidedir}/report $reports/${machine}
 
}
 
###
### The program
###
 
# From the commandline
case $# in
    2) mode=$1; thehosts=$2 ;;
    *) usage; exit 1 ;;
esac
 
# Set mode specific variables
case $mode in
    -init)       initlogs=${aidedir}/reports/initlogs
                 inittmp=${tmpdir}/initoutput/${date}
                 mail_fordir=${inittmp} ;;
    -check)      reports=${aidedir}/reports/${date}
                 mail_fordir=${reports} ;;
esac
 
#
case $thehosts in
     ALL) forcmd=`ls ${clientdir}` ;;
       *) forcmd=$thehosts ;;
esac
 
for machine in $forcmd ; do
    sleep 2  # so we get a different random word
 
    (    ## background it (this is so it runs in parellel)
 
    # Set up local directories and files for use
    config=${clientdir}/${machine}/aide.conf
    db=${clientdir}/${machine}/aide.db_${machine}
    binary=${clientdir}/${machine}/aide
    log=${clientdir}/${machine}/log
    sshaide_conf=${clientdir}/${machine}/sshaide.conf
 
    # Set up temporary directory name for remote machine
    rand_word=`gen_rand_word`
 
    # Apply client host configuration options
    if  test ! -r ${sshaide_conf}  ; then
        remote_aidedir=${homedefault}/${rand_word}.$$
        mailrcpts=${maildefault}
        userid=${useriddefault}
    else
        # Get the email addresses to send reports to
        grep '^emaillist' ${sshaide_conf}
        if [ $? != 0 ] ; then
            mailrcpts=${maildefault}
        else
            mailrcpts=`grep -m1 '^emaillist' ${sshaide_conf} | \
            awk '{print $2}'`
        fi
        # Get the remote user id
        grep '^userid' ${sshaide_conf}
        if [ $? != 0 ] ; then
            userid=${useriddefault}
        else
            userid=`grep -m1 '^userid' ${sshaide_conf} | \
            awk '{print $2}'`
        fi
        # Get home directory to use on remote machine
        grep '^homedir' ${sshaide_conf}
        if [ $? != 0 ] ; then
            remote_aidedir=/home/${userid}/${rand_word}.$$
        else
            remote_aidedir=`grep -m1 '^homedir' ${sshaide_conf} | \
            awk '{print $2}'`/${rand_word}.$$
        fi
    fi
 
    # Do the dirty work
    ssh -l $userid $machine "mkdir -p $remote_aidedir"
    scp -q $config ${userid}@${machine}:${remote_aidedir}
    scp -q $binary ${userid}@${machine}:${remote_aidedir}
 
    case $mode in
        -init)        init_cmds ;;
        -check)       check_cmds ;;
    esac
 
    # Delete remote directory
    ssh -l $userid $machine "rm -rf $remote_aidedir"
 
    # If $mail_fordir doesn't exist, don't continue
    if test ! -d "${mail_fordir}" ; then
        echo "${progname}:${mail_fordir} doesn't exist,"
        echo "exiting now, not sending mail"
        exit 1
    fi
     
    ###
    ### Mail reports out
    ###
     
    cat ${mail_fordir}/${machine} \
    | mail -s "### AIDE ${mode} ${machine} ${date}" ${mailrcpts}
 
    )
done
 
# Wait for all bg processes to finish before continuing
wait
 
# Tar and compress the reports
if test $mode = -check ; then
    tar cf ${reports}.tar ${reports}
    rm -rf ${reports}
    gzip -9 ${reports}.tar
fi
 
# If mode is check, examine clientdir for reinit file, and
# reinitialize if it exists
 
if test $mode = -check ; then
    for host in $forcmd ; do
        if test -w ${clientdir}/${host}/reinit ; then
            ${aidedir}/bin/${progname} -init ${host} &
            rm ${clientdir}/${host}/reinit
        fi
    done
fi
 
###
### Clean up init stuff
###
 
if test $mode = -init ; then
 
    # Concatenate inittmp directories into initlogs
    for host in `ls -A ${mail_fordir}` ; do
    (
    echo "********************************************"
    echo ${host} $date ${mode}
    echo "********************************************"
    echo ""
    cat ${mail_fordir}/${host}
    echo ""
    )| tee -a $initlogs/`date +%Y-%m` >> /dev/null
    done
 
    # Delete inittmp directory
    rm -rf ${tmpdir}/initoutput
fi
