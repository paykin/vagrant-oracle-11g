#!/bin/sh
#
# $Header: opsm/cvutl/runfixup.sh /main/3 2008/7/07 17:45:45 nvira Exp $
#
# runfixup.sh
#
# Copyright (c) 2007, 2008, Oracle. All rights reserved.  
#
#    NAME
#      runfixup.sh - This script is used to run fixups on a node
#
#    DESCRIPTION
#      <short description of component this file declares/defines>
#
#    NOTES
#      <other useful comments, qualifications, etc.>
#
#    MODIFIED   (MM/DD/YY)
#    nvira       06/24/08 - remove sudo
#    dsaggi      05/29/08 - remove orarun.log before invocation
#    dsaggi      10/24/07 - Creation
#

if [ -z "$ECHO" ]; then ECHO=/bin/echo; fi
if [ -z "$ID" ]; then ID=/usr/bin/id; fi

RUID=`$ID -u`
if [ "${RUID}" != "0" ];then
	  $ECHO "You must be logged in as root (uid=0) when running $0."
	    exit 1
fi


EXEC_DIR=`dirname $0`

RMF="/bin/rm -f"

#  Remove old orarun.log before invocation
$RMF ${EXEC_DIR}/orarun.log

${EXEC_DIR}/orarun.sh ${EXEC_DIR}/fixup.response  ${EXEC_DIR}/fixup.enable ${EXEC_DIR}
