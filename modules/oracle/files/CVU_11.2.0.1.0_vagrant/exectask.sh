#!/bin/sh
#
# Copyright (c) 2004, 2009, Oracle and/or its affiliates. All rights reserved. 

# Build: 110804

DIRNAME=`dirname $0`

PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin
export PATH
exec $DIRNAME/exectask "$@" 
