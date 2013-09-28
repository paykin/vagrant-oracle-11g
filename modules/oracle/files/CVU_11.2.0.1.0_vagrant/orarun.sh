#!/bin/sh
#
# $Header: oui/prov/fixup/linux/orarun.sh /main/2 2009/06/24 04:27:33 sandgoya Exp $
#
# orarun.sh
#
# Copyright (c) 2005, 2009, Oracle and/or its affiliates. All rights reserved. 
#
#    NAME
#      orarun.sh - <one-line expansion of the name>
#
#    DESCRIPTION
#      <short description of component this file declares/defines>
#
#    NOTES
#      <other useful comments, qualifications, etc.>
#
#    MODIFIED   (MM/DD/YY)
#     vkamthan 05/12/09 - Bug Fix 8445702
#     vkamthan 04/13/09 - Bug Fix 8304796
#     vkamthan 12/15/08 - Bug Fix 7378320
#     skhekale 07/22/08 - Added shell limit fixup 
#     kkhanuja 07/06/06 - Added fixup to start nscd 
#     vsubrahm 03/28/06 - XbranchMerge vsubrahm_orarun_rpm_changes from 
#                         st_empp_10.2.0.1.0 
#     vsubrahm 02/23/06 - Adding checks before changing values 
#     njerath  02/06/06 - XbranchMerge njerath_misc_prereq_fixup_2 from main 
#     vsubrahm 02/02/06 - XbranchMerge vsubrahm_orarun_target from main 
#     vsubrahm 01/27/06 -  Fix the variable name for shell limits
#     njerath  12/04/05 - Changed constant names for base urls
#     njerath  11/27/05 - Added more fixups
#       vsubrahm 10/22/05 - 
#   
#    vsubrahm    10/22/05  - changing add user to group to includ groups user belongs to
#    vsubrahm    10/18/05  -  Adding fixup for mount parameters
#    vsagar      10/26/05  - 
#    vsubrahm    10/22/05 -    
#    vsubrahm    10/22/05  - changing add user to group to includ groups user belongs to
#    vsubrahm    10/18/05  -  Adding fixup for mount parameters
#    gmanglik    09/02/05  - add fix up for central inventory permissions 
#    vsburahm    08/26/05 -  Added fixup for adding user to groups
#    bpaliwal    08/25/05 -  use tee to output the progress / errors an log
#    vsubrahm    07/26/05 - Changes for Shell limits 
#    suravind    07/15/05 - suravind_updation_prereq_xml
#    vsubrahm    07/06/05 - Creation
#
#set -x
#Assign command line params 1 and 2 to response file and enable file

# Helper function to verify an address is associated with an interface
resp_file=$1
enable_file=$2
log_file=$3
#If both files are not specified look for the files in the current directory
if [ $# -eq 0 ]
then
  resp_file=`pwd`/orarun.response
  enable_file=`pwd`/orarun.enable
  log_file=`pwd`
elif [ $# -eq 1 ]
then
 enable_file=`pwd`/orarun.enable
 log_file=`pwd`
elif [ $# -eq 2 ]
then
 log_file="`pwd`"
fi

EXIT_CODE=0

#if the user does not have write permission on given directory, then create logs in /tmp directory
if ! echo "This is the log file for orarun script" >> $log_file/orarun.log
then
   log_file=`/tmp`
  echo "This is the log file for orarun script" >> $log_file/orarun.log
fi
echo "Timestamp: `date +%m%d%y%H%M%S`" >> $log_file/orarun.log

echo "Response file being used is :$resp_file" |tee -a $log_file/orarun.log

echo "Enable file being used is :$enable_file" | tee -a $log_file/orarun.log

echo "Log file location: $log_file/orarun.log"

 if [ ! -f $resp_file -o ! -f $enable_file ]
 then
         echo "Nothing to fix!!" | tee -a $log_file/orarun.log
         exit 0
 fi
 if [ ! -r $resp_file -o ! -r $enable_file ]
 then
         echo "One or both of the input files are not readable" |tee -a $log_file/orarun.log
         exit 1
 fi

#check if user has given absolute/relative path or just filename
first_char=`expr "$resp_file" : '\(.\)'`
if [ "$first_char" != "/" -a "$first_char" != "." ]
then
 . ./$resp_file
else
. $resp_file
fi

first_char=`expr "$enable_file" : '\(.\)'`
if [ "$first_char" != "/" -a "$first_char" != "." ]
then
 . ./$enable_file
else
. $enable_file
fi

check_ifconfig()
{
    ADDR="$1"
    IFCONFIG="`/sbin/ifconfig 2>/dev/null`"
    if [ "$?" != 0 ]
    then
        echo "Unable to run ifconfig"
        return 1
    fi

    case "$IFCONFIG" in
    *addr:"$ADDR"*)
        return 0
        ;;
    *)
        ;;
    esac

    echo "IP address \"$ADDR\" is not associated with an interface"
    return 1
}

install_ocfs_packages()
{
   METHOD_INSTALL_OCFS="$1"
#install of ocfs
if [ "`echo $METHOD_INSTALL_OCFS | tr A-Z a-z`" == "true" ]
then
   METHOD_OCFS_RPMS="$2"
   METHOD_RPM_BASE_URL_OCFS="$3"
   METHOD_PROCESSOR="$4"
   for ocfs_rpm in $METHOD_OCFS_RPMS
   do
     full_ocfs_rpm=`echo $ocfs_rpm "$METHOD_PROCESSOR.rpm" | awk '$1 !~ /rpm$/ { print $1 "." $2 }'`
     if  test -z "$full_ocfs_rpm"
     then
        full_ocfs_rpm=$ocfs_rpm
     fi
     fullpath=${METHOD_RPM_BASE_URL_OCFS}/$full_ocfs_rpm
     if test -n "$fullpath" 
     then
        protocol="`expr $fullpath : '\(....\)'`"
        if [ "$protocol" == "http" ]
        then
            if test -n "$HTTP_PROXY" && test -n "$HTTP_PORT"
            then
               rpm -Uvh $fullpath --httpproxy $HTTP_PROXY --httpport $HTTP_PORT
               returncode=$?
            else    
             echo "Errors occured during installation of package:$ocfs_rpm. Either HTTP Proxy or HTTP Port not specified." | tee -a $log_file/orarun.log
            fi
        elif [ "$protocol" == "ftp:" ]
        then
           if test -n "$FTP_PROXY" && test -n "$FTP_PORT"
           then
              rpm -Uvh $fullpath --ftpproxy $FTP_PROXY --ftpport $FTP_PORT
              returncode=$?
           else
              echo "Errors occured during installation of package:$ocfs_rpm. Either FTP Proxy or FTP Port not specified." | tee -a $log_file/orarun.log
           fi
        else
            rpm -Uvh $fullpath
            returncode=$?
        fi
        if [ $? -ne 0 ]
        then
          echo "Errors occured during installation of package:$ocfs_rpm." | tee -a $log_file/orarun.log
        fi
     fi
   done 
fi
}

if [ "`echo $SET_KERNEL_PARAMETERS | tr A-Z a-z`" == "true" ]
then
    echo "Setting Kernel Parameters..." | tee -a $log_file/orarun.log
    if [ ! -d /proc/sys/kernel ]; then
        echo "No sysctl kernel interface - cannot set kernel parameters." |tee -a $log_file/orarun.log
    fi
   
    if [ -n "$KERNEL_PARAMETERS_FILE" ]
    then
   
       if [ -r $KERNEL_PARAMETERS_FILE ]
       then
         $SYSCTL_LOC -p "$KERNEL_PARAMETERS_FILE"
         if [ $? -ne 0 ]
         then
            echo "Could not set the Kernel parameters." |tee -a $log_file/orarun.log
         fi
       else
         echo "File $KERNEL_PARAMETERS_FILE is not found/not readable" |tee -a $log_file/orarun.log
       fi
    
    else
        #delete the line containing parameter from conf file and replace with new value
	# Set shared memory parameters:
        #SHMMAX, SHMMNI, SHMALL
       if [ -n "$SHMMAX" ]
       then
          #extract the line which contains shmmax in the /etc/sysctl.conf
          if grep "^kernel.shmmax[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
              line=`sed -ne '/^kernel.shmmax/p' /etc/sysctl.conf`
              #remove extra spaces in the line
              line=`echo $line | sed 's/ //g'` 
              #Now extract the value of shmmax
              fileValue=`echo $line | cut -d= -f2`
              echo "shmmax in response file:$SHMMAX" >> $log_file/orarun.log
              echo "shmmax in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
              if [ ! $SHMMAX ] || [ ! $fileValue ]
              then
                 echo "Could not find SHMMAX from /etc/sysctl.conf or response file.";
                 EXIT_CODE=1;
              else
                if [ $SHMMAX -gt $fileValue ]
                then
                  sed -ie '/^kernel.shmmax/d' /etc/sysctl.conf
                  echo "kernel.shmmax = $SHMMAX" >> /etc/sysctl.conf
                else
                   echo "The value for shmmax in response file is not greater than value for shmmax in /etc/sysctl.conf file. Hence not changing it." |tee -a $log_file/orarun.log
                fi
              fi
          else
             echo "kernel.shmmax = $SHMMAX" >> /etc/sysctl.conf
          fi
          #current value of shmmax - value in /proc/sys/kernel/shmmax
          cur_shmmax=`/sbin/sysctl -n kernel.shmmax`
          #remove the extra spaces in the line.
          cur_shmmax=`echo $cur_shmmax | sed 's/ //g'`
          echo "shmmax for current session:$cur_shmmax" >> $log_file/orarun.log
          if [ $SHMMAX -gt $cur_shmmax ]
          then
              if  ! $SYSCTL_LOC -w kernel.shmmax="$SHMMAX"
              then
                echo "$SYSCTL_LOC failed to set shmmax" |tee -a $log_file/orarun.log
              fi
           else
                 echo "The value for shmmax in response file is not greater than value of shmmax for current session. Hence not changing it." |tee -a $log_file/orarun.log
           fi
       fi

	if [ -n "$SHMMNI" ]
        then
          if grep "^kernel.shmmni[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
             #extract the line which contains shmmni in the /etc/sysctl.conf
             line=`sed -ne '/^kernel.shmmni/p' /etc/sysctl.conf`
             #remove extra spaces in the line
             line=`echo $line | sed 's/ //g'` 
             #Now extract the value of shmmni
             fileValue=`echo $line | cut -d= -f2`
             echo "shmmni in response file:$SHMMNI" >> $log_file/orarun.log
             echo "shmmni in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
             if [ ! $SHMMNI ] || [ ! $fileValue ]
             then
                echo "Could not find SHMMNI from /etc/sysctl.conf or response file.";
                EXIT_CODE=1;
             else
	        if [ $SHMMNI -gt $fileValue ]
		then
                  sed -ie '/^kernel.shmmni/d' /etc/sysctl.conf
                  echo "kernel.shmmni = $SHMMNI" >> /etc/sysctl.conf
                else
                  echo "The value for shmmni in response file is not greater than value for shmmni in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
                fi
	     fi
           else
             echo "kernel.shmmni = $SHMMNI" >> /etc/sysctl.conf
          fi
       

          #current value of shmmni - value in /proc/sys/kernel/shmmni
          cur_shmmni=`/sbin/sysctl -n kernel.shmmni`
          #remove the extra spaces in the line.
          cur_shmmni=`echo $cur_shmmni | sed 's/ //g'`
          echo "shmmni for current session:$cur_shmmni" >> $log_file/orarun.log
          if [ $SHMMNI -gt $cur_shmmni ]
          then
              if  ! $SYSCTL_LOC -w kernel.shmmni="$SHMMNI"
              then
                  echo "$SYSCTL_LOC failed to set shmmni" |tee -a $log_file/orarun.log
               fi
           else
              echo "The value for shmmni in response file is not greater than value of shmmni for current session. Hence not changing it." |tee -a $log_file/orarun.log
           
           fi
        fi
	
	if [ -n "$SHMALL" ]
        then
          if grep "^kernel.shmall[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
             #extract the line which contains shmall in the /etc/sysctl.conf
             line=`sed -ne '/^kernel.shmall/p' /etc/sysctl.conf`
             #remove extra spaces in the line
             line=`echo $line | sed 's/ //g'` 
             #Now extract the value of shmall
             fileValue=`echo $line | cut -d= -f2`
             echo "shmall in response file:$SHMALL" >> $log_file/orarun.log
             echo "shmall in /etc/sysctl.conf:$fileValue" >> $log_file/orarun.log
             if [ ! $SHMALL ] || [ ! $fileValue ]
             then
                echo "Could not find SHMALL from /etc/sysctl.conf or response file.";
                EXIT_CODE=1;
             else 
              if [ $SHMALL -gt $fileValue ]
              then
                sed -ie '/^kernel.shmall/d' /etc/sysctl.conf
                echo "kernel.shmall = $SHMALL" >> /etc/sysctl.conf
              else
                echo "The value for shmall in response file is not greater than value for shmall in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
              fi
             fi
          else
             echo "kernel.shmall = $SHMALL" >> /etc/sysctl.conf
          fi
          #current value of shmmni - value in /proc/sys/kernel/shmall
          cur_shmall=`/sbin/sysctl -n kernel.shmall`
          #remove the extra spaces in the line.
          cur_shmall=`echo $cur_shmall | sed 's/ //g'`
          echo "shmall for current session:$cur_shmall" >> $log_file/orarun.log
          if [ $SHMALL -gt $cur_shmall ]
          then
               if  ! $SYSCTL_LOC -w kernel.shmall="$SHMALL"
               then
                  echo "$SYSCTL_LOC failed to set shmall" |tee -a $log_file/orarun.log
               fi
           else
              echo "The value for shmall in response file is not greater than value of shmall for current session. Hence not changing it." | tee -a $log_file/orarun.log
           fi
	fi

	# Set the semaphore parameters:
        # SEMMSL, SEMMNS, SEMOPM, SEMMNI
        #Check if any of semaphores need to be set
	#All must be set at the same time, so first get those which need not be set
	#from /proc/sys/kernel/sem
	if [ -n "$SEMMSL" -o -n "$SEMMNS" -o -n "$SEMOPM" -o -n "$SEMMNI" ]
        then
          #change values for current session in /proc/sys/kernel/sem only if specified values are greater.
          cur_semmsl=`awk '{print $1}' /proc/sys/kernel/sem`
          cur_semmns=`awk '{print $2}' /proc/sys/kernel/sem`
          cur_semopm=`awk '{print $3}' /proc/sys/kernel/sem`
          cur_semmni=`awk '{print $4}' /proc/sys/kernel/sem`
          line=`sed -ne '/^kernel.sem/p' /etc/sysctl.conf`
          fileValue=`echo $line | cut -d= -f2`
          file_semmsl=`echo $fileValue | awk '{print $1}'`
          file_semmns=`echo $fileValue | awk '{print $2}'`
          file_semopm=`echo $fileValue | awk '{print $3}'`
          file_semmni=`echo $fileValue | awk '{print $4}'` 
          flag_cur="false"
          flag_file="false"

          if [ ! -z "$SEMMSL" ]
          then
              echo "semmsl in response file:$SEMMSL" >> $log_file/orarun.log
              echo "semmsl for current session:$cur_semmsl" >> $log_file/orarun.log
              if [ $SEMMSL -gt $cur_semmsl ]
              then
                  cur_semmsl=$SEMMSL
                  flag_cur="true"
              else
                echo "The value for semmsl in response file is not greater than value of semmsl for current session. Hence not changing it." | tee -a $log_file/orarun.log
              fi
              echo "semmsl in /etc/sysctl.conf:$file_semmsl" >>$log_file/orarun.log
              if test -z "$file_semmsl" || test $SEMMSL -gt $file_semmsl
              then
                file_semmsl=$SEMMSL
                flag_file="true"
              else
                echo "The value for semmsl in response file is not greater than value for semmsl in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
              fi
          fi

          if [ ! -z "$SEMMNS" ]
          then
            echo "semmns in response file:$SEMMNS" >> $log_file/orarun.log
            echo "semmns for current session:$cur_semmns" >> $log_file/orarun.log      
            if [ $SEMMNS -gt $cur_semmns ]
            then
               cur_semmns=$SEMMNS
               flag_cur="true"
             else
               echo "The value for semmns in response file is not greater than value of semmns for current session. Hence not changing it." | tee -a $log_file/orarun.log
            fi
               echo "semmns in /etc/sysctl.conf:$file_semmns" >>$log_file/orarun.log
            if test -z "$file_semmns" || test $SEMMNS -gt $file_semmns
            then
               file_semmns=$SEMMNS
               flag_file="true"
            else
                echo "The value for semmns in response file is not greater than value for semmns in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
            fi
          fi

          if [ ! -z "$SEMOPM" ]
          then
           echo "semopm in response file:$SEMOPM" >> $log_file/orarun.log
           echo "semopm for current session:$cur_semopm" >> $log_file/orarun.log
            if [ $SEMOPM -gt $cur_semopm ]
            then
               cur_semopm=$SEMOPM
               flag_cur="true"
             else
               echo "The value for semopm in response file is not greater than value of semopm for current session. Hence not changing it." | tee -a $log_file/orarun.log
            fi
            echo "semopm in /etc/sysctl.conf:$file_semopm" >>$log_file/orarun.log
            if test -z "$file_semopm" || test $SEMOPM -gt $file_semopm
            then
               file_semopm=$SEMOPM
               flag_file="true"
             else
               echo "The value for semopm in response file is not greater than value for semopm in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
             fi
          fi

	  if [ ! -z "$SEMMNI" ]
          then
             echo "semmni in response file:$SEMMNI" >> $log_file/orarun.log
             echo "semmni for current session:$cur_semmni" >> $log_file/orarun.log
            if [ $SEMMNI -gt $cur_semmni ]
            then
               cur_semmni=$SEMMNI
               flag_cur="true"
             else
               echo "The value for semmni in response file is not greater than value of semmni for current session. Hence not changing it." | tee -a $log_file/orarun.log
            fi
              echo "semmni in /etc/sysctl.conf:$file_semmni" >>$log_file/orarun.log
            if test -z "$file_semmni" || test $SEMMNI -gt $file_semmni
            then
               file_semmni=$SEMMNI
               flag_file="true"
             else
               echo "The value for semmni in response file is not greater than value for semmni in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
             fi
          fi
          if [ $flag_cur == "true" ]
          then
             if ! $SYSCTL_LOC -w kernel.sem="$cur_semmsl $cur_semmns $cur_semopm $cur_semmni"
             then
               echo "$SYSCTL_LOC failed to set semaphore parameters" |tee -a $log_file/orarun.log
              fi
           fi
           #Now edit the /etc/sysctl.conf file  
          if [ $flag_file == "true" ]   
          then
             sed -ie '/^kernel.sem/d' /etc/sysctl.conf
             echo "kernel.sem = $file_semmsl $file_semmns $file_semopm $file_semmni" >> /etc/sysctl.conf
          fi  
       fi

	#FILE_MAX_KERNEL, IP_LOCAL_PORT_RANGE, RMEM_DEFAULT, WMEM_DEFAULT, RMEM_MAX, WMEM_MAX,AIO_MAX_SIZE
       if [ -n "$FILE_MAX_KERNEL" ]
       then
          if grep "^fs.file-max[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
              #extract the line which contains filemax in the /etc/sysctl.conf
              line=`sed -ne '/^fs.file-max/p' /etc/sysctl.conf`
              #remove extra spaces in the line
              line=`echo $line | sed 's/ //g'` 
              #Now extract the value of filemax
              fileValue=`echo $line | cut -d= -f2`
              echo "file-max in response file:$FILE_MAX_KERNEL" >> $log_file/orarun.log
              echo "file-max in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
              if [ ! $FILE_MAX_KERNEL ] || [ ! $fileValue ]
              then
                 echo "Could not find FILE_MAX_KERNEL from /etc/sysctl.conf or response file.";
                 EXIT_CODE=1;
              else
               if [ $FILE_MAX_KERNEL -gt $fileValue ]
               then
                 sed -ie '/^fs.file-max/d' /etc/sysctl.conf
                 echo "fs.file-max = $FILE_MAX_KERNEL" >> /etc/sysctl.conf
               else
                 echo "The value for file-max in response file is not greater than value for file-max in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
               fi
	      fi
          else
            echo "fs.file-max = $FILE_MAX_KERNEL" >> /etc/sysctl.conf
          fi
          #current value of filemax - value in /proc/sys/fs
          cur_filemax=`/sbin/sysctl -n fs.file-max`
          #remove the extra spaces in the line.
          cur_filemax=`echo $cur_filemax | sed 's/ //g'`
          echo "file-max for current session:$cur_filemax" >> $log_file/orarun.log
          if [ $FILE_MAX_KERNEL -gt $cur_filemax ]
          then
             if ! $SYSCTL_LOC -w fs.file-max="$FILE_MAX_KERNEL"
             then
                echo "$SYSCTL_LOC failed to set fs.file-max parameter" |tee -a $log_file/orarun.log
             fi
          else
             echo "The value for file-max in response file is not greater than value of file-max for current session. Hence not changing it." | tee -a $log_file/orarun.log
           fi
	fi

       if [ -n "$IP_LOCAL_PORT_RANGE" ]
       then
           #extract the line which contains ip_local_port_range in the /etc/sysctl.conf
           line=`sed -ne '/^net.ipv4.ip_local_port_range/p' /etc/sysctl.conf`
           #Now extract the value of ip_local_port_range
           fileValue=`echo $line | cut -d= -f2`
           file_atleast=`echo $fileValue | awk '{print $1}'`
           file_atmost=`echo $fileValue | awk '{print $2}'`

           #change values for current session in /proc/sys/net/ipv4 only if specified values are greater.
           cur_atleast=`awk '{print $1}' /proc/sys/net/ipv4/ip_local_port_range`
           cur_atmost=`awk '{print $2}' /proc/sys/net/ipv4/ip_local_port_range`

	   #find the user specified atleast and atmost values:
	   user_atleast=`echo $IP_LOCAL_PORT_RANGE | awk '{print $1}'`
	   user_atmost=`echo $IP_LOCAL_PORT_RANGE | awk '{print $2}'`
           echo "ip_local_port_range in response file:$IP_LOCAL_PORT_RANGE" >> $log_file/orarun.log
           echo "ip_local_port_range in /etc/sysctl.conf:$file_atleast $file_atmost" >> $log_file/orarun.log
	   flag="false"
           echo "ip_local_port_range for current session:$cur_atleast $cur_atmost" >> $log_file/orarun.log
	   # bug fix 8445702 
	   # removing the less than equals check for atleast
           if [ -n "$user_atleast" ]
	   then
	     file_atleast=$user_atleast
	     flag="true"
           fi

	   if test -z "$file_atmost" || test $user_atmost -gt $file_atmost
	   then
	      file_atmost=$user_atmost
	      flag="true"
           else
	      echo "The upper limit of ip_local_port range in reponse file is not greater than value in /etc/sysctl.conf, hence not changing it."|tee -a $log_file/orarun.log
	   fi
           if [ $flag == "true" ]
           then
             sed -ie '/^net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
             echo "net.ipv4.ip_local_port_range = $file_atleast $file_atmost" >> /etc/sysctl.conf
           fi

	   #Now change for current session if reqd.
           flag="false"
           # bug fix 8445702 
           # removing the less than equals check for atleast
           if [ -n "$user_atleast" ]
	   then
	       cur_atleast=$user_atleast
               flag="true"
	    fi

            if [ $user_atmost -gt $cur_atmost ]
            then
	      cur_atmost=$user_atmost
	      flag="true"
            else
	      echo "The upper limit of ip_local_port range in response file is not greater than value for current session, hence not changing it."|tee -a $log_file/orarun.log
            fi
	    if [ $flag == "true" ]
	    then
              if ! $SYSCTL_LOC -w net.ipv4.ip_local_port_range="$cur_atleast $cur_atmost"
              then
	       echo "$SYSCTL_LOC failed to set net.ipv4.ip_local_port_range parameter"  |tee -a $log_file/orarun.log
              fi
            fi 
       fi

       if [ -n "$RMEM_DEFAULT" ]
       then
          if grep "^net.core.rmem_default[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
              #extract the line which contains rmem_default in the /etc/sysctl.conf
              line=`sed -ne '/^[[:space:]]*net.core.rmem_default/p' /etc/sysctl.conf`
              #remove extra spaces in the line
              line=`echo $line | sed 's/ //g'` 
              #Now extract the value of rmem_default
              fileValue=`echo $line | cut -d= -f2`
              echo "rmem_default in response file:$RMEM_DEFAULT" >> $log_file/orarun.log
              echo "rmem_default in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
              if [ ! $RMEM_DEFAULT ] || [ ! $fileValue ]
              then
                 echo "Could not find RMEM_DEFAULT from /etc/sysctl.conf or response file.";
                 EXIT_CODE=1;
              else
                if [ $RMEM_DEFAULT -gt $fileValue ]
                then
                  sed -ie '/^net.core.rmem_default/d' /etc/sysctl.conf
                  echo "net.core.rmem_default = $RMEM_DEFAULT" >> /etc/sysctl.conf
                else
                  echo "The value for rmem_default in response file is not greater than value for rmem_default in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
                fi
	      fi
          else
              echo "net.core.rmem_default = $RMEM_DEFAULT" >> /etc/sysctl.conf
          fi
          #current value of rmem_default in /proc/sys/net/core
          cur_rmem_default=`/sbin/sysctl -n net.core.rmem_default`
          #remove the extra spaces in the line.
          cur_rmem_default=`echo $cur_rmem_default | sed 's/ //g'`
          echo "rmem_default for current session:$cur_rmem_default" >> $log_file/orarun.log
          if [ $RMEM_DEFAULT -gt $cur_rmem_default ]
          then
            if ! $SYSCTL_LOC -w net.core.rmem_default="$RMEM_DEFAULT"
            then
             echo "$SYCTL_LOC failed to set net.core.rmem_default parameter" |tee -a $log_file/orarun.log
            fi	
           else
             echo "The value for rmem_default in response file is not greater than value of rmem_default for current session. Hence not changing it." | tee -a $log_file/orarun.log
          fi
       fi
    
       if [ -n "$WMEM_DEFAULT" ]
       then
          if grep "^net.core.wmem_default[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
              #extract the line which contains wmem_default in the /etc/sysctl.conf
              line=`sed -ne '/^net.core.wmem_default/p' /etc/sysctl.conf`
              #remove extra spaces in the line
              line=`echo $line | sed 's/ //g'` 
              #Now extract the value of wmem_default
              fileValue=`echo $line | cut -d= -f2`
              echo "wmem_default in response file:$WMEM_DEFAULT" >> $log_file/orarun.log
              echo "wmem_default in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
              if [ ! $WMEM_DEFAULT ] || [ ! $fileValue ]
              then
                 echo "Could not find WMEM_DEFAULT from /etc/sysctl.conf or response file.";
                 EXIT_CODE=1;
              else
               if [ $WMEM_DEFAULT -gt $fileValue ]
               then
                  sed -ie '/^net.core.wmem_default/d' /etc/sysctl.conf
                  echo "net.core.wmem_default = $WMEM_DEFAULT" >> /etc/sysctl.conf
               else
                  echo "The value for wmem_default in response file is not greater than value for wmem_default in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
               fi
	      fi
           else
             echo "net.core.wmem_default = $WMEM_DEFAULT" >> /etc/sysctl.conf
           fi
	  #current value of rmem_default in /proc/sys/net/core
          cur_wmem_default=`/sbin/sysctl -n net.core.wmem_default`
          #remove the extra spaces in the line.
          cur_wmem_default=`echo $cur_wmem_default | sed 's/ //g'`
            echo "wmem_default for current session:$cur_wmem_default" >> $log_file/orarun.log
          if [ $WMEM_DEFAULT -gt $cur_wmem_default ]
          then
            if ! $SYSCTL_LOC -w net.core.wmem_default="$WMEM_DEFAULT"
             then
               echo "$SYSCTL_LOC failed to set net.core.wmem_default parameter" >> $log_file/orarun.log
            fi	
           else
               echo "The value for wmem_default in response file is not greater than value of wmem_default for current session. Hence not changing it." | tee -a $log_file/orarun.log
          fi 
	fi	

       if [ -n "$RMEM_MAX" ]
       then
          if grep "^net.core.rmem_max[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
             #extract the line which contains rmem_max in the /etc/sysctl.conf
             line=`sed -ne '/^net.core.rmem_max/p' /etc/sysctl.conf`
             #remove extra spaces in the line
             line=`echo $line | sed 's/ //g'` 
             #Now extract the value of rmem_max
             fileValue=`echo $line | cut -d= -f2`
             echo "rmem_max in response file:$RMEM_MAX" >> $log_file/orarun.log
             echo "rmem_max in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
             if [ ! $RMEM_MAX ] || [ ! $fileValue ]
             then
                 echo "Could not find RMEM_MAX from /etc/sysctl.conf or response file.";
                 EXIT_CODE=1;
             else
               if [ $RMEM_MAX -gt $fileValue ]
               then
                 sed -ie '/^net.core.rmem_max/d' /etc/sysctl.conf
                 echo "net.core.rmem_max = $RMEM_MAX" >> /etc/sysctl.conf
               else
                 echo "The value for rmem_max in response file is not greater than value for rmem_max in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
	       fi
	     fi
          else
            echo "net.core.rmem_max = $RMEM_MAX" >> /etc/sysctl.conf
          fi

 	  #current value of rmem_max in /proc/sys/net/core
          cur_rmem_max=`/sbin/sysctl -n net.core.rmem_max`
          #remove the extra spaces in the line.
          cur_rmem_max=`echo $cur_rmem_max | sed 's/ //g'`
          echo "rmem_max for current session:$cur_rmem_max" >> $log_file/orarun.log
          if [ $RMEM_MAX -gt $cur_rmem_max ]
          then
           if ! $SYSCTL_LOC -w net.core.rmem_max="$RMEM_MAX"
           then
              echo "$SYSCTL_LOC failed to set net.core.rmem_max parameter" |tee -a $log_file/orarun.log
           fi
           else
              echo "The value for rmem_max in response file is not greater than value of rmem_max for current session. Hence not changing it." | tee -a $log_file/orarun.log
           fi
         
        fi

	if [ -n "$WMEM_MAX" ]
        then
         if grep "^net.core.wmem_max[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
         then
            #extract the line which contains wmem_max in the /etc/sysctl.conf
            line=`sed -ne '/^net.core.wmem_max/p' /etc/sysctl.conf`
            #remove extra spaces in the line
            line=`echo $line | sed 's/ //g'` 
            #Now extract the value of wmem_max
            fileValue=`echo $line | cut -d= -f2`
            echo "wmem_max in response file:$WMEM_MAX" >> $log_file/orarun.log
            echo "wmem_max in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
            if [ ! $WMEM_MAX ] || [ ! $fileValue ]
            then
                 echo "Could not find WMEM_MAX from /etc/sysctl.conf or response file.";
                 EXIT_CODE=1;
            else 
              if [ $WMEM_MAX -gt $fileValue ]
              then
                sed -ie '/^net.core.wmem_max/d' /etc/sysctl.conf
                echo "net.core.wmem_max = $WMEM_MAX" >> /etc/sysctl.conf
              else
                echo "The value for wmem_max in response file is not greater than value for wmem_max in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
	      fi
	    fi
          else
            echo "net.core.wmem_max = $WMEM_MAX" >> /etc/sysctl.conf
          fi
          #current value of wmem_max in /proc/sys/net/core
          cur_wmem_max=`/sbin/sysctl -n net.core.wmem_max`
          #remove the extra spaces in the line.
          cur_wmem_max=`echo $cur_wmem_max | sed 's/ //g'`
          echo "wmem_max for current session:$cur_wmem_max" >> $log_file/orarun.log
          if [ $WMEM_MAX -gt $cur_wmem_max ]
          then
             if ! $SYSCTL_LOC -w net.core.wmem_max="$WMEM_MAX"
             then
                echo "$SYSCTL_LOC failed to set net.core.wmem_max parameter" |tee -a $log_file/orarun.log
             fi
          else
             echo "The value for wmem_max in response file is not greater than value of wmem_max for current session. Hence not changing it." | tee -a $log_file/orarun.log
           fi
	fi

	if [ -n "$AIO_MAX_SIZE" ]
        then
          if grep "^fs.aio-max-size[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
             #extract the line which contains aio_max_size in the /etc/sysctl.conf
             line=`sed -ne '/^fs.aio-max-size/p' /etc/sysctl.conf`
             #remove extra spaces in the line
             line=`echo $line | sed 's/ //g'` 
             #Now extract the value of aio_max_size
             fileValue=`echo $line | cut -d= -f2`
             echo "aio-max-size in response file:$AIO_MAX_SIZE" >> $log_file/orarun.log
             echo "aio-max-size in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
	     if [ ! $AIO_MAX_SIZE ] || [ ! $fileValue ]
              then
                 echo "Could not find AIO_MAX_SIZE from /etc/sysctl.conf or response file.";
                 EXIT_CODE=1;
             else
              if [ $AIO_MAX_SIZE -gt $fileValue ]
              then
                 sed -ie '/^fs.aio-max-size/d' /etc/sysctl.conf
                 echo "fs.aio-max-size = $AIO_MAX_SIZE" >> /etc/sysctl.conf
              else
                 echo "The value for aio-max-size in response file is not greater than value for aio-max-size in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
              fi
	     fi
          else
            echo "fs.aio-max-size = $AIO_MAX_SIZE" >> /etc/sysctl.conf
          fi
          #current value of aio_max_size in /proc/sys/fs
          cur_aio_max_size=`/sbin/sysctl -n fs.aio-max-size`
          #remove the extra spaces in the line.
          cur_aio_max_size=`echo $cur_aio_max_size | sed 's/ //g'`
          echo "aio-max-size for current session:$cur_aio_max_size" >> $log_file/orarun.log
          if [ $AIO_MAX_SIZE -gt $cur_aio_max_size ]
          then
        	if ! $SYSCTL_LOC -w fs.aio-max-size="$AIO_MAX_SIZE"
                then
                 echo "$SYSCTL_LOC failed to set fs.aio-max-size parameter" |tee -a $log_file/orarun.log
               fi
          else
           echo "The value for aio-max-size in response file is not greater than value of aio-max-size for current session. Hence not changing it." | tee -a $log_file/orarun.log
          fi
           
	fi

	if [ -n "$AIO_MAX_NR" ]
        then
          if grep "^fs.aio-max-nr[[:space:]]*=[[:space:]]*[0-9]\+" /etc/sysctl.conf
          then
             #extract the line which contains aio-max-nr in the /etc/sysctl.conf
             line=`sed -ne '/^fs.aio-max-nr/p' /etc/sysctl.conf`
             #remove extra spaces in the line
             line=`echo $line | sed 's/ //g'` 
             #Now extract the value of aio-max-nr
             fileValue=`echo $line | cut -d= -f2`
             echo "aio-max-nr in response file:$AIO_MAX_NR" >> $log_file/orarun.log
             echo "aio-max-nr in /etc/sysctl.conf:$fileValue" >>$log_file/orarun.log
             if [ ! $AIO_MAX_NR ] || [ ! $fileValue ]
              then
                 echo "Could not find AIO_MAX_NR from /etc/sysctl.conf or response file.";
                 EXIT_CODE=1;
             else 
               if [ $AIO_MAX_NR -gt $fileValue ]
               then
                  sed -ie '/^fs.aio-max-nr/d' /etc/sysctl.conf
                  echo "fs.aio-max-nr = $AIO_MAX_NR" >> /etc/sysctl.conf
               else
                  echo "The value for aio-max-nr in response file is not greater than value for aio-max-nr in /etc/sysctl.conf file. Hence not changing it." | tee -a $log_file/orarun.log
               fi
	     fi
          else
            echo "fs.aio-max-nr = $AIO_MAX_NR" >> /etc/sysctl.conf
          fi
          #current value of aio-max-nr in /proc/sys/fs
          cur_aio_max_nr=`/sbin/sysctl -n fs.aio-max-nr`
          #remove the extra spaces in the line.
          cur_aio_max_nr=`echo $cur_aio_max_nr | sed 's/ //g'`
          echo "aio-max-nr for current session:$cur_aio_max_nr" >> $log_file/orarun.log
          if [ $AIO_MAX_NR -gt $cur_aio_max_nr ]
          then
        	if ! $SYSCTL_LOC -w fs.aio-max-nr="$AIO_MAX_NR"
                then
                 echo "$SYSCTL_LOC failed to set fs.aio-max-nr parameter" |tee -a $log_file/orarun.log
               fi
          else
           echo "The value for aio-max-nr in response file is not greater than value of aio-max-nr for current session. Hence not changing it." | tee -a $log_file/orarun.log
          fi
           
	fi
   fi
fi

#Create groups if they do not exist
if [ "`echo $CREATE_GROUPS | tr A-Z a-z`" == "true" ]
then
  echo " Creating groups ..." >> $log_file/orarun.log
   for group in $GROUP  
   do
      grep -qs ^$group: /etc/group || /usr/sbin/groupadd -r $group
     if [ $? -ne 0 ]
     then
      echo "An error occured while creating the group: $group" |tee -a $log_file/orarun.log
     
     fi
   done
fi


#Create the users if they do not exist
if [ "`echo $CREATE_USERS | tr A-Z a-z`" == "true" ]
then
   echo "Creating Users ...." >> $log_file/orarun.log
   for user_info in $USERS
   do        
       user=`echo $user_info | cut -d: -f1`
       login_dir=`echo $user_info | cut -d: -f2`
       login_shell=`echo $user_info | cut -d: -f3`
       echo "Creating $user with login directory $login_dir and login shell $login_shell " | tee -a $log_file/orarun.log
       id  $user || /usr/sbin/useradd -d $login_dir -s $login_shell -m -r $user
       if [ $? -ne 0 ]
       then
          echo "An error occured while creating the user $user " |tee -a $log_file/orarun.log
       fi
  done
fi

#Start the nscd daemon if not running
if [ "`echo $START_NSCD | tr A-Z a-z`" == "true" ]
then
   echo "Starting ncsd...." >> $log_file/orarun.log
   rm -rf awktemp
   /sbin/service nscd status > awktemp 2>&1

   VAR=`grep "running"  awktemp | awk -F. '{ print $1 }'`

   if [ "$VAR" == "" ]
   then
      VAR1=`grep "unrecognized"  awktemp | awk -F: '{ print $1 }'`
      if [ "$VAR1" == "" ]
      then
         /sbin/service nscd start
      else
         echo "nscd: unrecognized service " | tee -a $log_file/orarun.log
      fi
   fi
fi

#Set shell limits
if [ "`echo $SET_SHELL_LIMITS | tr A-Z a-z`" == "true" ]
then
 echo "Setting Shell limits ..." >> $log_file/orarun.log
  if [ ! -f /etc/security/limits.conf ]
  then
     echo "/etc/security/limits.conf file not found. Unable to set shell limits" | tee -a $log_file/orarun.log
  elif ! id $INSTALL_USER
  then
     echo "$INSTALL_USER does not exist on the system" | tee -a $log_file/orarun.log  
   else
      if [ -n "$MAX_PROCESSES_HARDLIMIT" ]
      then
	#get current value from /etc/security/limits.conf
        #If entry is found in the file

        echo "Max processes hard limit in response file:$MAX_PROCESSES_HARDLIMIT" >> $log_file/orarun.log
        if grep "^$INSTALL_USER[[:space:]]\+hard[[:space:]]\+nproc[[:space:]]\+[0-9]\+" /etc/security/limits.conf
        then
     	    val=`grep "^$INSTALL_USER" /etc/security/limits.conf | awk '/hard[[:space:]]*nproc/ {print $4}'`
            echo "Max processes hard limit in /etc/security/limits.conf file: $val" >> $log_file/orarun.log
            if [ ! $MAX_PROCESSES_HARDLIMIT ] || [ ! $val ]
            then
               echo "Could not find MAX_PROCESSES_HARDLIMIT from /etc/security/limits.conf or response file.";
               EXIT_CODE=1;
            else 
   	      if [ $MAX_PROCESSES_HARDLIMIT -gt $val ]
              then
	       #delete the line and insert the new line
	         grep -v "^$INSTALL_USER[[:space:]]\+hard[[:space:]]\+nproc[[:space:]]\+[0-9]\+" /etc/security/limits.conf > /tmp/limits.conf
	         cp /tmp/limits.conf /etc/security/limits.conf
                 echo "$INSTALL_USER hard nproc $MAX_PROCESSES_HARDLIMIT" >> /etc/security/limits.conf
              else
                 echo "Value of MAX PROCESSES HARDLIMIT in response file is not greater than value in/etc/security/limits.conf. Hence not changing it." | tee -a $log_file/orarun.log
              fi
	    fi
        else
          echo "$INSTALL_USER hard nproc $MAX_PROCESSES_HARDLIMIT" >> /etc/security/limits.conf
        fi 
     fi      
      
     if [ -n "$MAX_PROCESSES_SOFTLIMIT" ]
     then
        #if line is present then
	#get current value from /etc/security/limits.conf
        echo "Max processes softlimit in response file: $MAX_PROCESSES_SOFTLIMIT" >>$log_file/orarun.log
        if grep "^$INSTALL_USER[[:space:]]\+soft[[:space:]]\+nproc[[:space:]]\+[0-9]\+" /etc/security/limits.conf
        then
             val=`grep "^$INSTALL_USER" /etc/security/limits.conf | awk '/soft[[:space:]]*nproc/ {print $4}'`
             echo "Max processes soft limit in /etc/security/limits.conf: $val" >> $log_file/orarun.log
             if [ ! $MAX_PROCESSES_SOFTLIMIT ] || [ ! $val ]
             then
                echo "Could not find MAX_PROCESSES_SOFTLIMIT from /etc/security/limits.conf or response file.";
                EXIT_CODE=1;
            else 
              if [ $MAX_PROCESSES_SOFTLIMIT -gt $val ]
 	      then
        	 #delete the line and insert the new line
	         grep -v "^$INSTALL_USER[[:space:]]\+soft[[:space:]]\+nproc[[:space:]]\+[0-9]\+" /etc/security/limits.conf > /tmp/limits.conf
	         cp /tmp/limits.conf /etc/security/limits.conf
                 echo "$INSTALL_USER soft nproc $MAX_PROCESSES_SOFTLIMIT" >> /etc/security/limits.conf
               else
	          echo "Value of MAX PROCESSES SOFTLIMIT in response file is not greater than value in /etc/security/limits.conf. Hence not changing it." | tee -a $log_file/orarun.log
               fi  
	     fi
        else
          echo "$INSTALL_USER soft nproc $MAX_PROCESSES_SOFTLIMIT" >> /etc/security/limits.conf
        fi
     fi

     if [ -n "$MAX_STACK_SOFTLIMIT" ]
     then
       #if line is present then
       #get current value from /etc/security/limits.conf
        echo "Stack limit in response file:$MAX_STACK_SOFTLIMIT" >> $log_file/orarun.log
        if grep "^$INSTALL_USER[[:space:]]\+soft[[:space:]]\+stack[[:space:]]\+[0-9]\+" /etc/security/limits.conf
        then
             val=`grep "^$INSTALL_USER" /etc/security/limits.conf | awk '/soft[[:space:]]*stack/ {print $4}'`
             echo "Stack limit in /etc/security/limits.conf: $val" >> $log_file/orarun.log
                #delete the line and insert the new line
                grep -v "$INSTALL_USER[[:space:]]\+soft[[:space:]]\+stack[[:space:]]\+[0-9]\+" /etc/security/limits.conf > /tmp/limits.conf
                cp /tmp/limits.conf /etc/security/limits.conf
                echo "$INSTALL_USER soft stack $MAX_STACK_SOFTLIMIT" >> /etc/security/limits.conf
         else
            echo "$INSTALL_USER soft stack $MAX_STACK_SOFTLIMIT" >> /etc/security/limits.conf
         fi
     fi


     if [ -n "$FILE_OPEN_MAX_HARDLIMIT" ]
     then
       #if line is present then
       #get current value from /etc/security/limits.conf
        echo "File open max hard limit in response file:$FILE_OPEN_MAX_HARDLIMIT" >> $log_file/orarun.log
        if grep "^$INSTALL_USER[[:space:]]\+hard[[:space:]]\+nofile[[:space:]]\+[0-9]\+" /etc/security/limits.conf
        then
             val=`grep "^$INSTALL_USER" /etc/security/limits.conf | awk '/hard[[:space:]]*nofile/ {print $4}'`
             echo "File open max hard limit in /etc/security/limits.conf: $val" >> $log_file/orarun.log
             if [ ! $FILE_OPEN_MAX_HARDLIMIT ] || [ ! $val ]
              then
                 echo "Could not find FILE_OPEN_MAX_HARDLIMIT from /etc/security/limits.conf or response file.";
                 EXIT_CODE=1;
             else 
               if [ $FILE_OPEN_MAX_HARDLIMIT -gt $val ]
 	       then
                 #delete the line and insert the new line
	         grep -v "$INSTALL_USER[[:space:]]\+hard[[:space:]]\+nofile[[:space:]]\+[0-9]\+" /etc/security/limits.conf > /tmp/limits.conf
                 cp /tmp/limits.conf /etc/security/limits.conf
                 echo "$INSTALL_USER hard nofile $FILE_OPEN_MAX_HARDLIMIT" >> /etc/security/limits.conf
                else
       	         echo "Value of FILE OPEN MAX HARDLIMIT in response file is not greater than value in /etc/security/limits.conf.Hence not changing it."  | tee -a $log_file/orarun.log 
                fi
             fi
         else
            echo "$INSTALL_USER hard nofile $FILE_OPEN_MAX_HARDLIMIT" >> /etc/security/limits.conf
         fi
     fi
      
     if [ -n "$FILE_OPEN_MAX_SOFTLIMIT" ]
     then
        #if line is present in the file then
        #get current value from /etc/security/limits.conf
        echo "File open max softlimit in response file:$FILE_OPEN_MAX_SOFTLIMIT" >> $log_file/orarun.log
        if grep "^$INSTALL_USER[[:space:]]\+soft[[:space:]]\+nofile[[:space:]]\+[0-9]\+" /etc/security/limits.conf
        then
            val=`grep "^$INSTALL_USER" /etc/security/limits.conf | awk '/soft[[:space:]]*nofile/ {print $4}'`
            echo "File open max softlimit in /etc/security/limits.conf:$val" >> $log_file/orarun.log
            if [ ! $FILE_OPEN_MAX_SOFTLIMIT ] || [ ! $val ]
            then
               echo "Could not find FILE_OPEN_MAX_SOFTLIMIT from /etc/security/limits.conf or response file.";
               EXIT_CODE=1;
            else
              if [ $FILE_OPEN_MAX_SOFTLIMIT -gt $val ]
  	      then
                  #delete the line and insert the new line
    	          grep -v "^$INSTALL_USER[[:space:]]\+soft[[:space:]]\+nofile[[:space:]]\+[0-9]\+" /etc/security/limits.conf > /tmp/limits.conf
                  cp /tmp/limits.conf /etc/security/limits.conf
	          echo "$INSTALL_USER soft nofile $FILE_OPEN_MAX_SOFTLIMIT" >> /etc/security/limits.conf
              else
                  echo "File open max softlimit in response file is not greater than value in /etc/security/limits.conf. Hence not changing it." |tee -a $log_file/orarun.log
	      fi
            fi
         else
          echo "$INSTALL_USER soft nofile $FILE_OPEN_MAX_SOFTLIMIT" >> /etc/security/limits.conf
         fi
     fi
   fi
 fi		

#Set default and current runlevels correctly
if [ "`echo $CHANGE_CURRENT_RUNLEVEL | tr A-Z a-z`" == "true" ]
then
   /sbin/telinit $DESIRED_CURRENT_RUNLEVEL
fi

if [ "`echo $CHANGE_DEFAULT_RUNLEVEL | tr A-Z a-z`" == "true" ]
then
    INITTAB_FILE="/etc/inittab"
    echo "Modifying $INITTAB_FILE to update the default runlevel" | tee -a $log_file/orarun.log
    typeset -i linenumber=`grep -n ":initdefault" $INITTAB_FILE | awk -F: '{ print $1 }'`
    typeset -i linesbefore=$linenumber-1
    head -n $linesbefore $INITTAB_FILE > $INITTAB_FILE.tmp
    echo "id:$DESIRED_DEFAULT_RUNLEVEL:initdefault:" >> $INITTAB_FILE.tmp
    typeset -i totallines=`wc -l $INITTAB_FILE | awk '{ print $1 }'`
    typeset -i linesafter=$totallines-$linenumber
    tail -n $linesafter $INITTAB_FILE >> $INITTAB_FILE.tmp 
    mv $INITTAB_FILE.tmp $INITTAB_FILE
    # tell init to re-examine the /etc/inittab file.
    /sbin/telinit q
fi


#set inventory permissions
if [ "`echo $SET_INVENTORY_PERMISSIONS | tr A-Z a-z`" == "true" ]
then
   
      echo "setting permissions for the central inventory '$CENTRAL_INVENTORY'" |tee -a $log_file/orarun.log
      /bin/chmod 770 -R $CENTRAL_INVENTORY   
      /bin/chown -R $ORACLE_USER:$INSTALL_GROUP $CENTRAL_INVENTORY 
fi


#Setup virtual ip
if [ "`echo $SETUP_VIRTUAL_IP | tr A-Z a-z`" == "true" ]
then
 echo "Updating /etc/hosts with Virtual IP information ..." >> $log_file/orarun.log
 domain_name="`domainname`"     
#strip off quotes
 ip_host_list=`grep ^VIRTUAL_IP_INFO $resp_file | cut -d= -f2`
 ip_host_list=`echo $ip_host_list | cut -d\" -f2`
 ip_host_list=`echo $ip_host_list | cut -d\" -f1`  
 for ip_hosts in $ip_host_list
 do
  ip=`echo $ip_hosts | cut -d: -f1`
  host=`echo $ip_hosts | cut -d: -f2`
  
  echo $host | grep "$domain_name"
  if [ $? -eq 0 ]
  then
    fqhn="$host"
    host=`echo $fqhn | awk -F. '{ print $1 }'`
  else
    fqhn="$host.$domain_name"
  fi
  echo "$ip   $fqhn	$host" >> /etc/hosts
  if [ $? -ne 0 ]
  then
    echo "An error occured while trying to update /etc/hosts file with Virtual IP information." |tee -a $log_file/orarun.log
  fi     
 done
fi

#Setup private nodes
if [ "`echo $SETUP_PRIVATE_NODES | tr A-Z a-z`" == "true" ]
then
 echo "Updating /etc/hosts with private node information" >> $log_file/orarun.log
 domain_name="`domainname`"     
 ip_host_list=`grep ^PRIVATE_NODE_INFO $resp_file | cut -d= -f2`
 ip_host_list=`echo $ip_host_list | cut -d\" -f2`
 ip_host_list=`echo $ip_host_list | cut -d\" -f1`
 for ip_hosts in $ip_host_list
 do
  ip=`echo $ip_hosts | cut -d: -f1`
  host=`echo $ip_hosts | cut -d: -f2`
  echo $host | grep "$domain_name"
  if [ $? -eq 0 ]
  then
    fqhn="$host"
    host=`echo $fqhn | awk -F. '{ print $1 }'`
  else
    fqhn="$host.$domain_name"
  fi
  echo "$ip	$fqhn	$host" >> /etc/hosts
  if [ $? -ne 0 ]
  then
    echo "An error occured while trying to update /etc/hosts file with Private Node information." |tee -a $log_file/orarun.log
  fi     
 done
fi

#Change primary group for users
if [ "`echo $CHANGE_PRIMARY_GROUP | tr A-Z a-z`" == "true" ] 
then 
 echo "Changing primary group for users  ... " >> $log_file/orarun.log
 user_group_list=`grep ^USERS_PRIMARY_GROUP $resp_file | cut -d= -f2`

     #Strip off quotes
 user_group_list=`echo $user_group_list | cut -d\" -f2`
 user_group_list=`echo $user_group_list | cut -d\" -f1` 
 for user_groups in `echo $user_group_list`
  do
    # user_groups=`echo $user_groups | tr , \ `
     user=`echo $user_groups | cut -d: -f1`
     if id $user
     then
         primary_grp=`echo $user_groups | cut -d: -f2`
         #Check if the user has the correct primary group 
         existing_primary_group=`id -ng $user` 
         if [ "$existing_primary_group" != "$primary_group" ]
         then 
            # Change the primary group for the user
            group_ids=`grep "$primary_grp:" /etc/group | awk -F: '{ print $3 }'` 
            for group_id in $group_ids
            do
               in_primary_group_name=`grep ":$group_id:" /etc/group | awk -F: '{ print $1 }'`
               if [ "$in_primary_group_name" = "$primary_grp" ]
               then
                  primary_group_id=$group_id
               fi
           done
           /usr/sbin/usermod -g $primary_group_id $user 
           existing_grps=`id -nG $user`
           # replace all spaces in existing_grps by ,
           existing_grps=`echo $existing_grps | tr \  ,`
           /usr/sbin/usermod -G $existing_grps,$existing_primary_group $user 
           if [ $? -ne 0 ]
           then
              echo "User: $user could not be added to all the groups in the list $grp_list. " |tee -a $log_file/orarun.log
           fi
        fi
     else
         echo "$user does not exist. " | tee -a $log_file/orarun.log
     fi
  done
fi

#Add users to the required groups
if [ "`echo $ADD_USER_TO_GROUP | tr A-Z a-z`" == "true" ]
then
 echo "Adding users to required groups ... " >> $log_file/orarun.log
  user_group_list=`grep ^USERS_GROUPS $resp_file | cut -d= -f2`

     #Strip off quotes
 user_group_list=`echo $user_group_list | cut -d\" -f2`
 user_group_list=`echo $user_group_list | cut -d\" -f1` 
 for user_groups in `echo $user_group_list`
  do
    # user_groups=`echo $user_groups | tr , \ `
     user=`echo $user_groups | cut -d: -f1`
     if id $user
     then
         grp_list=`echo $user_groups | cut -d: -f2`
         #get the groups user belongs to
          existing_grps=`id -nG $user`
         # replace all spaces in existing_grps by ,
          existing_grps=`echo $existing_grps | tr \  ,`
          /usr/sbin/usermod -G $grp_list,$existing_grps $user 
          if [ $? -ne 0 ]
          then
              echo "User: $user could not be added to all the groups in the list $grp_list. " |tee -a $log_file/orarun.log
          fi
     else
        echo "$user does not exist." | tee -a $log_file/orarun.log
     fi
  done 
fi


#install of ocfs tools
install_ocfs_packages ${INSTALL_PACKAGES_OCFS_TOOLS} "${PACKAGES_OCFS_TOOLS}" ${RPM_BASE_URL_OCFS_TOOLS} `uname -i`

#install of ocfs
install_ocfs_packages ${INSTALL_PACKAGES_OCFS}  "${PACKAGES_OCFS}" ${RPM_BASE_URL_OCFS} `uname -p`


#loading of ocfs kernel module
if [ "`echo $INSTALL_OCFS_MODULE | tr A-Z a-z`" == "true" ]
then
#Add /sbin to PATH so that ifconfig can run
   PATH=$PATH:/sbin
   if [ -f /etc/ocfs.conf ]
   then
	echo "No need to populate /etc/ocfs.conf"
   else
     for private_node in $PRIVATE_NODES
     do
       private_ip=`grep "$private_node" /etc/hosts | awk ' { print $1 }'`
       if check_ifconfig "$private_ip"
       then
#This is the Private IP address which needs to go into /etc/ocfs.conf
 	    echo "node_name = $private_node" > /etc/ocfs.conf
	    echo "ip_address = $private_ip" >> /etc/ocfs.conf
	    echo "ip_port = 7000" >> /etc/ocfs.conf
	    echo "comm_voting = 1" >> /etc/ocfs.conf
         fi
     done
     /sbin/ocfs_uid_gen -c
   fi 
#Prepare the dependencies among kernel modules which can later be used by modprobe
   /sbin/depmod -a
   kernel_rel=`uname -r`
   cd /lib/modules/$kernel_rel
   LOAD_OCFS=/sbin/load_ocfs
   mkdir -p ocfs
   cd ocfs
   ln -s /lib/modules/$kernel_rel/kernel/drivers/addon/ocfs/ocfs.o ocfs.o
   typeset -i load_ocfs_updated=`grep "MODULE=" $LOAD_OCFS | grep -v "MODULE_SCRIPT" | awk '$1 !~ /#/ { print $0 }' | grep "/lib/modules/$kernel_rel/ocfs/ocfs.o" | wc -l`
   if [ $load_ocfs_updated -eq 0 ]
   then
 # Check if atleast the MODULE= line is present
       typeset -i module_line_present=`grep "MODULE=" $LOAD_OCFS | grep -v "MODULE_SCRIPT" |  wc -l`
       if [ $module_line_present -ne 0 ]
       then
#There should be only one such line
         typeset -i linenumber=`grep -n "MODULE=" $LOAD_OCFS | grep -v "MODULE_SCRIPT" | awk -F: '{ print $1 }'`
          head -n $linenumber $LOAD_OCFS > $LOAD_OCFS.tmp
          echo "MODULE=/lib/modules/$kernel_rel/ocfs/ocfs.o" >> $LOAD_OCFS.tmp
          typeset -i totallines=`wc -l $LOAD_OCFS | awk '{ print $1 }'`
          typeset -i linesafter=$totallines-$linenumber-1
          tail -n $linesafter $LOAD_OCFS >> $LOAD_OCFS.tmp
          mv $LOAD_OCFS.tmp $LOAD_OCFS
       else
          echo "Could not find MODULE= line in $LOAD_OCFS. Please update $LOAD_OCFS manually. Please add the following line at the appropriate place: MODULE=/lib/modules/$kernel_rel/ocfs/ocfs.o."
          updated_load_ocfs="false"
       fi
   fi
   chmod +x ${LOAD_OCFS}
   ${LOAD_OCFS}
fi


#Mount devices using required parameters
if [ "`echo $ENABLE_MOUNT | tr A-Z a-z`" == "true" ]
then
  echo "Mounting devices with required parameters ..." >> $log_file/orarun.log
   mount_info_list=$MOUNT_INFO
   for mount_info in `echo $mount_info_list`
   do
         type_info=`echo $mount_info | cut -d% -f1`
         device_info=`echo $mount_info | cut -d% -f2`
         mount_pt=`echo $mount_info | cut -d% -f3`
         mount_options=`echo $mount_info | cut -d% -f4`
#First updating /etc/fstab if not updated already
         grep $device_info /etc/fstab

         if [ $? != 0 ]
         then
#Update /etc/fstab
           echo "$device_info $mount_pt $type_info $mount_options 0 2" >> /etc/fstab
         fi
# Create the mount location if does not exist already
         if ! test -d "$mount_pt"
         then
             su $INSTALL_USER -c "mkdir -p $mount_pt"
             if  [ $? -ne 0 ]
             then
               echo "Could not create mount point $mount_pt" | tee -a $log_file/orarun.log
             fi
         fi 
         #If mount point is in use; mount point could be in format /scratch/dir or /scratch/dir/ 
         if mount -l | grep "$mount_pt[/]\?[[:space:]]\+"
         then
           #if the reqd device is already  mounted on the given mount point umount and mount again, else if someother device is mounted, then error out. |||ly device can be in same format at mt pt.
           if mount -l | grep "$mount_pt[/]\?[[:space:]]\+" | grep "$device_info[/]\?[[:space:]]\+"
            then
                 echo "Unmounting the device..."
                 if ! umount $mount_pt
                 then
                     echo "Unmounting of $device_info failed, check if the device is in use." | tee -a $log_file/orarun.log
                 else
                     mount -t $type_info $device_info $mount_pt -o $mount_options
                     if [ $? -ne 0 ]
                     then
                        echo "Mounting $device_info on mountpoint $mount_pt with parameter $mount_options failed." | tee -a $log_file/orarun.log
                      fi
                 fi
            else
                echo "Some other filesystem is already mounted on $mount_pt. Specify another mount point or try unmounting the file system from $mount_pt."| tee -a $log_file/orarun.log
            fi
         else
           if ! mount -t $type_info $device_info $mount_pt -o $mount_options
           then
              echo "Mounting $device_info on mountpoint $mount_pt with parameter $mount_options failed." | tee -a $log_file/orarun.log
            fi
         fi
  done

fi

#install the required packages
if [ "`echo $INSTALL_PACKAGES | tr A-Z a-z`" == "true" ]
then
    if [ "`echo $USE_YUM | tr A-Z a-z`" == "true" ]
   then
	http_proxy=http://$HTTP_PROXY:$HTTP_PORT/
        export http_proxy
        ftp_proxy=http://$FTP_PROXY:$FTP_PORT/
        export ftp_proxy
	if [ -z "$YUM_CONF_LOCATION" -o ! -r "$YUM_CONF_LOCATION" ]
        then
                curr_dir=`pwd`
                echo "\n Creating the yum.conf file $curr_dir/yum.conf.. \n "
                YUM_LOG_DIR="/var/yum"
                if [ ! -e $YUM_LOG_DIR ]
                then
                   mkdir -p $YUM_LOG_DIR
                fi
                if [ ! -e $YUM_CACHE_LOC ]
                then
                   mkdir -p $YUM_CACHE_LOC
                fi
                prefix=""  
                if [ "$protocol" != "http" -o "$protocol" != "ftp:" ]
              then
                prefix="file://localhost"
              fi
                cat <<EOF > $curr_dir/yum.conf
[main]
cachedir=$YUM_CACHE_LOC
debuglevel=2
errorlevel=2
logfile=$YUM_LOG_DIR/yum.log
pkgpolicy=newest
tolerant=0
exactarch=1

[base]
baseurl=$prefix$YUM_REPOSITORY_URL
EOF
                YUM_CONF_LOCATION=$curr_dir/yum.conf
        fi
	if [ -n "$PACKAGES" ]
        then
           for package in $PACKAGES $GLIBC_PACKAGE $OCFS_PACKAGES
            do
                yum -y -c $YUM_CONF_LOCATION install $package
                if ! rpm --quiet -q $package
                then
                echo "Package: $package could not be installed" |tee -a $log_file/orarun.log
                fi
            done
        fi
  
    else
#USE RPM TO INSTALL PACKAGES
         echo "Installing packages using rpm ..." >> $log_file/orarun.log
	for rpm_name in $RPM_FILENAMES
        do
           url="$RPM_BASE_URL/$rpm_name"
           if [ -n $url ]
           then
              protocol="`expr $url : '\(....\)'`"
              if [ "$protocol" == "http" ]
              then
                 rpm -Uvh $url --httpproxy $HTTP_PROXY --httpport $HTTP_PORT
              elif [ "$protocol" == "ftp:" ]
              then
                 rpm -Uvh $url --ftpproxy $FTP_PROXY --ftpport $FTP_PORT
              else
                 rpm -Uvh $url
              fi
           fi
        done
	for package in $PACKAGES $GLIBC_PACKAGE $OCFS_PACKAGES
        do
          if ! rpm --quiet -q $package
          then
           echo "Package: $package could not be installed." |tee -a $log_file/orarun.log
          fi
       done
   fi	
fi

#install the oracle packages : bug fix 7378320
if [ "`echo $ORACLE_PACKAGES_ENABLE | tr A-Z a-z`" == "true" ]
then
#export all the env vars required for installing the packages
	if [ -n "$EXPORT_RPM_VARS" ]
	then
		for var in $EXPORT_RPM_VARS
		do
			export $var
		done
	fi

#install the packages from rpm location
        if [ -n "$ORACLE_PACKAGES" ]
        then
           for package in $ORACLE_PACKAGES
            do
		oraclepackage="$ORACLE_RPM_LOCATION/$package"
		echo Installing Package $oraclepackage
		rpm -Uvh $oraclepackage
		returncode=$?
            done
        fi
fi

#install the oracle packages : bug fix 7378320
if [ "`echo $REMOVE_USER_FROM_GROUP_ENABLE | tr A-Z a-z`" == "true" ]
then
	echo "Removing user '$REMOVE_USER' from group '$REMOVE_FROM_GROUP' ..."
	existing_user_groups=`id -nG $REMOVE_USER | grep $REMOVE_FROM_GROUP`
	if [ "$existing_user_groups" == "" ]; 
	then 
		echo "User '$REMOVE_USER' not in group '$REMOVE_FROM_GROUP'"
	else
		modified_groups=`echo $existing_user_groups | sed "s/$REMOVE_FROM_GROUP//g"  | sed "s/  / /g" | sed "s/ /,/g"`
		/usr/sbin/usermod -G $modified_groups $REMOVE_USER
	fi
fi

exit $EXIT_CODE ;
