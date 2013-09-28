class oracle::server (
  $oracle_user  = "oracle", # User to run Oracle DB
  $dba_group    = "dba", # User group for user that runs Oracle DB
  $sid          = "orcl", # SID for Oracle database
  $oracle_root  = "/oradb", # Where install database
  $password     = "password" # SYS and SYSDBA password
) {

  # Derived parameters - do not change
  $ORACLE_USER        = "$oracle_user"    
  $DBA_GROUP          = "$dba_group" 
  $SID                = "$sid"
  $ORACLE_ROOT        = "$oracle_root"
  $PASSWORD           = "$password"
  $ORACLE_BASE        = "$ORACLE_ROOT/app/$ORACLE_USER"
  $ORACLE_HOME        = "$ORACLE_BASE/product/11.2.0/dbhome_1" 
  $DATA_LOCATION      = "$ORACLE_BASE/oradata"
  $INVENTORY_LOCATION = "$ORACLE_ROOT/app/oraInventory"

  package {
    ['oracle-rdbms-server-11gR2-preinstall','unzip', 'xorg-x11-apps', 'libaio', 'glibc', 'compat-libstdc++-33','elfutils-libelf-devel', 'libaio-devel', 'libgcc', 'libstdc++', 'unixODBC', 'unixODBC-devel', 'ksh']:
      ensure => installed;
  }
  
  group{ 
    ["$DBA_GROUP", 'oinstall'] :
      ensure => present;
  } 

  user { 
    "vagrant":
      groups => "$DBA_GROUP",
      require => Group["$DBA_GROUP"];

    "$ORACLE_USER":
      groups => "$DBA_GROUP",
      gid => 'oinstall',
      password => sha1('oracle'),
      ensure => present,
      require => Group["$DBA_GROUP", 'oinstall']
  }

  file {
    '/home/vagrant/aaa':
      content => "hello bla $test";

    "/etc/profile.d/ora.sh":
      mode => 0777,
      content => template("oracle/ora.sh.erb");

    ["$ORACLE_ROOT", "$ORACLE_ROOT/tmp"]:
      ensure => "directory",
      owner  => "$ORACLE_USER",
      group  => "$DBA_GROUP", 
      require=> Group["$DBA_GROUP"]; 

    "$ORACLE_ROOT/tmp/db_install_my.rsp":
      content => template("oracle/db_install_my.erb");

    "/etc/init.d/oracle":
      mode => 0777,
      content => template("oracle/oracle.erb");            
         
  }


  exec {
    "kernelprops":
      command => "/vagrant/modules/oracle/files/CVU_11.2.0.1.0_vagrant/runfixup.sh",
      user => root;

    "unzip part1":
      command => "/usr/bin/unzip /vagrant/modules/oracle/files/linux.x64_11gR2_database_1of2.zip -d $ORACLE_ROOT/tmp",
      cwd => "$ORACLE_ROOT/tmp",
      require => Package['unzip'],
      creates => "$ORACLE_ROOT/tmp/database",
      user => "$ORACLE_USER";

    "unzip part2":
      command => "/usr/bin/unzip /vagrant/modules/oracle/files/linux.x64_11gR2_database_2of2.zip -d $ORACLE_ROOT/tmp",
      cwd => "$ORACLE_ROOT/tmp",
      require => Exec['unzip part1'],
      creates => "$ORACLE_ROOT/tmp/database/stage/Components/oracle.jdk/1.5.0.17.0/1/DataFiles",
      user => "$ORACLE_USER";

    "install" :
      command => "/bin/sh -c '$ORACLE_ROOT/tmp/database/runInstaller -silent -waitforcompletion -ignorePrereq -responseFile $ORACLE_ROOT/tmp/db_install_my.rsp'",
      cwd => "$ORACLE_ROOT/tmp/database",
      timeout => 0,
      returns => [0, 3],
      require => [File["$ORACLE_ROOT/tmp/db_install_my.rsp", "$ORACLE_ROOT", '/etc/profile.d/ora.sh'], Exec['unzip part2','kernelprops']],
      creates => "$ORACLE_BASE",
      user => "$ORACLE_USER";

    "post-install 1":  
      command => "$INVENTORY_LOCATION/orainstRoot.sh",
      user => root,
      require=>Exec['install'];

    "post-install 2":  
      command => "$ORACLE_HOME/root.sh",
      user => root,
      require=>Exec['post-install 1'];     

    "autostart":  
      command => "/sbin/chkconfig --level 345 oracle on",
      user => root,
      require=>[Exec['post-install 2'], File['/etc/init.d/oracle', '/etc/profile.d/ora.sh']];  

    "autostart 2":  
      command => "/bin/sed -i 's/:N$/:Y/g' /etc/oratab",
      user => root,
      require=>Exec['autostart'];       
  }
}


class oracle::swap {
  exec {
    "create swapfile":
      # Needs to be 2 times the memory
      command => "/bin/dd if=/dev/zero of=/swapfile bs=2M count=1024",
      user => root,
      creates => "/swapfile";
    "set up swapfile":
      command => "/sbin/mkswap /swapfile",
      require => Exec["create swapfile"],
      user => root,
      unless => "/usr/bin/file /swapfile | grep 'swap file' 2>/dev/null";
    "enable swapfile":
      command => "/sbin/swapon /swapfile",
      require => Exec["set up swapfile"],
      user => root,
      unless => "/bin/cat /proc/swaps | grep '^/swapfile' 2>/dev/null";
    "add swapfile entry to fstab":
      command => "/bin/echo >>/etc/fstab /swapfile swap swap defaults 0 0",
      user => root,
      unless => "/bin/grep '^/swapfile' /etc/fstab 2>/dev/null";
  }

  file {
    "/swapfile":
      mode => 600,
      owner => root,
      group => root,
      require => Exec['create swapfile'];
  }
}
