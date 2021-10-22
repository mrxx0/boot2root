
════════════════════════════════════╣ Basic information ╠════════════════════════════════════
OS: Linux version 3.2.0-91-generic-pae (buildd@lgw01-15) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015
User & Groups: uid=1003(laurie) gid=1003(laurie) groups=1003(laurie)
Hostname: BornToSecHackMe
Writable folder: /rofs/tmp
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


Caching directories . . . . . ./linpeas.sh: 1: eval: Syntax error: "(" unexpected
. . . . . . . . . . . . . . . ./linpeas.sh: 1: eval: Syntax error: "(" unexpected
. . . . . . . . . . . . . . . . . DONE

════════════════════════════════════╣ System Information ╠════════════════════════════════════
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 3.2.0-91-generic-pae (buildd@lgw01-15) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015
Distributor ID:	Ubuntu
Description:	Ubuntu 12.04.5 LTS
Release:	12.04
Codename:	precise

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.3p1

╔══════════╣ USBCreator
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation

╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games

╔══════════╣ Date & uptime
Fri Oct 22 15:39:03 CEST 2021
 15:39:03 up  1:10,  1 user,  load average: 0.08, 0.03, 0.05

╔══════════╣ System stats
Filesystem      Size  Used Avail Use% Mounted on
/cow            501M   43M  459M   9% /
udev            493M  4.0K  493M   1% /dev
tmpfs           101M  276K  100M   1% /run
/dev/sr0        408M  408M     0 100% /cdrom
/dev/loop0      386M  386M     0 100% /rofs
tmpfs           501M  4.0K  501M   1% /tmp
none            5.0M     0  5.0M   0% /run/lock
none            501M     0  501M   0% /run/shm
             total       used       free     shared    buffers     cached
Mem:       1025212     583968     441244          0      99724     331528
-/+ buffers/cache:     152716     872496
Swap:            0          0          0

╔══════════╣ CPU info
Architecture:          i686
CPU op-mode(s):        32-bit, 64-bit
Byte Order:            Little Endian
CPU(s):                1
On-line CPU(s) list:   0
Thread(s) per core:    1
Core(s) per socket:    1
Socket(s):             1
Vendor ID:             GenuineIntel
CPU family:            6
Model:                 58
Stepping:              9
CPU MHz:               2893.406
BogoMIPS:              5786.81
Hypervisor vendor:     KVM
Virtualization type:   full
L1d cache:             32K
L1i cache:             32K
L2 cache:              256K
L3 cache:              6144K

╔══════════╣ Environment
╚ Any private information inside environment variables?
LESSOPEN=| /usr/bin/lesspipe %s
HISTFILESIZE=0
MAIL=/var/mail/laurie
SSH_CLIENT=192.168.56.1 59563 22
USER=laurie
SHLVL=1
HOME=/home/laurie
OLDPWD=/home/laurie
SSH_TTY=/dev/pts/0
LC_CTYPE=UTF-8
LC_TERMINAL_VERSION=3.4.2
LOGNAME=laurie
_=./linpeas.sh
TERM=xterm-256color
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
LANG=en_US.UTF-8
HISTSIZE=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.axa=00;36:*.oga=00;36:*.spx=00;36:*.xspf=00;36:
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
LC_TERMINAL=iTerm2
PWD=/home/laurie
SSH_CONNECTION=192.168.56.1 59563 192.168.56.104 22
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmseg
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester

Available information:

Kernel version: 3.2.0
Architecture: i386
Distribution: ubuntu
Distribution version: 12.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

78 kernel space exploits
48 user space exploits

Possible Exploits:

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2015-3202] fuse (fusermount)

   Details: http://seclists.org/oss-sec/2015/q2/520
   Exposure: probable
   Tags: debian=7.0|8.0,[ ubuntu=* ]
   Download URL: https://www.exploit-db.com/download/37089
   Comments: Needs cron or system admin interaction

[+] [CVE-2014-4699] ptrace/sysret

   Details: http://www.openwall.com/lists/oss-security/2014/07/08/16
   Exposure: probable
   Tags: [ ubuntu=12.04 ]
   Download URL: https://www.exploit-db.com/download/34134

[+] [CVE-2014-4014] inode_capable

   Details: http://www.openwall.com/lists/oss-security/2014/06/10/4
   Exposure: probable
   Tags: [ ubuntu=12.04 ]
   Download URL: https://www.exploit-db.com/download/33824

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL:
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: less probable
   Tags: ubuntu=(14.04|16.04){kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-1000370,CVE-2017-1000371] linux_offset2lib

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_offset2lib.c
   Comments: Uses "Stack Clash" technique

[+] [CVE-2017-1000366,CVE-2017-1000371] linux_ldso_dynamic

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=9|10,ubuntu=14.04.5|16.04.2|17.04,fedora=23|24|25
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_dynamic.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root PIEs

[+] [CVE-2017-1000366,CVE-2017-1000370] linux_ldso_hwcap

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2016-6663,CVE-2016-6664|CVE-2016-6662] mysql-exploit-chain

   Details: https://legalhackers.com/advisories/MySQL-Maria-Percona-PrivEscRace-CVE-2016-6663-5616-Exploit.html
   Exposure: less probable
   Tags: ubuntu=16.04.1
   Download URL: http://legalhackers.com/exploits/CVE-2016-6663/mysql-privesc-race.c
   Comments: Also MariaDB ver<10.1.18 and ver<10.0.28 affected

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2015-8660] overlayfs (ovl_setattr)

   Details: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
   Exposure: less probable
   Tags: ubuntu=(14.04|15.10){kernel:4.2.0-(18|19|20|21|22)-generic}
   Download URL: https://www.exploit-db.com/download/39166

[+] [CVE-2015-8660] overlayfs (ovl_setattr)

   Details: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/39230

[+] [CVE-2014-5207] fuse_suid

   Details: https://www.exploit-db.com/exploits/34923/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/34923

[+] [CVE-2014-5119] __gconv_translit_find

   Details: http://googleprojectzero.blogspot.com/2014/08/the-poisoned-nul-byte-2014-edition.html
   Exposure: less probable
   Tags: debian=6
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/34421.tar.gz

[+] [CVE-2014-0196] rawmodePTY

   Details: http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/33516

[+] [CVE-2013-2094] semtex

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Exposure: less probable
   Tags: RHEL=6
   Download URL: https://www.exploit-db.com/download/25444

[+] [CVE-2013-1959] userns_root_sploit

   Details: http://www.openwall.com/lists/oss-security/2013/04/29/1
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/25450

[+] [CVE-2013-0268] msr

   Details: https://www.exploit-db.com/exploits/27297/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/27297

[+] [CVE-2012-0809] death_star (sudo)

   Details: http://seclists.org/fulldisclosure/2012/Jan/att-590/advisory_sudo.txt
   Exposure: less probable
   Tags: fedora=16
   Download URL: https://www.exploit-db.com/download/18436


╔══════════╣ Executing Linux Exploit Suggester 2
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = (unset),
	LC_ALL = (unset),
	LC_CTYPE = "UTF-8",
	LC_TERMINAL_VERSION = "3.4.2",
	LC_TERMINAL = "iTerm2",
	LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 3.2.0
  Searching 72 exploits...

  Possible Exploits
  [1] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [4] perf_swevent
      CVE-2013-2094
      Source: http://www.exploit-db.com/exploits/26131


╔══════════╣ Protections
═╣ AppArmor enabled? .............. /etc/apparmor  /etc/apparmor.d
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Is ASLR enabled? ............... No
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes

════════════════════════════════════╣ Containers ╠════════════════════════════════════
╔══════════╣ Container related tools present
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No

════════════════════════════════════╣ Devices ╠════════════════════════════════════
╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk
sda

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
overlayfs / overlayfs rw 0 0
tmpfs /tmp tmpfs nosuid,nodev 0 0

╔══════════╣ Mounted disks information
diskutil Not Found

╔══════════╣ Mounted SMB Shares
smbutil Not Found


════════════════════════════════════╣ Available Software ╠════════════════════════════════════
╔══════════╣ Useful software

╔══════════╣ Installed Compiler
ii  gcc                                4:4.6.3-1ubuntu5                  GNU C compiler
ii  gcc-4.6                            4.6.3-1ubuntu5                    GNU C compiler
/usr/bin/gcc


════════════════════════════════════╣ Processes, Cron, Services, Timers & Sockets ╠════════════════════════════════════
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
root         1  0.0  0.1   3540  1952 ?        Ss   14:28   0:00 /sbin/init
root       873  0.0  0.0   2836   608 ?        S    14:28   0:00 upstart-udev-bridge --daemon
root       884  0.0  0.1   3076  1300 ?        Ss   14:28   0:00 /sbin/udevd --daemon
root       999  0.0  0.0   2952   788 ?        S    14:28   0:00  _ /sbin/udevd --daemon
root      1000  0.0  0.0   3068   848 ?        S    14:28   0:00  _ /sbin/udevd --daemon
syslog     895  0.0  0.1  30036  1352 ?        Sl   14:28   0:00 rsyslogd -c5
102        896  0.0  0.0   3260   892 ?        Ss   14:28   0:00 dbus-daemon --system --fork --activation=upstart
root      1103  0.0  0.0   2848   344 ?        S    14:28   0:00 upstart-socket-bridge --daemon
root      1212  0.0  0.0   4628   832 tty4     Ss+  14:28   0:00 /sbin/getty -8 38400 tty4
root      1227  0.0  0.0   4628   832 tty5     Ss+  14:28   0:00 /sbin/getty -8 38400 tty5
root      1238  0.0  0.0   2924   816 ?        Ss   14:28   0:00 dhclient3 -e IF_METRIC=100 -pf /var/run/dhclient.eth1.pid -lf /var/lib/dhcp/dhclient.eth1.leases -1 eth1
root      1262  0.0  0.0   4628   832 tty2     Ss+  14:28   0:00 /sbin/getty -8 38400 tty2
root      1263  0.0  0.0   4628   832 tty3     Ss+  14:28   0:00 /sbin/getty -8 38400 tty3
root      1267  0.0  0.0   4628   832 tty6     Ss+  14:28   0:00 /sbin/getty -8 38400 tty6
root      1274  0.0  0.0   2172   600 ?        Ss   14:28   0:00 acpid -c /etc/acpi/events -s /var/run/acpid.socket
root      1283  0.0  0.0   2616   876 ?        Ss   14:28   0:00 cron
1         1287  0.0  0.0   2468   344 ?        Ss   14:28   0:00 atd
root      1290  0.0  0.1   3008  1116 ?        Ss   14:28   0:00 /usr/sbin/dovecot -F -c /etc/dovecot/dovecot.conf
dovecot   1371  0.0  0.0   2720   820 ?        S    14:28   0:00  _ dovecot/anvil
root      1372  0.0  0.0   2716   908 ?        S    14:28   0:00  _ dovecot/log
root      1382  0.0  0.2   4836  2700 ?        S    14:28   0:00  _ dovecot/config
root      1291  0.0  0.0   4696   968 ?        Ss   14:28   0:00 /usr/sbin/vsftpd
root      1310  0.0  0.2   6680  2420 ?        Ss   14:28   0:00 /usr/sbin/sshd -D
laurie    1682  0.0  0.1  11360  1604 ?        S    14:29   0:00      _ sshd: laurie@pts/0
laurie    1683  0.0  0.5   9636  6076 pts/0    Ss   14:29   0:00          _ -bash
laurie    2096  0.5  0.1   2976  1324 pts/0    S+   15:38   0:00              _ /bin/sh ./linpeas.sh
laurie    6163  0.0  0.0   2976   816 pts/0    S+   15:39   0:00                  _ /bin/sh ./linpeas.sh
laurie    6167  0.0  0.1   4904  1060 pts/0    R+   15:39   0:00                  |   _ ps fauxwww
laurie    6166  0.0  0.0   2976   816 pts/0    S+   15:39   0:00                  _ /bin/sh ./linpeas.sh
mysql     1399  0.0  3.7 326544 38452 ?        Ssl  14:28   0:00 /usr/sbin/mysqld
root      1441  0.0  0.3  35012  3312 ?        Ss   14:28   0:00 php-fpm: master process (/etc/php5/fpm/php-fpm.conf)
www-data  1445  0.0  0.2  35012  2716 ?        S    14:28   0:00  _ php-fpm: pool www
www-data  1446  0.0  0.2  35012  2720 ?        S    14:28   0:00  _ php-fpm: pool www
www-data  1447  0.0  0.2  35012  2720 ?        S    14:28   0:00  _ php-fpm: pool www
www-data  1448  0.0  0.2  35012  2720 ?        S    14:28   0:00  _ php-fpm: pool www
whoopsie  1470  0.0  0.3  24448  3184 ?        Ssl  14:28   0:00 whoopsie
root      1516  0.0  0.8  38840  8460 ?        Ss   14:28   0:00 /usr/sbin/apache2 -k start
www-data  1538  0.0  0.4  38864  4224 ?        S    14:28   0:00  _ /usr/sbin/apache2 -k start
www-data  1539  0.0  0.4  38864  4224 ?        S    14:28   0:00  _ /usr/sbin/apache2 -k start
www-data  1540  0.0  0.4  38864  4224 ?        S    14:28   0:00  _ /usr/sbin/apache2 -k start
www-data  1548  0.0  0.4  38864  4224 ?        S    14:28   0:00  _ /usr/sbin/apache2 -k start
www-data  1549  0.0  0.4  38864  4224 ?        S    14:28   0:00  _ /usr/sbin/apache2 -k start
root      1555  0.0  0.0   4628   832 tty1     Ss+  14:28   0:00 /sbin/getty -8 38400 tty1

╔══════════╣ Binary processes permissions
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
   0 lrwxrwxrwx 1 root root    4 Mar 29  2012 /bin/sh -> dash
 27K -rwxr-xr-x 2 root root  27K Jun 18  2014 /sbin/getty
190K -rwxr-xr-x 1 root root 190K Mar 11  2015 /sbin/init
174K -rwxr-xr-x 1 root root 174K Sep 17  2015 /sbin/udevd
   0 lrwxrwxrwx 1 root root   34 Jul 24  2015 /usr/sbin/apache2 -> ../lib/apache2/mpm-prefork/apache2
 62K -rwxr-xr-x 1 root root  62K Oct 28  2014 /usr/sbin/dovecot
 11M -rwxr-xr-x 1 root root  11M Jul 17  2015 /usr/sbin/mysqld
520K -rwxr-xr-x 1 root root 520K Aug 18  2015 /usr/sbin/sshd
167K -rwxr-xr-x 1 root root 167K Mar 30  2012 /usr/sbin/vsftpd

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND    PID       USER   FD      TYPE DEVICE SIZE/OFF  NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd process found (dump creds from memory as root)
apache2 process found (dump creds from memory as root)
sshd: process found (dump creds from memory as root)

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root    722 Apr  2  2012 /etc/crontab

/etc/cron.d:
total 2
drwxr-xr-x 2 root root  47 Oct  8  2015 .
drwxr-xr-x 1 root root 420 Oct 22 14:28 ..
-rw-r--r-- 1 root root 102 Apr  2  2012 .placeholder
-rw-r--r-- 1 root root 544 Sep 30  2015 php5

/etc/cron.daily:
total 29
drwxr-xr-x 2 root root   275 Oct  8  2015 .
drwxr-xr-x 1 root root   420 Oct 22 14:28 ..
-rw-r--r-- 1 root root   102 Apr  2  2012 .placeholder
-rwxr-xr-x 1 root root   633 Jul 24  2015 apache2
-rwxr-xr-x 1 root root   219 Apr 10  2012 apport
-rwxr-xr-x 1 root root 15399 Apr 20  2012 apt
-rwxr-xr-x 1 root root   314 Apr 19  2013 aptitude
-rwxr-xr-x 1 root root   502 Mar 31  2012 bsdmainutils
-rwxr-xr-x 1 root root   256 Apr 13  2012 dpkg
-rwxr-xr-x 1 root root   372 Oct  4  2011 logrotate
-rwxr-xr-x 1 root root  1365 Sep 23  2014 man-db
-rwxr-xr-x 1 root root   606 Aug 17  2011 mlocate
-rwxr-xr-x 1 root root   249 Apr  9  2012 passwd
-rwxr-xr-x 1 root root  2417 Jul  1  2011 popularity-contest
-rwxr-xr-x 1 root root   330 Jul 27  2011 squirrelmail
-rwxr-xr-x 1 root root  2947 Apr  2  2012 standard
-rwxr-xr-x 1 root root   214 Jul  1  2014 update-notifier-common

/etc/cron.hourly:
total 1
drwxr-xr-x 2 root root  35 Oct  8  2015 .
drwxr-xr-x 1 root root 420 Oct 22 14:28 ..
-rw-r--r-- 1 root root 102 Apr  2  2012 .placeholder

/etc/cron.monthly:
total 1
drwxr-xr-x 2 root root  35 Oct  8  2015 .
drwxr-xr-x 1 root root 420 Oct 22 14:28 ..
-rw-r--r-- 1 root root 102 Apr  2  2012 .placeholder

/etc/cron.weekly:
total 3
drwxr-xr-x 2 root root  73 Oct  8  2015 .
drwxr-xr-x 1 root root 420 Oct 22 14:28 ..
-rw-r--r-- 1 root root 102 Apr  2  2012 .placeholder
-rwxr-xr-x 1 root root 730 Sep 13  2013 apt-xapian-index
-rwxr-xr-x 1 root root 907 Sep 23  2014 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


╔══════════╣ Services
╚ Search for outdated versions
 [ + ]  apache2
 [ - ]  bootlogd
 [ - ]  casper
 [ - ]  grub-common
 [ + ]  php5-fpm
 [ - ]  postfix
 [ - ]  rsync
 [ + ]  ssh
 [ - ]  stop-bootlogd
 [ - ]  stop-bootlogd-single
 [ - ]  urandom
 [ - ]  virtualbox-guest-utils
 [ - ]  x11-common

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#systemd-path-relative-paths

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#services
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/dbus.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket

╔══════════╣ Writable Sockets
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets
Socket '/dev/log' is writable
Socket '/run/dovecot/dns-client' is writable
Socket '/run/dovecot/lmtp' is writable
Socket '/run/mysqld/mysqld.sock' is writable
Socket '/run/acpid.socket' is writable
Socket '/run/dbus/system_bus_socket' is writable
Socket '/var/spool/postfix/dev/log' is writable
Socket '/rofs/var/spool/postfix/dev/log' is writable
╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets
/com/ubuntu/upstart
/dev/log
  └─(Read Write)
/rofs/var/spool/postfix/dev/log
  └─(Read Write)
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/dovecot/anvil
/run/dovecot/anvil-auth-penalty
/run/dovecot/auth-client
/run/dovecot/auth-login
/run/dovecot/auth-master
/run/dovecot/auth-userdb
/run/dovecot/auth-worker
/run/dovecot/config
/run/dovecot/dict
/run/dovecot/director-admin
/run/dovecot/director-userdb
/run/dovecot/dns-client
  └─(Read Write)
/run/dovecot/doveadm-server
/run/dovecot/ipc
/run/dovecot/lmtp
  └─(Read Write)
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/udev/control
  └─(Read )
/var/run/acpid.socket
  └─(Read Write)
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/dovecot/anvil
/var/run/dovecot/anvil-auth-penalty
/var/run/dovecot/auth-client
/var/run/dovecot/auth-login
/var/run/dovecot/auth-master
/var/run/dovecot/auth-userdb
/var/run/dovecot/auth-worker
/var/run/dovecot/config
/var/run/dovecot/dict
/var/run/dovecot/director-admin
/var/run/dovecot/director-userdb
/var/run/dovecot/dns-client
  └─(Read Write)
/var/run/dovecot/doveadm-server
/var/run/dovecot/ipc
/var/run/dovecot/lmtp
  └─(Read Write)
/var/run/dovecot/login/dns-client
/var/run/dovecot/login/imap
/var/run/dovecot/login/ipc-proxy
/var/run/dovecot/login/login
/var/run/dovecot/login/ssl-params
/var/run/mysqld/mysqld.sock
  └─(Read Write)
/var/spool/postfix/dev/log
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/wpa_supplicant.conf (        <policy group="netdev">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus
busctl Not Found


════════════════════════════════════╣ Network Information ╠════════════════════════════════════
╔══════════╣ Hostname, hosts and DNS
BornToSecHackMe
127.0.0.1 localhost
127.0.1.1 BornToSecHackMe

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts


╔══════════╣ Content of /etc/inetd.conf & /etc/xinetd.conf
/etc/inetd.conf Not Found

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth1      Link encap:Ethernet  HWaddr 08:00:27:7e:4b:78
          inet addr:192.168.56.104  Bcast:192.168.56.255  Mask:255.255.255.0
          inet6 addr: fe80::a00:27ff:fe7e:4b78/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:4410 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2991 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:982580 (982.5 KB)  TX bytes:511728 (511.7 KB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:40 errors:0 dropped:0 overruns:0 frame:0
          TX packets:40 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:3224 (3.2 KB)  TX bytes:3224 (3.2 KB)


╔══════════╣ Networks and neighbours
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
192.168.56.0    *               255.255.255.0   U     0      0        0 eth1
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.56.100           ether   08:00:27:6d:45:db   C                     eth1
192.168.56.1             ether   0a:00:27:00:00:00   C                     eth1

╔══════════╣ Iptables rules
iptables rules Not Found

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:993             0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:143             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
tcp6       0      0 :::993                  :::*                    LISTEN      -
tcp6       0      0 :::143                  :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -

╔══════════╣ Can I sniff with tcpdump?
No


════════════════════════════════════╣ Users Information ╠════════════════════════════════════
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#users
uid=1003(laurie) gid=1003(laurie) groups=1003(laurie)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Clipboard or highlighted text?
xsel and xclip Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#reusing-sudo-tokens
/proc/sys/kernel/yama/ptrace_scope is not enabled (1)
gdb was found in PATH

╔══════════╣ Checking doas.conf
doas.conf Not Found

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#pe-method-2

╔══════════╣ Superusers
root:roK20XGbWEsSM:0:0:pwned:/root:/bin/bash

╔══════════╣ Users with console
Binary file /etc/passwd matches

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(libuuid) gid=101(libuuid) groups=101(libuuid)
uid=1000(ft_root) gid=1000(ft_root) groups=1000(ft_root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),112(lpadmin),113(sambashare)
uid=1001(lmezard) gid=1001(lmezard) groups=1001(lmezard)
uid=1002(laurie@borntosec.net) gid=1002(laurie@borntosec.net) groups=1002(laurie@borntosec.net),8(mail)
uid=1003(laurie) gid=1003(laurie) groups=1003(laurie)
uid=1003(laurie) gid=1003(laurie) groups=1003(laurie)
uid=1004(thor) gid=1004(thor) groups=1004(thor)
uid=1005(zaz) gid=1005(zaz) groups=1005(zaz)
uid=101(syslog) gid=103(syslog) groups=103(syslog)
uid=102(messagebus) gid=106(messagebus) groups=106(messagebus)
uid=103(whoopsie) gid=107(whoopsie) groups=107(whoopsie)
uid=104(landscape) gid=110(landscape) groups=110(landscape)
uid=105(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(mysql) gid=115(mysql) groups=115(mysql)
uid=107(ftp) gid=116(ftp) groups=116(ftp)
uid=108(dovecot) gid=117(dovecot) groups=117(dovecot)
uid=109(dovenull) gid=65534(nogroup) groups=65534(nogroup)
uid=110(postfix) gid=118(postfix) groups=118(postfix)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 15:39:09 up  1:10,  1 user,  load average: 0.16, 0.05, 0.06
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
laurie   pts/0    192.168.56.1     14:29   13.00s  0.45s  0.00s /bin/sh ./linpe

╔══════════╣ Last logons

╔══════════╣ Last time logon each user

╔══════════╣ Password policy
PASS_MAX_DAYS	99999
PASS_MIN_DAYS	0
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



════════════════════════════════════╣ Software Information ╠════════════════════════════════════
╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.5.44, for debian-linux-gnu (i686) using readline 6.2

═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No
╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/my.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
[client]
port		= 3306
socket		= /var/run/mysqld/mysqld.sock
[mysqld_safe]
socket		= /var/run/mysqld/mysqld.sock
nice		= 0
[mysqld]
user		= mysql
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
port		= 3306
basedir		= /usr
datadir		= /var/lib/mysql
lc-messages-dir	= /usr/share/mysql
skip-external-locking
bind-address		= 127.0.0.1
key_buffer		= 16M
max_allowed_packet	= 16M
thread_stack		= 192K
thread_cache_size       = 8
myisam-recover         = BACKUP
query_cache_limit	= 1M
query_cache_size        = 16M
log_error = /var/log/mysql/error.log
expire_logs_days	= 10
max_binlog_size         = 100M
[mysqldump]
quick
quote-names
max_allowed_packet	= 16M
[mysql]
[isamchk]
key_buffer		= 16M
!includedir /etc/mysql/conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)
mariadb.cnf Not Found

-rw------- 1 root root 333 Oct  8  2015 /etc/mysql/debian.cnf

╔══════════╣ Analyzing PostgreSQL Files (limit 70)
Version: psql Not Found

pgadmin*.db Not Found

pg_hba.conf Not Found

postgresql.conf Not Found

pgsql.conf Not Found

═╣ PostgreSQL connection to template0 using postgres/NOPASS ........ No
═╣ PostgreSQL connection to template1 using postgres/NOPASS ........ No
═╣ PostgreSQL connection to template0 using pgsql/NOPASS ........... No
═╣ PostgreSQL connection to template1 using pgsql/NOPASS ........... No

╔══════════╣ Analyzing Mongo Files (limit 70)
Version: mongo Not Found
mongod Not Found

mongod*.conf Not Found

╔══════════╣ Analyzing Apache Files (limit 70)
Version: Server version: Apache/2.2.22 (Ubuntu)
Server built:   Jul 24 2015 17:25:42
httpd Not Found

══╣ PHP exec extensions
/etc/apache2/mods-available/php5.conf-    <FilesMatch "\.ph(p3?|tml)$">
/etc/apache2/mods-available/php5.conf:	SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php5.conf-    <FilesMatch "\.phps$">
/etc/apache2/mods-available/php5.conf:	SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php5.conf-    <FilesMatch "\.ph(p3?|tml)$">
/etc/apache2/mods-enabled/php5.conf:	SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php5.conf-    <FilesMatch "\.phps$">
/etc/apache2/mods-enabled/php5.conf:	SetHandler application/x-httpd-php-source
--
/etc/apache2/sites-available/default-	<IfModule mod_php5.c>
/etc/apache2/sites-available/default:		AddType application/x-httpd-php .php
--
/etc/apache2/sites-enabled/000-default-	<IfModule mod_php5.c>
/etc/apache2/sites-enabled/000-default:		AddType application/x-httpd-php .php
drwxr-xr-x 2 root root 34 Oct  8  2015 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 34 Oct  8  2015 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 26 Oct  8  2015 /etc/apache2/sites-enabled/000-default -> ../sites-available/default
	ServerName BorntoSec
    AuthType Basic
    AuthName "phpMyAdmin Setup"
    AuthUserFile /etc/phpmyadmin/htpasswd.setup


000-default.conf Not Found

╔══════════╣ Analyzing Tomcat Files (limit 70)
tomcat-users.xml Not Found

╔══════════╣ Analyzing FastCGI Files (limit 70)
fastcgi_params Not Found

╔══════════╣ Analyzing Http conf Files (limit 70)
-rw-r--r-- 1 root root 0 Oct  8  2015 /etc/apache2/httpd.conf

╔══════════╣ Analyzing Htpasswd Files (limit 70)
.htpasswd Not Found

╔══════════╣ Analyzing PHP Sessions Files (limit 70)
/var/lib/php/sessions Not Found
sess_* Not Found

╔══════════╣ Analyzing Wordpress Files (limit 70)
wp-config.php Not Found

╔══════════╣ Analyzing Drupal Files (limit 70)
settings.php Not Found

╔══════════╣ Analyzing Moodle Files (limit 70)
config.php Not Found

╔══════════╣ Analyzing Supervisord Files (limit 70)
supervisord.conf Not Found

╔══════════╣ Analyzing Cesi Files (limit 70)
cesi.conf Not Found

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 937 Nov  8  2011 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

rsyncd.secrets Not Found

╔══════════╣ Analyzing Hostapd Files (limit 70)
hostapd.conf Not Found

╔══════════╣ Searching wifi conns file
 Not Found

╔══════════╣ Analyzing Anaconda ks Files (limit 70)
anaconda-ks.cfg Not Found

╔══════════╣ Analyzing VNC Files (limit 70)
.vnc Not Found

*vnc*.c*nf* Not Found

*vnc*.ini Not Found

*vnc*.txt Not Found

*vnc*.xml Not Found

╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 32 Oct  8  2015 /etc/ldap


╔══════════╣ Analyzing OpenVPN Files (limit 70)
*.ovpn Not Found

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)
id_dsa* Not Found

id_rsa* Not Found

known_hosts Not Found

authorized_hosts Not Found

authorized_keys Not Found

Port 22
PermitRootLogin no
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/apache2/server.crt
/var/spool/postfix/etc/ssl/certs/ca-certificates.crt
2096PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config
AuthorizedKeysFile	.ssh/authorized_keys
Subsystem	sftp	/usr/libexec/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Searching unexpected auth lines in /etc/pam.d/sshd
No

╔══════════╣ NFS exports?
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
/etc/exports Not Found

╔══════════╣ Searching kerberos conf files and tickets
╚ https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt
tickets kerberos Not Found
klist Not Found

╔══════════╣ Analyzing Knockd Files (limit 70)
*knockd* Not Found

╔══════════╣ Analyzing Kibana Files (limit 70)
kibana.y*ml Not Found

╔══════════╣ Analyzing Elasticsearch Files (limit 70)
The version is
elasticsearch.y*ml Not Found

╔══════════╣ Searching logstash files
 Not Found

╔══════════╣ Searching Vault-ssh files
vault-ssh-helper.hcl Not Found

╔══════════╣ Searching AD cached hashes
cached hashes Not Found

╔══════════╣ Searching screen sessions
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions
No Sockets found in /var/run/screen/S-laurie.

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions
tmux Not Found

╔══════════╣ Analyzing CouchDB Files (limit 70)
couchdb Not Found

╔══════════╣ Analyzing Redis Files (limit 70)
redis.conf Not Found

╔══════════╣ Searching dovecot files
dovecot credentials Not Found

╔══════════╣ Analyzing Mosquitto Files (limit 70)
mosquitto.conf Not Found

╔══════════╣ Analyzing Neo4j Files (limit 70)
neo4j Not Found

╔══════════╣ Analyzing Cloud Credentials Files (limit 70)
credentials Not Found

credentials.db Not Found

legacy_credentials.db Not Found

access_tokens.db Not Found

access_tokens.json Not Found

accessTokens.json Not Found

azureProfile.json Not Found

TokenCache.dat Not Found

AzureRMContext.json Not Found

.bluemix Not Found

╔══════════╣ Analyzing Cloud Init Files (limit 70)
cloud.cfg Not Found

╔══════════╣ Analyzing CloudFlare Files (limit 70)
.cloudflared Not Found

╔══════════╣ Analyzing Erlang Files (limit 70)
.erlang.cookie Not Found

╔══════════╣ Analyzing GMV Auth Files (limit 70)
gvm-tools.conf Not Found

╔══════════╣ Analyzing IPSec Files (limit 70)
ipsec.secrets Not Found

ipsec.conf Not Found

╔══════════╣ Analyzing IRSSI Files (limit 70)
.irssi Not Found

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 121 Oct  8  2015 /usr/share/keyrings
drwxr-xr-x 2 root root 49 Oct  8  2015 /var/lib/apt/keyrings

*.keyring Not Found

*.keystore Not Found

*.jks Not Found

╔══════════╣ Analyzing Filezilla Files (limit 70)
filezilla Not Found

filezilla.xml Not Found

recentservers.xml Not Found

╔══════════╣ Analyzing Backup Manager Files (limit 70)
storage.php Not Found

database.php Not Found

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing kcpassword files
╚ https://book.hacktricks.xyz/macos/macos-security-and-privilege-escalation#kcpassword
n

╔══════════╣ Searching GitLab related files


╔══════════╣ Analyzing Github Files (limit 70)
.github Not Found

.gitconfig Not Found

.git-credentials Not Found

.git Not Found

╔══════════╣ Analyzing Svn Files (limit 70)
.svn Not Found

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found
*.pgp Not Found

-rw------- 1 root root 1200 Oct  8  2015 /etc/apt/trustdb.gpg
-rw-r--r-- 1 root root 12335 Oct  8  2015 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 198 Oct 13  2011 /usr/share/apt-setup/release-files/archive.canonical.com/precise/Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.10 (GNU/Linux)
iEYEABECAAYFAk6XHOYACgkQQJdur0N9BbVtpACfTUw+q4n26EJrWW5ABCH87Pot
n24An2w46qbMspGZDeCfQbmCVKP+ghZU
=Zzuk
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 198 Oct 14  2011 /usr/share/apt-setup/release-files/archive.ubuntu.com/precise-backports/Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.10 (GNU/Linux)
iEYEABECAAYFAk6XnO8ACgkQQJdur0N9BbWmtgCgpPKuPWoM/gNAafUM4hycAxxJ
ZC8AniX3m1F0dClhunjnplSwT9FBfa5F
=1HcT
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 198 Oct 14  2011 /usr/share/apt-setup/release-files/archive.ubuntu.com/precise-proposed/Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.10 (GNU/Linux)
iEYEABECAAYFAk6XnO8ACgkQQJdur0N9BbXvqACfeMw8UqdMI7BpUuoO2Q4VbK5f
ghgAnREznkJqNuevL29+mQnT7CLrjkBx
=GszV
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 198 Oct 14  2011 /usr/share/apt-setup/release-files/archive.ubuntu.com/precise-updates/Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.10 (GNU/Linux)
iEYEABECAAYFAk6XnO8ACgkQQJdur0N9BbUFYACfb2n5rCQ5tgOKh+VzRnmKkP5F
Vs0Anjokby6yfsMAHS2bmB0XbUjBbCgT
=B5k+
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 198 Oct 25  2011 /usr/share/apt-setup/release-files/archive.ubuntu.com/precise/Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.10 (GNU/Linux)
iEYEABECAAYFAk6mm10ACgkQQJdur0N9BbWe/ACgpwxyZOkAw3AHhnDDsX7DFaeK
0l8An1BpwhjNB6VLtLKLtCROoZAWxJLx
=q3c5
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 198 Oct 25  2011 /usr/share/apt-setup/release-files/security.ubuntu.com/precise/Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.10 (GNU/Linux)
iEYEABECAAYFAk6mm10ACgkQQJdur0N9BbWe/ACgpwxyZOkAw3AHhnDDsX7DFaeK
0l8An1BpwhjNB6VLtLKLtCROoZAWxJLx
=q3c5
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 1724 Jul 22  2015 /usr/share/apt/ubuntu-archive.gpg
-rw-r--r-- 1 root root 12335 Sep 27  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 Sep 27  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 Sep 27  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct  8  2015 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 198 Oct 13  2015 /var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_precise-security_Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)
iEYEABECAAYFAlYdUwsACgkQQJdur0N9BbV3PACghSRBplHeSZS8AH7dKXUHwT51
WHIAoKmFvr0DR1vJnlf24Tnm6kuKIw5Z
=n7sr
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 198 Jun 29  2015 /var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_precise-backports_Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)
iEYEABECAAYFAlWQ6+0ACgkQQJdur0N9BbUW3wCgkmkTMYnVXHlupngo45EXEGpJ
AuMAmgI0OZhJW6PNNar4RWpfrCjkJbXA
=Nosq
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 198 Oct 10  2015 /var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_precise-updates_Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)
iEYEABECAAYFAlYYukQACgkQQJdur0N9BbUExwCfcbEAso3bOOpy6pukbPaapq3c
8g0AnA/Yux/JEJB8gakB+2CqI3TJRMCd
=g7I2
-----END PGP SIGNATURE-----
-rw-r--r-- 1 root root 198 Apr 26  2012 /var/lib/apt/lists/us.archive.ubuntu.com_ubuntu_dists_precise_Release.gpg
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.10 (GNU/Linux)
iEYEABECAAYFAk+Yf4YACgkQQJdur0N9BbVHsgCfR7AVn0dpd488Ge5cYlOCv5GA
g8wAmwaLRc0PwlYfNr3MbsgQ5T+RBbbd
=J4xr
-----END PGP SIGNATURE-----

*.gnupg Not Found

╔══════════╣ Analyzing Cache Vi Files (limit 70)
*.swp Not Found

*.viminfo Not Found

╔══════════╣ Analyzing Wget Files (limit 70)
.wgetrc Not Found

╔══════════╣ Checking if containerd(ctr) is available
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/containerd-ctr-privilege-escalation

╔══════════╣ Checking if runc is available
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/runc-privilege-escalation

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-docker-socket

╔══════════╣ Analyzing Firefox Files (limit 70)
.mozilla Not Found

Firefox Not Found

╔══════════╣ Analyzing Chrome Files (limit 70)
google-chrome Not Found

Chrome Not Found

╔══════════╣ Analyzing Autologin Files (limit 70)
autologin Not Found

autologin.conf Not Found

╔══════════╣ S/Key authentication

╔══════════╣ YubiKey authentication

╔══════════╣ Passwords inside pam.d

╔══════════╣ Analyzing SNMP Files (limit 70)
snmpd.conf Not Found

╔══════════╣ Analyzing Pypirc Files (limit 70)
.pypirc Not Found

╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 5117 May 10  2013 /etc/bash_completion.d/postfix

-rwxr-xr-x 1 root root 7355 Feb 20  2015 /etc/init.d/postfix

-rw-r--r-- 1 root root 30 Feb 20  2015 /etc/insserv.conf.d/postfix

-rwxr-xr-x 1 root root 803 Feb 20  2015 /etc/network/if-down.d/postfix

-rwxr-xr-x 1 root root 1120 Feb 20  2015 /etc/network/if-up.d/postfix

drwxr-xr-x 3 root root 144 Oct  8  2015 /etc/postfix
-rw-r--r-- 1 root root 5531 Oct  8  2015 /etc/postfix/master.cf
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#  user=cyrus argv=/cyrus/bin/deliver -e -r ${sender} -m ${extension} ${user}
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py

-rwxr-xr-x 1 root root 803 Feb 20  2015 /etc/ppp/ip-down.d/postfix

-rwxr-xr-x 1 root root 1120 Feb 20  2015 /etc/ppp/ip-up.d/postfix

-rwxr-xr-x 1 root root 426 Feb 20  2015 /etc/resolvconf/update-libc.d/postfix

-rw-r--r-- 1 root root 361 Feb 20  2015 /etc/ufw/applications.d/postfix

drwxr-xr-x 2 root root 616 Oct  8  2015 /usr/lib/postfix
-rwxr-xr-x 1 root root 5531 Feb 20  2015 /usr/lib/postfix/master.cf
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#  user=cyrus argv=/cyrus/bin/deliver -e -r ${sender} -m ${extension} ${user}
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py

-rwxr-xr-x 1 root root 9512 Feb 20  2015 /usr/sbin/postfix

drwxr-xr-x 2 root root 102 Oct  8  2015 /usr/share/doc/postfix

-rw-r--r-- 1 root root 275 Feb 20  2015 /usr/share/lintian/overrides/postfix

drwxr-xr-x 2 root root 124 Oct  8  2015 /usr/share/postfix

drwxr-xr-x 2 postfix postfix 96 Oct  8  2015 /var/lib/postfix

-rw-r--r-- 1 root root 29 Oct  8  2015 /var/lib/update-rc.d/postfix

drwxr-xr-x 1 root root 80 Oct  8  2015 /var/spool/postfix
find: `/var/spool/postfix/active': Permission denied
find: `/var/spool/postfix/bounce': Permission denied
find: `/var/spool/postfix/corrupt': Permission denied
find: `/var/spool/postfix/defer': Permission denied
find: `/var/spool/postfix/deferred': Permission denied
find: `/var/spool/postfix/flush': Permission denied
find: `/var/spool/postfix/hold': Permission denied
find: `/var/spool/postfix/incoming': Permission denied
find: `/var/spool/postfix/maildrop': Permission denied
find: `/var/spool/postfix/private': Permission denied
find: `/var/spool/postfix/public': Permission denied
find: `/var/spool/postfix/saved': Permission denied
find: `/var/spool/postfix/trace': Permission denied


╔══════════╣ Analyzing Ldaprc Files (limit 70)
.ldaprc Not Found

╔══════════╣ Analyzing Env Files (limit 70)
.env Not Found

╔══════════╣ Analyzing Msmtprc Files (limit 70)
.msmtprc Not Found

╔══════════╣ Analyzing Keepass Files (limit 70)
*.kdbx Not Found

KeePass.config* Not Found

KeePass.ini Not Found

KeePass.enforced* Not Found

╔══════════╣ Analyzing FTP Files (limit 70)
*.ftpconfig Not Found

ffftp.ini Not Found

ftp.ini Not Found

ftp.config Not Found

sites.ini Not Found

wcx_ftp.ini Not Found

winscp.ini Not Found

ws_ftp.ini Not Found

╔══════════╣ Analyzing Racoon Files (limit 70)
racoon.conf Not Found

psk.txt Not Found

╔══════════╣ Analyzing Opera Files (limit 70)
com.operasoftware.Opera Not Found

╔══════════╣ Analyzing Safari Files (limit 70)
Safari Not Found

╔══════════╣ Analyzing Bind Files (limit 70)
bind Not Found

╔══════════╣ Analyzing SeedDMS Files (limit 70)
seeddms* Not Found

╔══════════╣ Analyzing Ddclient Files (limit 70)
ddclient.conf Not Found

╔══════════╣ Analyzing Sentry Files (limit 70)
sentry Not Found

sentry.conf.py Not Found

╔══════════╣ Analyzing Strapi Files (limit 70)
environments Not Found

╔══════════╣ Analyzing Cacti Files (limit 70)
cacti Not Found

╔══════════╣ Analyzing Roundcube Files (limit 70)
roundcube Not Found

╔══════════╣ Analyzing Passbolt Files (limit 70)
passbolt.php Not Found

╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r--r-- 1 root root 0 Oct 22 14:28 /var/log/apache2/access.log

-rw-r--r-- 1 root root 399 Oct 22 14:28 /var/log/apache2/error.log

╔══════════╣ Analyzing Windows Files Files (limit 70)
unattend.inf Not Found

*.rdg Not Found

AppEvent.Evt Not Found

ConsoleHost_history.txt Not Found

FreeSSHDservice.ini Not Found

NetSetup.log Not Found

Ntds.dit Not Found

protecteduserkey.bin Not Found

RDCMan.settings Not Found

SAM Not Found

SYSTEM Not Found

SecEvent.Evt Not Found

appcmd.exe Not Found

bash.exe Not Found

datasources.xml Not Found

default.sav Not Found

drives.xml Not Found

groups.xml Not Found

https-xampp.conf Not Found

https.conf Not Found

iis6.log Not Found

index.dat Not Found

-rw-r--r-- 1 root root 3490 Oct  8  2015 /etc/mysql/my.cnf

my.ini Not Found

ntuser.dat Not Found

pagefile.sys Not Found

-rw-r--r-- 1 root root 68428 Sep 30  2015 /etc/php5/apache2/php.ini
-rw-r--r-- 1 root root 68105 Sep 30  2015 /etc/php5/cli/php.ini
-rw-r--r-- 1 root root 68428 Sep 30  2015 /etc/php5/fpm/php.ini

printers.xml Not Found

recentservers.xml Not Found

scclient.exe Not Found

scheduledtasks.xml Not Found

security.sav Not Found

server.xml Not Found

setupinfo Not Found

setupinfo.bak Not Found

sitemanager.xml Not Found

sites.ini Not Found

software Not Found

software.sav Not Found

sysprep.inf Not Found

sysprep.xml Not Found

system.sav Not Found

unattend.txt Not Found

unattend.xml Not Found

unattended.xml Not Found

wcx_ftp.ini Not Found

ws_ftp.ini Not Found

web*.config Not Found

winscp.ini Not Found

wsl.exe Not Found

╔══════════╣ Analyzing Other Interesting Files Files (limit 70)
-rw-r--r-- 1 root root 3486 Apr  3  2012 /etc/skel/.bashrc

.google_authenticator Not Found

hosts.equiv Not Found

.lesshst Not Found

.plan Not Found

-rw-r--r-- 1 root root 675 Apr  3  2012 /etc/skel/.profile

.recently-used.xbel Not Found

.rhosts Not Found

.sudo_as_admin_successful Not Found


════════════════════════════════════╣ Interesting Files ╠════════════════════════════════════
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 26K May 15  2015 /bin/fusermount
-rwsr-xr-x 1 root root 87K Jun 18  2014 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 34K Nov  8  2011 /bin/ping
-rwsr-xr-x 1 root root 39K Nov  8  2011 /bin/ping6
-rwsr-xr-x 1 root root 31K Sep 13  2012 /bin/su
-rwsr-xr-x 1 root root 67K Jun 18  2014 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 14K Mar  5  2015 /sbin/mount.ecryptfs_private
-rwsr-sr-x 1 1 daemon 42K Oct 25  2011 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 40K Sep 13  2012 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 32K Sep 13  2012 /usr/bin/chsh
-rwsr-xr-x 1 root root 57K Sep 13  2012 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Jul 28  2011 /usr/bin/mtr
-rwsr-xr-x 1 root root 31K Sep 13  2012 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 41K Sep 13  2012 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 2 root root 69K Mar 12  2015 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 2 root root 69K Mar 12  2015 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerableedit
-rwsr-xr-x 1 root root 14K Nov  8  2011 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root messagebus 310K Nov 25  2014 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 5.5K Dec 13  2011 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 243K Aug 18  2015 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 9.5K Mar 26  2015 /usr/lib/pt_chown  --->  GNU_glibc_2.1/2.1.1_-6(08-1999)
-rwsr-xr-- 1 root dip 295K Apr 21  2015 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-sr-x 1 libuuid libuuid 18K Jun 18  2014 /usr/sbin/uuidd
-rwsr-xr-x 1 root root 26K May 15  2015 /rofs/bin/fusermount
-rwsr-xr-x 1 root root 87K Jun 18  2014 /rofs/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 34K Nov  8  2011 /rofs/bin/ping
-rwsr-xr-x 1 root root 39K Nov  8  2011 /rofs/bin/ping6
-rwsr-xr-x 1 root root 31K Sep 13  2012 /rofs/bin/su
-rwsr-xr-x 1 root root 67K Jun 18  2014 /rofs/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 14K Mar  5  2015 /rofs/sbin/mount.ecryptfs_private
-rwsr-sr-x 1 1 daemon 42K Oct 25  2011 /rofs/usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 40K Sep 13  2012 /rofs/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 32K Sep 13  2012 /rofs/usr/bin/chsh
-rwsr-xr-x 1 root root 57K Sep 13  2012 /rofs/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Jul 28  2011 /rofs/usr/bin/mtr
-rwsr-xr-x 1 root root 31K Sep 13  2012 /rofs/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 41K Sep 13  2012 /rofs/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 2 root root 69K Mar 12  2015 /rofs/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 2 root root 69K Mar 12  2015 /rofs/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerableedit
-rwsr-xr-x 1 root root 14K Nov  8  2011 /rofs/usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root messagebus 310K Nov 25  2014 /rofs/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 5.5K Dec 13  2011 /rofs/usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 243K Aug 18  2015 /rofs/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 9.5K Mar 26  2015 /rofs/usr/lib/pt_chown  --->  GNU_glibc_2.1/2.1.1_-6(08-1999)
-rwsr-xr-- 1 root dip 295K Apr 21  2015 /rofs/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-sr-x 1 libuuid libuuid 18K Jun 18  2014 /rofs/usr/sbin/uuidd

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 30K Feb  9  2012 /sbin/unix_chkpwd
-rwsr-sr-x 1 1 daemon 42K Oct 25  2011 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root tty 9.5K Mar 31  2012 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 45K Sep 13  2012 /usr/bin/chage
-rwxr-sr-x 1 root crontab 34K Jun 19  2012 /usr/bin/crontab
-rwxr-sr-x 1 root mail 14K Jun 27  2013 /usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 18K Sep 13  2012 /usr/bin/expiry
-rwxr-sr-x 3 root mail 9.5K Oct 18  2011 /usr/bin/mail-lock
-rwxr-sr-x 3 root mail 9.5K Oct 18  2011 /usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 9.5K Oct 18  2011 /usr/bin/mail-unlock
-rwxr-sr-x 1 root mlocate 34K Aug 17  2011 /usr/bin/mlocate
-rwxr-sr-x 1 root utmp 357K Jun  6  2011 /usr/bin/screen  --->  GNU_Screen_4.5.0
-rwxr-sr-x 1 root ssh 126K Aug 18  2015 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 18K Jun 18  2014 /usr/bin/wall
-r-xr-sr-x 1 root postdrop 14K Feb 20  2015 /usr/sbin/postdrop
-r-xr-sr-x 1 root postdrop 14K Feb 20  2015 /usr/sbin/postqueue
-rwsr-sr-x 1 libuuid libuuid 18K Jun 18  2014 /usr/sbin/uuidd
-rwxr-sr-x 1 root shadow 30K Feb  9  2012 /rofs/sbin/unix_chkpwd
-rwsr-sr-x 1 1 daemon 42K Oct 25  2011 /rofs/usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root tty 9.5K Mar 31  2012 /rofs/usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 45K Sep 13  2012 /rofs/usr/bin/chage
-rwxr-sr-x 1 root crontab 34K Jun 19  2012 /rofs/usr/bin/crontab
-rwxr-sr-x 1 root mail 14K Jun 27  2013 /rofs/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 18K Sep 13  2012 /rofs/usr/bin/expiry
-rwxr-sr-x 3 root mail 9.5K Oct 18  2011 /rofs/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 9.5K Oct 18  2011 /rofs/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 9.5K Oct 18  2011 /rofs/usr/bin/mail-unlock
-rwxr-sr-x 1 root mlocate 34K Aug 17  2011 /rofs/usr/bin/mlocate
-rwxr-sr-x 1 root utmp 357K Jun  6  2011 /rofs/usr/bin/screen  --->  GNU_Screen_4.5.0
-rwxr-sr-x 1 root ssh 126K Aug 18  2015 /rofs/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 18K Jun 18  2014 /rofs/usr/bin/wall
-r-xr-sr-x 1 root postdrop 14K Feb 20  2015 /rofs/usr/sbin/postdrop
-r-xr-sr-x 1 root postdrop 14K Feb 20  2015 /rofs/usr/sbin/postqueue
-rwsr-sr-x 1 libuuid libuuid 18K Jun 18  2014 /rofs/usr/sbin/uuidd

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/i686-linux-gnu.conf
/lib/i386-linux-gnu
/usr/lib/i386-linux-gnu
/lib/i686-linux-gnu
/usr/lib/i686-linux-gnu
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
Current capabilities:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	ffffffffffffffff

Shell capabilities:
capsh Not Found
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	ffffffffffffffff

Files with capabilities (limited to 50):

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
/etc/security/capability.conf Not Found

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path
/usr/bin/amuFormat.sh
/usr/bin/gettext.sh

╔══════════╣ Unexpected in root
/initrd.img
/selinux
/vmlinuz
/rofs

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#profiles-files
total 3
drwxr-xr-x 2 root root   61 Oct  8  2015 .
drwxr-xr-x 1 root root  420 Oct 22 14:28 ..
-rwxr-xr-x 1 root root 1561 Jan 15  2012 Z97-byobu.sh
-rw-r--r-- 1 root root  475 May 10  2013 bash_completion.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/kern.log
/var/log/syslog
/var/log/auth.log

╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation
logrotate Not Found
./linpeas.sh: 3527: [: ImPOsSiBleeElastWlogFolder: unexpected operator
./linpeas.sh: 3527: [: ImPOsSiBleeElastWlogFolder: unexpected operator

╔══════════╣ Files inside /home/laurie (limit 20)
total 677
drwxr-x--- 1 laurie   laurie    140 Oct 22 15:39 .
drwxrwx--x 1 www-data root       60 Oct 13  2015 ..
-rwxr-x--- 1 laurie   laurie      1 Oct 15  2015 .bash_history
-rwxr-x--- 1 laurie   laurie    220 Oct  8  2015 .bash_logout
-rwxr-x--- 1 laurie   laurie   3489 Oct 13  2015 .bashrc
drwx------ 2 laurie   laurie     43 Oct 15  2015 .cache
drwx------ 2 laurie   laurie    100 Oct 22 15:39 .gnupg
-rwxr-x--- 1 laurie   laurie    675 Oct  8  2015 .profile
-rw------- 1 laurie   laurie   2258 Oct 22 14:34 .viminfo
-rwxr-x--- 1 laurie   laurie    158 Oct  8  2015 README
-rwxr-x--- 1 laurie   laurie  26943 Oct  8  2015 bomb
-rwxrwxr-x 1 laurie   laurie  12466 Oct 22 14:34 dirty
-rw-rw-r-- 1 laurie   laurie   4807 Oct 22 14:34 dirty.c
-rwxrwxr-x 1 laurie   laurie 629053 Oct 22 15:38 linpeas.sh

╔══════════╣ Files inside others home (limit 20)

╔══════════╣ Searching installed mail applications
dovecot
postfix
squirrelmail
maildirmake.dovecot
dovecot
postfix
postfix-add-filter
postfix-add-policy
sendmail
squirrelmail-configure

╔══════════╣ Mails (limit 50)
 13521    4 -rw-------   1 laurie@borntosec.net mail         3131 Oct  8  2015 /var/mail/laurie@borntosec.net
 13522    1 -rw-------   1 root     mail          608 Oct 14  2015 /var/mail/root
 13521    4 -rw-------   1 laurie@borntosec.net mail         3131 Oct  8  2015 /var/spool/mail/laurie@borntosec.net
 13522    1 -rw-------   1 root     mail          608 Oct 14  2015 /var/spool/mail/root

╔══════════╣ Backup folders

╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 335 Nov  1  2010 /etc/sgml/catalog.old
-rw-r--r-- 1 root root 610 Oct  8  2015 /etc/xml/catalog.old
-rw-r--r-- 1 root root 673 Oct  8  2015 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 6676 Sep  9  2015 /lib/modules/3.2.0-91-generic-pae/kernel/drivers/power/wm831x_backup.ko
-rwxr-xr-x 1 root root 86 Jan 24  2014 /lib/partman/commit.d/20remove_backup
-rwxr-xr-x 1 root root 142 Jan 24  2014 /lib/partman/init.d/95backup
-rwxr-xr-x 1 root root 186 Jan 24  2014 /lib/partman/undo.d/70unbackup
-rw-rw-r-- 1 laurie laurie 1601 Oct 22 14:34 /tmp/passwd.bak
-rwxr-xr-x 1 root root 30967 Jan 11  2013 /usr/bin/remastersys.old
-rw-r--r-- 1 root root 7867 Mar  7  2010 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 2513 Nov 18  2011 /usr/share/doc/tmux/examples/tmux_backup.sh
-rw-r--r-- 1 root root 1780 Apr 11  2012 /usr/share/gnome/help-langpack/evolution/en_GB/backup-restore.page
-rw-r--r-- 1 root root 960 Apr  2  2013 /usr/share/help-langpack/en_AU/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 738 Apr  2  2013 /usr/share/help-langpack/en_AU/deja-dup/backup-first.page
-rw-r--r-- 1 root root 1722 Aug  1  2012 /usr/share/help-langpack/en_AU/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2016 Aug  1  2012 /usr/share/help-langpack/en_AU/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 2387 Aug  1  2012 /usr/share/help-langpack/en_AU/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1422 Aug  1  2012 /usr/share/help-langpack/en_AU/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3167 Aug  1  2012 /usr/share/help-langpack/en_AU/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2498 Aug  1  2012 /usr/share/help-langpack/en_AU/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2342 Aug  1  2012 /usr/share/help-langpack/en_AU/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1294 Aug  1  2012 /usr/share/help-langpack/en_AU/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 1742 Aug  1  2012 /usr/share/help-langpack/en_CA/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2036 Aug  1  2012 /usr/share/help-langpack/en_CA/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 2392 Aug  1  2012 /usr/share/help-langpack/en_CA/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1429 Aug  1  2012 /usr/share/help-langpack/en_CA/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3189 Aug  1  2012 /usr/share/help-langpack/en_CA/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2536 Aug  1  2012 /usr/share/help-langpack/en_CA/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2355 Aug  1  2012 /usr/share/help-langpack/en_CA/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1301 Aug  1  2012 /usr/share/help-langpack/en_CA/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 960 Apr  2  2013 /usr/share/help-langpack/en_GB/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 738 Apr  2  2013 /usr/share/help-langpack/en_GB/deja-dup/backup-first.page
-rw-r--r-- 1 root root 1722 Aug  1  2012 /usr/share/help-langpack/en_GB/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2018 Aug  1  2012 /usr/share/help-langpack/en_GB/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 2375 Aug  1  2012 /usr/share/help-langpack/en_GB/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1422 Aug  1  2012 /usr/share/help-langpack/en_GB/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3167 Aug  1  2012 /usr/share/help-langpack/en_GB/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2499 Aug  1  2012 /usr/share/help-langpack/en_GB/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2342 Aug  1  2012 /usr/share/help-langpack/en_GB/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1294 Aug  1  2012 /usr/share/help-langpack/en_GB/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 11098 Oct 13  2015 /usr/share/info/dir.old
-rw-r--r-- 1 root root 147770 Sep  9  2015 /usr/src/linux-headers-3.2.0-91-generic-pae/.config.old
-rw-r--r-- 1 root root 0 Sep  9  2015 /usr/src/linux-headers-3.2.0-91-generic-pae/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 4200298 Oct  8  2015 /var/lib/aptitude/pkgstates.old
-rw-r--r-- 1 root root 198 Oct  8  2015 /var/lib/belocs/hashfile.old
-rw-r--r-- 1 root root 335 Nov  1  2010 /rofs/etc/sgml/catalog.old
-rw-r--r-- 1 root root 610 Oct  8  2015 /rofs/etc/xml/catalog.old
-rw-r--r-- 1 root root 673 Oct  8  2015 /rofs/etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 6676 Sep  9  2015 /rofs/lib/modules/3.2.0-91-generic-pae/kernel/drivers/power/wm831x_backup.ko
-rwxr-xr-x 1 root root 86 Jan 24  2014 /rofs/lib/partman/commit.d/20remove_backup
-rwxr-xr-x 1 root root 142 Jan 24  2014 /rofs/lib/partman/init.d/95backup
-rwxr-xr-x 1 root root 186 Jan 24  2014 /rofs/lib/partman/undo.d/70unbackup
-rwxr-xr-x 1 root root 30967 Jan 11  2013 /rofs/usr/bin/remastersys.old
-rw-r--r-- 1 root root 7867 Mar  7  2010 /rofs/usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 2513 Nov 18  2011 /rofs/usr/share/doc/tmux/examples/tmux_backup.sh
-rw-r--r-- 1 root root 1780 Apr 11  2012 /rofs/usr/share/gnome/help-langpack/evolution/en_GB/backup-restore.page
-rw-r--r-- 1 root root 960 Apr  2  2013 /rofs/usr/share/help-langpack/en_AU/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 738 Apr  2  2013 /rofs/usr/share/help-langpack/en_AU/deja-dup/backup-first.page
-rw-r--r-- 1 root root 1722 Aug  1  2012 /rofs/usr/share/help-langpack/en_AU/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2016 Aug  1  2012 /rofs/usr/share/help-langpack/en_AU/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 2387 Aug  1  2012 /rofs/usr/share/help-langpack/en_AU/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1422 Aug  1  2012 /rofs/usr/share/help-langpack/en_AU/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3167 Aug  1  2012 /rofs/usr/share/help-langpack/en_AU/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2498 Aug  1  2012 /rofs/usr/share/help-langpack/en_AU/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2342 Aug  1  2012 /rofs/usr/share/help-langpack/en_AU/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1294 Aug  1  2012 /rofs/usr/share/help-langpack/en_AU/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 1742 Aug  1  2012 /rofs/usr/share/help-langpack/en_CA/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2036 Aug  1  2012 /rofs/usr/share/help-langpack/en_CA/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 2392 Aug  1  2012 /rofs/usr/share/help-langpack/en_CA/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1429 Aug  1  2012 /rofs/usr/share/help-langpack/en_CA/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3189 Aug  1  2012 /rofs/usr/share/help-langpack/en_CA/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2536 Aug  1  2012 /rofs/usr/share/help-langpack/en_CA/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2355 Aug  1  2012 /rofs/usr/share/help-langpack/en_CA/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1301 Aug  1  2012 /rofs/usr/share/help-langpack/en_CA/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 960 Apr  2  2013 /rofs/usr/share/help-langpack/en_GB/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 738 Apr  2  2013 /rofs/usr/share/help-langpack/en_GB/deja-dup/backup-first.page
-rw-r--r-- 1 root root 1722 Aug  1  2012 /rofs/usr/share/help-langpack/en_GB/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2018 Aug  1  2012 /rofs/usr/share/help-langpack/en_GB/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 2375 Aug  1  2012 /rofs/usr/share/help-langpack/en_GB/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1422 Aug  1  2012 /rofs/usr/share/help-langpack/en_GB/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3167 Aug  1  2012 /rofs/usr/share/help-langpack/en_GB/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2499 Aug  1  2012 /rofs/usr/share/help-langpack/en_GB/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2342 Aug  1  2012 /rofs/usr/share/help-langpack/en_GB/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1294 Aug  1  2012 /rofs/usr/share/help-langpack/en_GB/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 11098 Oct 13  2015 /rofs/usr/share/info/dir.old
-rw-r--r-- 1 root root 147770 Sep  9  2015 /rofs/usr/src/linux-headers-3.2.0-91-generic-pae/.config.old
-rw-r--r-- 1 root root 0 Sep  9  2015 /rofs/usr/src/linux-headers-3.2.0-91-generic-pae/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 4200298 Oct  8  2015 /rofs/var/lib/aptitude/pkgstates.old
-rw-r--r-- 1 root root 198 Oct  8  2015 /rofs/var/lib/belocs/hashfile.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found: /etc/aliases.db: Berkeley DB (Hash, version 9, native byte-order)
Found: /var/lib/mlocate/mlocate.db: regular file, no read permission
Found: /var/lib/postfix/smtp_scache.db: regular file, no read permission
Found: /var/lib/postfix/smtpd_scache.db: regular file, no read permission


╔══════════╣ Web files?(output limit)
/var/www/:
total 5.5K
-rwxr-x---  1 www-data www-data  165 Oct  8  2015 +.png
drwxr-xr-x  4 root     root      134 Oct  8  2015 .
drwxr-xr-x  1 root     root      120 Jun 16  2017 ..
-rwxr-x---  1 www-data www-data  313 Oct  8  2015 fb.png
drwxr-x---  2 www-data www-data  132 Oct  8  2015 fonts
drwxr-xr-x 12 www-data www-data  186 Oct  8  2015 forum
-rw-r--r--  1 www-data www-data 1.1K Oct  8  2015 index.html
-rwxr-x---  1 www-data www-data 1.8K Oct  8  2015 style.css

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw------- 1 root root 0 Oct  8  2015 /etc/.pwd.lock
-rw-r--r-- 1 root root 220 Apr  3  2012 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 0 Oct 22 14:28 /run/network/.ifstate.lock
-rw-r--r-- 1 root root 118 Feb 18  2012 /usr/share/phpmyadmin/libraries/.htaccess
-rw-r--r-- 1 root root 118 Feb 18  2012 /usr/share/phpmyadmin/setup/frames/.htaccess
-rw-r--r-- 1 root root 118 Feb 18  2012 /usr/share/phpmyadmin/setup/lib/.htaccess
-rw-r--r-- 1 root root 14 Mar 26  2009 /usr/share/squirrelmail/class/.htaccess
-rw-r--r-- 1 root root 14 Mar 26  2009 /usr/share/squirrelmail/functions/.htaccess
-rw-r--r-- 1 root root 14 Mar 26  2009 /usr/share/squirrelmail/help/.htaccess
-rw-r--r-- 1 root root 14 Mar 26  2009 /usr/share/squirrelmail/include/.htaccess
-rw-r--r-- 1 root root 14 Mar 26  2009 /usr/share/squirrelmail/locale/.htaccess
-rw-r--r-- 1 root root 14 Feb  5  2002 /usr/share/squirrelmail/plugins/squirrelspell/modules/.htaccess
-rw-r--r-- 1 root root 14 Mar 26  2009 /usr/share/squirrelmail/po/.htaccess
-rw-r--r-- 1 root root 188 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/.built-in.o.cmd
-rw-r--r-- 1 root root 28486 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/.alloc-r0drv.o.cmd
-rw-r--r-- 1 root root 28748 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/.initterm-r0drv.o.cmd
-rw-r--r-- 1 root root 28766 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/.memobj-r0drv.o.cmd
-rw-r--r-- 1 root root 28644 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/.mpnotification-r0drv.o.cmd
-rw-r--r-- 1 root root 28814 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/.powernotification-r0drv.o.cmd
-rw-r--r-- 1 root root 28664 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/generic/.semspinmutex-r0drv-generic.o.cmd
-rw-r--r-- 1 root root 40482 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.RTLogWriteDebugger-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40658 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.alloc-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40738 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.assert-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40558 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.initterm-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40950 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.memobj-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40584 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.memuserkernel-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40754 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.mp-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40963 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.mpnotification-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40295 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.process-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 41214 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.semevent-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 41269 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.semeventmulti-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40876 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.semfastmutex-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40975 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.spinlock-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40663 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.thread-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40914 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.thread2-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 40466 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/r0drv/linux/.time-r0drv-linux.o.cmd
-rw-r--r-- 1 root root 6481 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.GenericRequest.o.cmd
-rw-r--r-- 1 root root 6784 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.HGCMInternal.o.cmd
-rw-r--r-- 1 root root 6227 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.Init.o.cmd
-rw-r--r-- 1 root root 6138 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.PhysHeap.o.cmd
-rw-r--r-- 1 root root 5763 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.SysHlp.o.cmd
-rw-r--r-- 1 root root 42465 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.VBoxGuest-linux.o.cmd
-rw-r--r-- 1 root root 7208 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.VBoxGuest.o.cmd
-rw-r--r-- 1 root root 6322 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.VBoxGuest2.o.cmd
-rw-r--r-- 1 root root 5850 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.VMMDev.o.cmd
-rw-r--r-- 1 root root 218 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.built-in.o.cmd
-rw-r--r-- 1 root root 383 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.vboxguest.ko.cmd
-rw-r--r-- 1 root root 26632 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.vboxguest.mod.o.cmd
-rw-r--r-- 1 root root 6150 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/.vboxguest.o.cmd
-rw-r--r-- 1 root root 4863 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/VBox/.log-vbox.o.cmd
-rw-r--r-- 1 root root 28262 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/VBox/.logbackdoor.o.cmd
-rw-r--r-- 1 root root 28132 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/alloc/.alloc.o.cmd
-rw-r--r-- 1 root root 28151 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/err/.RTErrConvertFromErrno.o.cmd
-rw-r--r-- 1 root root 28129 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/err/.RTErrConvertToErrno.o.cmd
-rw-r--r-- 1 root root 28267 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/log/.logcom.o.cmd
-rw-r--r-- 1 root root 28068 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/log/.logellipsis.o.cmd
-rw-r--r-- 1 root root 28156 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/log/.logformat.o.cmd
-rw-r--r-- 1 root root 28812 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/log/.logrel.o.cmd
-rw-r--r-- 1 root root 27964 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/log/.logrelellipsis.o.cmd
-rw-r--r-- 1 root root 4539 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/math/gcc/.divdi3.o.cmd
-rw-r--r-- 1 root root 4539 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/math/gcc/.moddi3.o.cmd
-rw-r--r-- 1 root root 4550 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/math/gcc/.qdivrem.o.cmd
-rw-r--r-- 1 root root 4550 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/math/gcc/.udivdi3.o.cmd
-rw-r--r-- 1 root root 4550 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/math/gcc/.umoddi3.o.cmd
-rw-r--r-- 1 root root 27999 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/misc/.RTAssertMsg1Weak.o.cmd
-rw-r--r-- 1 root root 27955 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/misc/.RTAssertMsg2.o.cmd
-rw-r--r-- 1 root root 27988 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/misc/.RTAssertMsg2Add.o.cmd
-rw-r--r-- 1 root root 28032 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/misc/.RTAssertMsg2AddWeak.o.cmd
-rw-r--r-- 1 root root 28043 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/misc/.RTAssertMsg2AddWeakV.o.cmd
-rw-r--r-- 1 root root 27999 Oct  8  2015 /var/lib/dkms/virtualbox-guest/4.1.12/build/vboxguest/common/misc/.RTAssertMsg2Weak.o.cmd

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-rw-r-- 1 laurie laurie 1601 Oct 22 14:34 /tmp/passwd.bak
-rwxr-xr-x 1 www-data www-data 14 Oct  8  2015 /var/www/forum/backup/.htaccess

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
/rofs
/rofs/tmp
/rofs/var/crash
/rofs/var/lib/php5
/rofs/var/tmp
/rofs/var/www/forum/templates_c
/run/lock
/run/screen/S-laurie
/run/shm
/tmp
/tmp/.ICE-unix
/tmp/.X11-unix
/tmp/passwd.bak
/tmp/tmux-1003
/var/crash
/var/lib/php5
/var/tmp
/var/www/forum/templates_c

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
  Group laurie:
/tmp/passwd.bak

╔══════════╣ Searching passwords in config PHP files
    // $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
// $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['nopassword'] = false;
$cfg['ShowChgPassword'] = true;
        'admin_confirm_password' => 'Admin password:',
        'edit_email_pw' => 'Password:',
        'edit_pw_conf' => 'Repeat new password:',
        'edit_pw_new' => 'New password:',
        'edit_pw_old' => 'Old password:',
        'edit_user_pw' => 'Password:',
        'error_password_too_short' => 'The password must contain at least [characters] characters',
        'error_password_wrong' => 'Password wrong',
        'login_password' => 'Password:',
        'register_pw' => 'Password:',
        'register_pw_conf' => 'Confirm password:',
        'register_pw_conf' => 'Repeat Password:',
Password: [password]

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Finding IPs inside logs (limit 70)

╔══════════╣ Finding passwords inside logs (limit 70)
passwd: password expiry information changed.

╔══════════╣ Finding emails inside logs (limit 70)
      1 maxk@qualcomm.com
      1 dm-devel@redhat.com

╔══════════╣ Finding *password* or *credential* files in home (limit 70)
/etc/apache2/server.key
/etc/pam.d/common-password
/usr/lib/dovecot/checkpassword-reply
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/pppd/2.4.5/passwordfd.so
/usr/lib/python2.7/dist-packages/launchpadlib/credentials.py
/usr/lib/python2.7/dist-packages/launchpadlib/credentials.pyc
/usr/lib/python2.7/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python2.7/dist-packages/launchpadlib/tests/test_credential_store.pyc
/usr/lib/python2.7/dist-packages/twisted/cred/credentials.py
/usr/lib/python2.7/dist-packages/twisted/cred/credentials.pyc
/usr/share/doc/dialog/examples/password
/usr/share/doc/dialog/examples/password1
/usr/share/doc/dialog/examples/password2
/usr/share/doc/dovecot-core/dovecot/example-config/conf.d/auth-checkpassword.conf.ext
/usr/share/dovecot/conf.d/auth-checkpassword.conf.ext
/usr/share/gnome/help-langpack/evince/en_GB/password.page
/usr/share/gnome/help-langpack/file-roller/en_GB/password-protection.page
/usr/share/gnome/help-langpack/file-roller/en_GB/troubleshooting-password.page
/usr/share/gnome/help-langpack/zenity/en_GB/password.page
/usr/share/help-langpack/en_AU/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_AU/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_AU/ubuntu-help/user-goodpassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-goodpassword.page
/usr/share/help-langpack/en_GB/empathy/irc-nick-password.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-goodpassword.page
/usr/share/man/man7/credentials.7.gz
/usr/share/pam/common-password
/usr/share/pam/common-password.md5sums
/usr/share/phpmyadmin/libraries/display_change_password.lib.php
/usr/share/phpmyadmin/user_password.php
/usr/share/pyshared/launchpadlib/credentials.py
/usr/share/pyshared/launchpadlib/tests/test_credential_store.py
/usr/share/pyshared/twisted/cred/credentials.py
/var/cache/debconf/passwords.dat
/var/lib/pam/password

╔══════════╣ Finding passwords inside key folders (limit 70) - only PHP files
/etc/phpmyadmin/config.inc.php:    // $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
/etc/phpmyadmin/config.inc.php:// $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
/var/www/forum/config/db_settings.php:$db_settings['password'] = 'Fg-\'kKXBj87E:aJ$';
/var/www/forum/includes/admin.inc.php:      #if(md5($_POST['restore_password'])!=$data['user_pw']) $errors[] = 'error_password_wrong';
/var/www/forum/includes/admin.inc.php:      #if(md5($_POST['update_password'])!=$data['user_pw']) $errors[] = 'error_password_wrong';
/var/www/forum/includes/admin.inc.php:      if(!is_pw_correct($_POST['restore_password'],$data['user_pw'])) $errors[] = 'error_password_wrong';
/var/www/forum/includes/admin.inc.php:      if(!is_pw_correct($_POST['update_password'],$data['user_pw'])) $errors[] = 'error_password_wrong';
/var/www/forum/includes/admin.inc.php:    if(empty($_POST['restore_password']) || $_POST['restore_password']=='') $errors[] = 'error_password_wrong';
/var/www/forum/includes/admin.inc.php:    if(empty($_POST['update_password']) || $_POST['update_password']=='') $errors[] = 'error_password_wrong';
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'admin_confirm_password' => 'Admin password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'edit_email_pw' => 'Password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'edit_pw_conf' => 'Repeat new password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'edit_pw_new' => 'New password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'edit_pw_old' => 'Old password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'edit_user_pw' => 'Password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'error_password_wrong' => 'Password wrong',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'login_password' => 'Password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'register_pw' => 'Password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'register_pw_conf' => 'Confirm password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:        'register_pw_conf' => 'Repeat Password:',
/var/www/forum/templates_c/8e2360743d8fd2dec4d073e8a0541dbe322a9482.english.lang.config.php:Password: [password]

╔══════════╣ Finding passwords inside key folders (limit 70) - no PHP files
/etc/acpi/powerbtn.sh:                userhome=`getent passwd $user | cut -d: -f6`
/etc/apache2/sites-available/default-ssl:	#     file needs this password: `xxj31ZMTZzkVA'.
/etc/apache2/sites-available/ssl:	#     file needs this password: `xxj31ZMTZzkVA'.
/etc/bash_completion.d/cvs:                pwd=$( pwd )
/etc/bash_completion.d/cvs:                pwd=${pwd##*/}
/etc/bash_completion.d/grub:__grub_mkpasswd_pbkdf2_program=$( echo grub-mkpasswd-pbkdf2 | sed "s,x,x," )
/etc/bash_completion.d/rsync:                --log-file-format= --password-file= --list-only --bwlimit= \
/etc/bash_completion:        COMPREPLY=( $( compgen -W '$( getent passwd | cut -d: -f3 )' -- "$cur" ) )
/etc/debconf.conf:#BindPasswd: secret
/etc/dovecot/conf.d/10-auth.conf:# We also try to handle password changes automatically: If user's previous
/etc/dovecot/conf.d/10-logging.conf:#auth_debug_passwords = no
/etc/dovecot/conf.d/10-logging.conf:#auth_verbose_passwords = no
/etc/dovecot/conf.d/10-ssl.conf:# root owned 0600 file by using ssl_key_password = <path.
/etc/dovecot/conf.d/auth-static.conf.ext:#  args = password=test
/etc/dovecot/conf.d/auth-static.conf.ext:#  args = proxy=y host=%1Mu.example.com nopassword=y
/etc/iscsi/iscsid.conf:#discovery.sendtargets.auth.password = password
/etc/iscsi/iscsid.conf:#discovery.sendtargets.auth.password_in = password_in
/etc/iscsi/iscsid.conf:#node.session.auth.password = password
/etc/iscsi/iscsid.conf:#node.session.auth.password_in = password_in
/etc/nsswitch.conf:passwd:         compat
/etc/pam.d/common-password:password	[success=1 default=ignore]	pam_unix.so obscure sha512
/etc/phpmyadmin/lighttpd.conf:	auth.backend.htpasswd.userfile = "/etc/phpmyadmin/htpasswd.setup"
/etc/security/namespace.init:                gid=$(echo "$passwd" | cut -f4 -d":")
/etc/security/namespace.init:        homedir=$(echo "$passwd" | cut -f6 -d":")
/etc/security/namespace.init:        passwd=$(getent passwd "$user")
/etc/squirrelmail/conf.pl:            print "Enter password:";
/etc/ssl/openssl.cnf:# input_password = secret
/etc/ssl/openssl.cnf:# output_password = secret
/etc/ssl/openssl.cnf:challengePassword		= A challenge password
/etc/ssl/openssl.cnf:challengePassword_max		= 20
/etc/ssl/openssl.cnf:challengePassword_min		= 4
/var/www/forum/lang/chinese.lang:admin_confirm_password =          管理员密码:
/var/www/forum/lang/chinese.lang:error_password_too_short =        密码至少包含[characters]个字符
/var/www/forum/lang/chinese.lang:error_password_wrong =            密码错误
/var/www/forum/lang/chinese.lang:login_password =                  密码:
/var/www/forum/lang/croatian.lang:admin_confirm_password =          Administracijska lozinka:
/var/www/forum/lang/croatian.lang:error_password_too_short =        Lozinka mora imati najmanje [characters] znakova
/var/www/forum/lang/croatian.lang:error_password_wrong =            Lozinka je neispravna
/var/www/forum/lang/croatian.lang:login_password =                  Lozinka:
/var/www/forum/lang/english.lang:Password: [password]
/var/www/forum/lang/english.lang:admin_confirm_password =          Admin password:
/var/www/forum/lang/english.lang:error_password_too_short =        The password must contain at least [characters] characters
/var/www/forum/lang/english.lang:error_password_wrong =            Password wrong
/var/www/forum/lang/english.lang:login_password =                  Password:
/var/www/forum/lang/french.lang:admin_confirm_password =          Mot de passe administrateur:
/var/www/forum/lang/french.lang:error_password_too_short =        Le mot de passe doit contenir au moins [characters] caractères
/var/www/forum/lang/french.lang:error_password_wrong =            Mot de passe erroné
/var/www/forum/lang/french.lang:login_password =                  Mot de passe:
/var/www/forum/lang/german.lang:admin_confirm_password =          Administrator-Passwort:
/var/www/forum/lang/german.lang:error_password_too_short =        das Passwort muss mindestens [characters] Zeichen lang sein
/var/www/forum/lang/german.lang:error_password_wrong =            Passwort falsch
/var/www/forum/lang/german.lang:login_password =                  Passwort:
/var/www/forum/lang/italian.lang:Password: [password]
/var/www/forum/lang/italian.lang:admin_confirm_password =          Password amministratore:
/var/www/forum/lang/italian.lang:error_password_too_short =        La password deve contenere almeno [characters] caratteri
/var/www/forum/lang/italian.lang:error_password_wrong =            Password sbagliata
/var/www/forum/lang/italian.lang:login_password =                  Password:
/var/www/forum/lang/norwegian.lang:admin_confirm_password =          Administratorpassord:
/var/www/forum/lang/norwegian.lang:error_password_too_short =        Passordet må inneholde minst [characters] tegn
/var/www/forum/lang/norwegian.lang:error_password_wrong =            Feil passord
/var/www/forum/lang/norwegian.lang:login_password =                  Passord:
/var/www/forum/lang/russian.lang:admin_confirm_password =          Административный пароль:
/var/www/forum/lang/russian.lang:error_password_wrong =            Пароль неправильный
/var/www/forum/lang/russian.lang:login_password =                  Пароль:
/var/www/forum/lang/spanish.lang:admin_confirm_password =          Admin Contrasena:
/var/www/forum/lang/spanish.lang:error_password_too_short =        La contrasena debe contener al menos [characters] caracteres
/var/www/forum/lang/spanish.lang:error_password_wrong =            Contrasena incorrecta
/var/www/forum/lang/spanish.lang:login_password =                  Contrasena:
/var/www/forum/lang/swedish.lang:admin_confirm_password =          Administratörslösenord:
/var/www/forum/lang/swedish.lang:error_password_too_short =        Lösenordet måste innehålla [characters] tecken!

╔══════════╣ Finding possible password variables inside key folders (limit 140)
/var/www/forum/includes/functions.inc.php:  $lang['admin_email_subject'] = str_replace("[subject]", $subject, $lang['admin_email_subject']);
/var/www/forum/lang/chinese.lang:admin_email_subject =             论坛新帖: [subject]
/var/www/forum/lang/chinese.lang:admin_email_text =                """[name]发表的新贴
/var/www/forum/lang/chinese.lang:admin_email_text_reply =          """由[name]回复
/var/www/forum/lang/chinese.lang:error_akismet_api_key =           Wordpress API Key错误
/var/www/forum/lang/chinese.lang:error_db_connection =             数据库连接错误, 请检查主机, 用户与密码
/var/www/forum/lang/chinese.lang:inst_admin_email =                管理员e-mail
/var/www/forum/lang/chinese.lang:inst_admin_email_desc =           论坛管理员e-mail
/var/www/forum/lang/chinese.lang:inst_db_host =                    数据库服务器
/var/www/forum/lang/chinese.lang:inst_db_host_desc =               服务器名称, 通常为 "localhost"
/var/www/forum/lang/chinese.lang:inst_db_pw =                      数据库密码
/var/www/forum/lang/chinese.lang:inst_db_pw_desc =                 数据库访问密码
/var/www/forum/lang/chinese.lang:inst_db_user =                    数据库用户
/var/www/forum/lang/chinese.lang:inst_db_user_desc =               数据库用户
/var/www/forum/lang/croatian.lang:admin_email_subject =           Nova poruka u forumu: [subject]
/var/www/forum/lang/croatian.lang:admin_email_text =              """Nova poruka od [name]
/var/www/forum/lang/croatian.lang:admin_email_text_reply =        """Odgovor od [name]
/var/www/forum/lang/croatian.lang:error_akismet_api_key =           Neispravan Wordpress API ključ
/var/www/forum/lang/croatian.lang:inst_admin_email =                   E-mail administratora
/var/www/forum/lang/croatian.lang:inst_admin_email_desc =              E-mail adresa administratora foruma
/var/www/forum/lang/croatian.lang:inst_db_host =                       Poslužitelj baze podataka
/var/www/forum/lang/croatian.lang:inst_db_host_desc =                  naziv poslužitelja, najčešće "localhost"
/var/www/forum/lang/croatian.lang:inst_db_pw =                         Lozinka baze
/var/www/forum/lang/croatian.lang:inst_db_pw_desc =                    Lozinka za pristup bazi
/var/www/forum/lang/croatian.lang:inst_db_user =                       Korisnik baze
/var/www/forum/lang/croatian.lang:inst_db_user_desc =                  Korisničko ime za pristup bazi
/var/www/forum/lang/english.lang:admin_email_subject =             New entry in the forum: [subject]
/var/www/forum/lang/english.lang:admin_email_text =                """New Entry by [name]
/var/www/forum/lang/english.lang:admin_email_text_reply =          """Reply by [name]
/var/www/forum/lang/english.lang:error_akismet_api_key =           Invalid Wordpress API Key
/var/www/forum/lang/english.lang:error_db_connection =             Database connection error - please check host, user and password
/var/www/forum/lang/english.lang:inst_admin_email =                Admin e-mail
/var/www/forum/lang/english.lang:inst_admin_email_desc =           E-mail address of the forum administrator
/var/www/forum/lang/english.lang:inst_db_host =                    Database host
/var/www/forum/lang/english.lang:inst_db_host_desc =               host name, mostly "localhost"
/var/www/forum/lang/english.lang:inst_db_pw =                      Database password
/var/www/forum/lang/english.lang:inst_db_pw_desc =                 Password to access the database
/var/www/forum/lang/english.lang:inst_db_user =                    Database user
/var/www/forum/lang/english.lang:inst_db_user_desc =               Username to access the database
/var/www/forum/lang/french.lang:admin_email_subject =             Nouveau sujet dans le forum : [subject]
/var/www/forum/lang/french.lang:admin_email_text =                """Nouveau sujet par [name]
/var/www/forum/lang/french.lang:admin_email_text_reply =          """Réponse par [name]
/var/www/forum/lang/french.lang:error_akismet_api_key =           Clé Wordpress API incorrecte
/var/www/forum/lang/french.lang:inst_admin_email =                Email de l'administrateur
/var/www/forum/lang/french.lang:inst_admin_email_desc =           Adresse email de l'administrateur du forum
/var/www/forum/lang/french.lang:inst_db_host =                    Serveur de la base de données
/var/www/forum/lang/french.lang:inst_db_host_desc =               nom du serveur, souvent "localhost"
/var/www/forum/lang/french.lang:inst_db_pw =                      Mot de passe pour la base de données
/var/www/forum/lang/french.lang:inst_db_pw_desc =                 Mot de passe pour accéder à la base de données
/var/www/forum/lang/french.lang:inst_db_user =                    Nom d'utilisateur pour la base de données
/var/www/forum/lang/french.lang:inst_db_user_desc =               Nom d'utilisateur pour accéder à la base de données
/var/www/forum/lang/german.lang:admin_email_subject =             Neuer Eintrag im Forum: [subject]
/var/www/forum/lang/german.lang:admin_email_text =                """Neuer Eintrag von [name]
/var/www/forum/lang/german.lang:admin_email_text_reply =          """Antwort von [name]
/var/www/forum/lang/german.lang:error_akismet_api_key =           Ungültiger Wordpress-API-Key
/var/www/forum/lang/german.lang:error_db_connection =             Datenbank-Verbindungsfehler - bitte Host, Benutzer und Passwort überprüfen
/var/www/forum/lang/german.lang:inst_admin_email =                E-Mail
/var/www/forum/lang/german.lang:inst_admin_email_desc =           E-Mail-Adresse des Foren-Administrators
/var/www/forum/lang/german.lang:inst_db_host =                    Datenbank-Host
/var/www/forum/lang/german.lang:inst_db_host_desc =               meistens "localhost"
/var/www/forum/lang/german.lang:inst_db_pw =                      Datenbank-Passwort
/var/www/forum/lang/german.lang:inst_db_pw_desc =                 Zugangspasswort für die Datenbank
/var/www/forum/lang/german.lang:inst_db_user =                    Datenbank-Benutzername
/var/www/forum/lang/german.lang:inst_db_user_desc =               Benutzername für die Datenbank
/var/www/forum/lang/italian.lang:admin_email_subject =             Nuovo argomento nel forum: [subject]
/var/www/forum/lang/italian.lang:admin_email_text =                """Nuovo argomento di [name]
/var/www/forum/lang/italian.lang:admin_email_text_reply =          """Risposta di [name]
/var/www/forum/lang/italian.lang:error_akismet_api_key =           Non valido Wordpress API Key
/var/www/forum/lang/italian.lang:inst_admin_email =                Indirizzo e-mail
/var/www/forum/lang/italian.lang:inst_admin_email_desc =           Indirizzo e-mail dell'amministratore del forum

╔══════════╣ Finding possible password in config files

╔══════════╣ Finding 'username' string inside key folders (limit 70)
/etc/casper.conf:export USERNAME="random"
/etc/dovecot/conf.d/auth-passwdfile.conf.ext:  args = scheme=CRYPT username_format=%u /etc/dovecot/users
/etc/dovecot/conf.d/auth-passwdfile.conf.ext:  args = username_format=%u /etc/dovecot/users
/etc/squirrelmail/conf.pl:            $force_username_lowercase       = false;
/etc/squirrelmail/conf.pl:            $force_username_lowercase       = true;
/etc/squirrelmail/conf.pl:            elsif ( $command == 5 )  { $force_username_lowercase = command35(); }
/etc/squirrelmail/conf.pl:        print "    Remove username from header  : $WHT$hide_auth_header$NRM\n";
/etc/squirrelmail/conf.pl:        print "5.  Field for username     : $WHT$prefs_user_field$NRM\n";
/etc/squirrelmail/conf.pl:        print "5.  Usernames in Lowercase       : $WHT$force_username_lowercase$NRM\n";
/etc/squirrelmail/conf.pl:        print "Enter username [$smtp_sitewide_user]:";
/etc/squirrelmail/conf.pl:        print CF "\$force_username_lowercase = $force_username_lowercase;\n";
/etc/squirrelmail/conf.pl:    print "Convert usernames to lowercase (y/n) [$WHT$default_value$NRM]: $WHT";
/etc/squirrelmail/conf.pl:    print "Remove username from email headers? (y/n) [$WHT$default_value$NRM]: $WHT";
/etc/squirrelmail/conf.pl:$force_username_lowercase = "false"    if ( !$force_username_lowercase );
/etc/squirrelmail/config.php:$force_username_lowercase = false;
/etc/squirrelmail/config_default.php:$force_username_lowercase = false;
/var/www/forum/includes/admin.inc.php:  $ar_username = $_POST['ar_username'];
/var/www/forum/includes/admin.inc.php:  $ar_username = trim($ar_username);
/var/www/forum/includes/admin.inc.php:  if($ar_username=='' or $ar_email=='') $errors[] = 'error_form_uncomplete';
/var/www/forum/includes/login.inc.php:elseif(isset($_GET['username']) && trim($_GET['username'])!='') $request_username = $_GET['username'];
/var/www/forum/includes/login.inc.php:if(isset($_POST['username']) && trim($_POST['username'])!='') $request_username = $_POST['username'];
/var/www/forum/lang/chinese.lang:error_username_invalid_chars =    The user name contains special characters
/var/www/forum/lang/chinese.lang:error_username_too_long =         用户名过长
/var/www/forum/lang/chinese.lang:login_username =                  用户名:
/var/www/forum/lang/chinese.lang:pwf_username =                    用户名:
/var/www/forum/lang/chinese.lang:register_username =               用户名:
/var/www/forum/lang/croatian.lang:error_username_invalid_chars =    Korisničko ime sadrži nedopuštene znakove
/var/www/forum/lang/croatian.lang:error_username_too_long =         Korisničko ime je predugačko
/var/www/forum/lang/croatian.lang:login_username =                  Korisničko ime:
/var/www/forum/lang/croatian.lang:pwf_username =                    Koriničko ime:
/var/www/forum/lang/croatian.lang:register_username =               Korisničko ime:
/var/www/forum/lang/croatian.lang:register_username =             Korisničko ime:
/var/www/forum/lang/english.lang:error_username_invalid_chars =    The user name contains invalid characters
/var/www/forum/lang/english.lang:error_username_too_long =         The user name is too long
/var/www/forum/lang/english.lang:login_username =                  Username:
/var/www/forum/lang/english.lang:pwf_username =                    Username:
/var/www/forum/lang/english.lang:register_username =               User name:
/var/www/forum/lang/english.lang:register_username =               Username:
/var/www/forum/lang/french.lang:error_username_invalid_chars =    Le nom de l'utilisateur contient des caractères spéciaux
/var/www/forum/lang/french.lang:error_username_too_long =         Le nom d'utilisateur est trop long
/var/www/forum/lang/french.lang:login_username =                  Identifiant:
/var/www/forum/lang/french.lang:pwf_username =                    Identifiant:
/var/www/forum/lang/french.lang:register_username =               Identifiant:
/var/www/forum/lang/french.lang:register_username =               Nom d'utilisateur:
/var/www/forum/lang/german.lang:error_username_invalid_chars =    der Benutzername enthält ungültige Zeichen
/var/www/forum/lang/german.lang:error_username_too_long =         der Name ist zu lang
/var/www/forum/lang/german.lang:login_username =                  Benutzername:
/var/www/forum/lang/german.lang:pwf_username =                    Benutzername:
/var/www/forum/lang/german.lang:register_username =               Benutzername:
/var/www/forum/lang/italian.lang:error_username_invalid_chars =    <!-- TODO -->The user name contains special characters
/var/www/forum/lang/italian.lang:error_username_too_long =         Il nome utente è troppo grande
/var/www/forum/lang/italian.lang:login_username =                  Nome utente:
/var/www/forum/lang/italian.lang:pwf_username =                    Nome utente:
/var/www/forum/lang/italian.lang:register_username =               Nome utente:
/var/www/forum/lang/norwegian.lang:error_username_invalid_chars =    Brukernavnet inneholder spesialtegn
/var/www/forum/lang/norwegian.lang:error_username_too_long =         Brukernavnet er for langt
/var/www/forum/lang/norwegian.lang:login_username =                  Brukernavn:
/var/www/forum/lang/norwegian.lang:pwf_username =                    Brukernavn:
/var/www/forum/lang/norwegian.lang:register_username =               Brukernavn:
/var/www/forum/lang/russian.lang:error_username_too_long =         Это имя слишком длинное
/var/www/forum/lang/russian.lang:login_username =                  Пользователь:
/var/www/forum/lang/russian.lang:pwf_username =                    Пользователь:
/var/www/forum/lang/russian.lang:register_username =               Имя пользователя:
/var/www/forum/lang/russian.lang:register_username =               Пользователь:
/var/www/forum/lang/spanish.lang:error_username_invalid_chars =    El nombre de usuario contiene caracteres especiales
/var/www/forum/lang/spanish.lang:error_username_too_long =         El nombre de usuario es demasiado largo
/var/www/forum/lang/spanish.lang:login_username =                  Nombre de Usuario:
/var/www/forum/lang/spanish.lang:pwf_username =                    Nombre de usuario:
/var/www/forum/lang/spanish.lang:register_username =               Nombre de usuario:
/var/www/forum/lang/swedish.lang:error_username_invalid_chars =    Användarnamnet innehåller ogiltiga tecken!

╔══════════╣ Searching specific hashes inside files - less false positives (limit 70)
