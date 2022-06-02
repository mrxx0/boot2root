Using solution 1 to log as laurie we can see with :

unmame -a

Linux BornToSecHackMe 3.2.0-91-generic-pae #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015 i686 i686 i386 GNU/Linux

Our kernel version is 3.2.0-91

After few research online we found that our machine is vulnerable to an exploit called DirtyCow or
CVE-2016-5195

This exploit execute a COW (Copy On Write).
Skipping all the details (https://blogs.vmware.com/security/2016/12/dirty-truth-dirty-cow-cve-2016-5195.html) it's basically a race condition.

Using it gave us the permission to add a new user, we called it root, set a password and this
user receive the root rights.
