# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Win32-SysPrivilege.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 1;
BEGIN { use_ok('Win32::SysPrivilege') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
print "Sorry, Some bugs in it. I'll fix it these days. use Ctrl-C to interupt it.\n";
use Win32::SysPrivilege;
Win32::SysPrivilege::CreateSystemProcess("cmd.exe");
exit;
