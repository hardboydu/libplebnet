#!./perl

# $Header: /home/cvs/386BSD/ports/lang/perl/t/op/read.t,v 1.1.1.1 1993/08/23 21:30:04 nate Exp $

print "1..4\n";


open(FOO,'op/read.t') || open(FOO,'./read.t') || open(FOO,'t/op/read.t') || die "Can't open op.read";
seek(FOO,4,0);
$got = read(FOO,$buf,4);
print "This is got ... $got\n";

print ($got == 4 ? "ok 1\n" : "not ok 1\n");
print ($buf eq "perl" ? "ok 2\n" : "not ok 2 :$buf:\n");

seek(FOO,20000,0);
$got = read(FOO,$buf,4);

print ($got == 0 ? "ok 3\n" : "not ok 3\n");
print ($buf eq "" ? "ok 4\n" : "not ok 4\n");
