:loop
/\\$/N
s/\\\n */ /g
t loop

s!\.o:!.lo:!
s! @BFD_H@!!g
s!@INCDIR@!$(INCDIR)!g
s!@SRCDIR@/../opcodes!$(srcdir)/../opcodes!g
s!@SRCDIR@/!!g
s! hosts/[^ ]*\.h! !g
s! sysdep.h!!g
s! \.\./bfd/sysdep.h!!g
s! libbfd.h!!g
s! config.h!!g
s! \$(INCDIR)/fopen-[^ ]*\.h!!g
s! \$(INCDIR)/ansidecl\.h!!g
s! \$(INCDIR)/symcat\.h!!g

s/\\\n */ /g

s/ *$//
s/  */ /g
s/ *:/:/g
/:$/d

s/\(.\{50\}[^ ]*\) /\1 \\\
  /g
