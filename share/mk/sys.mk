#	from: @(#)sys.mk	8.2 (Berkeley) 3/21/94
#	$Id: sys.mk,v 1.8 1994/11/07 04:18:04 phk Exp $

unix		?=	We run FreeBSD, not UNIX.

.SUFFIXES:	.out .a .ln .o .c .cc .cxx .C .F .f .e .r .y .l .S .s .cl .p .h 

.LIBS:		.a

X11BASE		?=	/usr/X11R6

AR		?=	ar
ARFLAGS		?=	rl
RANLIB		?=	ranlib

AS		?=	as
AFLAGS		?=

CC		?=	cc

.if ${MACHINE} == "sparc"
CFLAGS		?=	-O4
.else
CFLAGS		?=	-O2
.endif

CXX		?=	c++
CXXFLAGS	?=	${CXXINCLUDES} ${CFLAGS}

CPP		?=	cpp

.if ${.MAKEFLAGS:M-s} == ""
ECHO		?=	echo
ECHODIR		?=	echo
.else
ECHO		?=	true
.if ${.MAKEFLAGS:M-s} == "-s"
ECHODIR		?=	echo
.else
ECHODIR		?=	true
.endif
.endif

FC		?=	f77
FFLAGS		?=	-O
EFLAGS		?=

INSTALL		?=	install

LEX		?=	lex
LFLAGS		?=

LD		?=	ld
LDFLAGS		?=

LINT		?=	lint
LINTFLAGS	?=	-chapbx

MAKE		?=	make

PC		?=	pc
PFLAGS		?=

RC		?=	f77
RFLAGS		?=

SHELL		?=	sh

YACC		?=	yacc
YFLAGS		?=	-d

# This rule currently causes both make from 1.x and 2.x to have problems,
# and is not being used so disable it for now.
#.c:
#	${CC} ${CFLAGS} ${.IMPSRC} -o ${.TARGET}

.c.o:
	${CC} ${CFLAGS} -c ${.IMPSRC}

.cc.o .cxx.o .C.o:
	${CXX} ${CXXFLAGS} -c ${.IMPSRC}

.p.o:
	${PC} ${PFLAGS} -c ${.IMPSRC}

.e.o .r.o .F.o .f.o:
	${FC} ${RFLAGS} ${EFLAGS} ${FFLAGS} -c ${.IMPSRC}

.S.o:
	${CC} ${CFLAGS} -c ${.IMPSRC}

.s.o:
	${AS} ${AFLAGS} -o ${.TARGET} ${.IMPSRC}

.y.o:
	${YACC} ${YFLAGS} ${.IMPSRC}
	${CC} ${CFLAGS} -c y.tab.c -o ${.TARGET}
	rm -f y.tab.c

.l.o:
	${LEX} ${LFLAGS} ${.IMPSRC}
	${CC} ${CFLAGS} -c lex.yy.c -o ${.TARGET}
	rm -f lex.yy.c

.y.c:
	${YACC} ${YFLAGS} ${.IMPSRC}
	mv y.tab.c ${.TARGET}

.l.c:
	${LEX} ${LFLAGS} ${.IMPSRC}
	mv lex.yy.c ${.TARGET}

.s.out .c.out .o.out:
	${CC} ${CFLAGS} ${.IMPSRC} ${LDLIBS} -o ${.TARGET}

.f.out .F.out .r.out .e.out:
	${FC} ${EFLAGS} ${RFLAGS} ${FFLAGS} ${.IMPSRC} \
	    ${LDLIBS} -o ${.TARGET}
	rm -f ${.PREFIX}.o

.y.out:
	${YACC} ${YFLAGS} ${.IMPSRC}
	${CC} ${CFLAGS} y.tab.c ${LDLIBS} -ly -o ${.TARGET}
	rm -f y.tab.c

.l.out:
	${LEX} ${LFLAGS} ${.IMPSRC}
	${CC} ${CFLAGS} lex.yy.c ${LDLIBS} -ll -o ${.TARGET}
	rm -f lex.yy.c

.include <bsd.own.mk>

.if exists(/etc/make.conf)
.include </etc/make.conf>
.endif
