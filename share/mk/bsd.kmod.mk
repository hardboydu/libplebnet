#	From: @(#)bsd.prog.mk	5.26 (Berkeley) 6/25/91
#	$Id: bsd.kmod.mk,v 1.19 1996/04/03 12:08:52 phk Exp $

.if exists(${.CURDIR}/../Makefile.inc)
.include "${.CURDIR}/../Makefile.inc"
.endif

.SUFFIXES: .out .o .c .cc .cxx .C .y .l .s .S

#
# Assume that we are in /usr/src/foo/bar, so /sys is
# ${.CURDIR}/../../sys.  We don't bother adding a .PATH since nothing
# actually lives in /sys directly.
#
CWARNFLAGS?= -W -Wreturn-type -Wcomment -Wredundant-decls -Wimplicit \
	-Wnested-externs -Wstrict-prototypes -Wmissing-prototypes \
	-Winline

CFLAGS+=${COPTS} -DKERNEL -DACTUALLY_LKM_NOT_KERNEL -I${.CURDIR}/../../sys \
	${CWARNFLAGS}

EXPORT_SYMS?= _${KMOD}

.if defined(VFS_LKM)
CFLAGS+= -DVFS_LKM -DMODVNOPS=${KMOD}vnops -I.
SRCS+=	vnode_if.h
CLEANFILES+=	vnode_if.h vnode_if.c
.endif

.if defined(PSEUDO_LKM)
CFLAGS+= -DPSEUDO_LKM
.endif

DPSRCS+= ${SRCS:M*.h}
OBJS+=  ${SRCS:N*.h:R:S/$/.o/g}

.if !defined(PROG)
PROG=	${KMOD}.o
.endif

${PROG}: ${DPSRCS} ${OBJS} ${DPADD} 
	${LD} -r ${LDFLAGS} -o tmp.o ${OBJS}
.if defined(EXPORT_SYMS)
	@rm -f symb.tmp
	@for i in ${EXPORT_SYMS} ; do echo $$i >> symb.tmp ; done
	symorder -c symb.tmp tmp.o
	@rm -f symb.tmp
.endif
	mv tmp.o ${.TARGET}

.if !defined(NOMAN)
.include <bsd.man.mk>
.if !defined(_MANPAGES) || empty(_MANPAGES)
MAN1=	${KMOD}.4
.endif

.elif !target(maninstall)
maninstall:
all-man:
.endif

_PROGSUBDIR: .USE
.if defined(SUBDIR) && !empty(SUBDIR)
	@for entry in ${SUBDIR}; do \
		(${ECHODIR} "===> $$entry"; \
		if test -d ${.CURDIR}/$${entry}.${MACHINE}; then \
			cd ${.CURDIR}/$${entry}.${MACHINE}; \
		else \
			cd ${.CURDIR}/$${entry}; \
		fi; \
		${MAKE} ${.TARGET:S/realinstall/install/:S/.depend/depend/}); \
	done
.endif

.MAIN: all
all: ${PROG} all-man _PROGSUBDIR

CLEANFILES+=${PROG} ${OBJS} 

.if !target(install)
.if !target(beforeinstall)
beforeinstall:
.endif
.if !target(afterinstall)
afterinstall:
.endif

realinstall: _PROGSUBDIR
	${INSTALL} ${COPY} -o ${KMODOWN} -g ${KMODGRP} -m ${KMODMODE} \
	    ${INSTALLFLAGS} ${PROG} ${DESTDIR}${KMODDIR}
.if defined(LINKS) && !empty(LINKS)
	@set ${LINKS}; \
	while test $$# -ge 2; do \
		l=${DESTDIR}$$1; \
		shift; \
		t=${DESTDIR}$$1; \
		shift; \
		${ECHO} $$t -\> $$l; \
		rm -f $$t; \
		ln ${LN_FLAGS} $$l $$t; \
	done; true
.endif

install: afterinstall
.if !defined(NOMAN)
afterinstall: realinstall maninstall
.else
afterinstall: realinstall
.endif
realinstall: beforeinstall
.endif

DISTRIBUTION?=	bin
.if !target(distribute)
distribute:
	cd ${.CURDIR} ; $(MAKE) install DESTDIR=${DISTDIR}/${DISTRIBUTION} SHARED=copies
.endif

.if !target(tags)
tags: ${SRCS} _PROGSUBDIR
.if defined(PROG)
	-cd ${.CURDIR}; ctags -f /dev/stdout ${.ALLSRC} | \
	    sed "s;\${.CURDIR}/;;" > tags
.endif
.endif


.if !target(load)
load:	${PROG}
	/sbin/modload -o ${KMOD} -e${KMOD} ${PROG}
.endif

.if !target(unload)
unload:	${PROG}
	/sbin/modunload -n ${KMOD}
.endif

KERN=	${.CURDIR}/../../sys/kern

vnode_if.h:	${KERN}/vnode_if.sh ${KERN}/vnode_if.src
	sh ${KERN}/vnode_if.sh ${KERN}/vnode_if.src

./vnode_if.h:	vnode_if.h

_DEPSUBDIR=	_PROGSUBDIR
_SUBDIRUSE:	_PROGSUBDIR
.include <bsd.obj.mk>
.include <bsd.dep.mk>

