#	from: @(#)bsd.doc.mk	5.3 (Berkeley) 1/2/91
#	$Id: bsd.doc.mk,v 1.16 1995/01/17 21:36:06 ache Exp $

PRINTER?=	ps

BIB?=		bib
EQN?=		eqn -T${PRINTER}
GREMLIN?=	grn
GRIND?=		vgrind -f
INDXBIB?=	indxbib
PIC?=		pic
REFER?=		refer
.if ${PRINTER} == "ascii"
ROFF?=          groff -mtty-char ${TRFLAGS} ${MACROS} -o${PAGES}
.else
ROFF?=		groff ${TRFLAGS} ${MACROS} -o${PAGES}
.endif
SOELIM?=	soelim
TBL?=		tbl

DOC?=		paper

TRFLAGS+=	-T${PRINTER}
.if defined(USE_EQN)
TRFLAGS+=	-e
.endif
.if defined(USE_TBL)
TRFLAGS+=	-t
.endif
.if defined(USE_PIC)
TRFLAGS+=	-p
.endif
.if defined(USE_SOELIM)
TRFLAGS+=	-s
.endif
.if defined(USE_REFER)
TRFALGS+=	-R
.endif

PAGES?=		1-

# Compatibility mode flag for groff.  Use this when formatting documents with
# Berkeley me macros.
COMPAT?=	-C

.PATH: ${.CURDIR} ${SRCDIR}

.MAIN:	all
all:	${DOC}.${PRINTER}

.if !target(print)
print: ${DOC}.${PRINTER}
	lpr -P${PRINTER} ${DOC}.${PRINTER}
.endif

.if !target(obj)
.if defined(NOOBJ)
obj:
.else
obj:
	@cd ${.CURDIR}; rm -f obj; \
	here=`pwd`; dest=/usr/obj`echo $$here | sed 's,^/usr/src,,'`; \
	${ECHO} "$$here -> $$dest"; ln -s $$dest obj; \
	if test -d /usr/obj -a ! -d $$dest; then \
		mkdir -p $$dest; \
	else \
		true; \
	fi;
.endif
.endif

clean:
	rm -f ${DOC}.${PRINTER} ${DOC}.ps ${DOC}.ascii \
		[eE]rrs mklog ${CLEANFILES}

cleandir: clean
	cd ${.CURDIR}; rm -rf obj

FILES?=	${SRCS}
realinstall:
	@if [ ! -d "${DESTDIR}${BINDIR}/${VOLUME}" ]; then \
                /bin/rm -f ${DESTDIR}${BINDIR}/${VOLUME}  ; \
                mkdir -p ${DESTDIR}${BINDIR}/${VOLUME}  ; \
                chown root.wheel ${DESTDIR}${BINDIR}/${VOLUME}  ; \
                chmod 755 ${DESTDIR}${BINDIR}/${VOLUME}  ; \
        else \
                true ; \
        fi
	${INSTALL} ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${DOC}.${PRINTER} ${DESTDIR}${BINDIR}/${VOLUME}

install:	beforeinstall realinstall afterinstall

.if !target(beforeinstall)
beforeinstall:

.endif
.if !target(afterinstall)
afterinstall:

.endif

DISTRIBUTION?=	doc
.if !target(distribute)
distribute:
	cd ${.CURDIR} ; $(MAKE) install DESTDIR=${RELEASEDIR}/${DISTRIBUTION} SHARED=copies
.endif

spell: ${SRCS}
	(cd ${.CURDIR};  spell ${SRCS} ) | sort | \
		comm -23 - ${.CURDIR}/spell.ok > ${DOC}.spell

BINDIR?=	/usr/share/doc
BINMODE=        444

SRCDIR?=	${.CURDIR}

.if !target(${DOC}.${PRINTER})
CLEANFILES+=	${DOC}.${PRINTER}+

${DOC}.${PRINTER}:	${SRCS}
	(cd ${SRCDIR}; ${ROFF} ${.ALLSRC}) > ${.TARGET}+
	rm -f ${.TARGET}
	mv ${.TARGET}+ ${.TARGET}
.endif

.if !target(depend)
depend:

.endif

