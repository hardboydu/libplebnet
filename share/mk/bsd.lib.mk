#	from: @(#)bsd.lib.mk	5.26 (Berkeley) 5/2/91
# $FreeBSD$
#

.include <bsd.init.mk>

.if exists(${.CURDIR}/shlib_version)
SHLIB_MAJOR != . ${.CURDIR}/shlib_version ; echo $$major
.if ${OBJFORMAT} == aout
SHLIB_MINOR != . ${.CURDIR}/shlib_version ; echo $$minor
.endif
.endif

# Set up the variables controlling shared libraries.  After this section,
# SHLIB_NAME will be defined only if we are to create a shared library.
# SHLIB_LINK will be defined only if we are to create a link to it.
# INSTALL_PIC_ARCHIVE will be defined only if we are to create a PIC archive.
.if defined(NOPIC)
.undef SHLIB_NAME
.undef INSTALL_PIC_ARCHIVE
.else
.if ${OBJFORMAT} == elf
.if !defined(SHLIB_NAME) && defined(SHLIB_MAJOR)
SHLIB_NAME=	lib${LIB}.so.${SHLIB_MAJOR}
SHLIB_LINK?=	lib${LIB}.so
.endif
SONAME?=	${SHLIB_NAME}
.else
.if defined(SHLIB_MAJOR) && defined(SHLIB_MINOR)
SHLIB_NAME?=	lib${LIB}.so.${SHLIB_MAJOR}.${SHLIB_MINOR}
.endif
.endif
.endif

.if defined(DEBUG_FLAGS)
CFLAGS+= ${DEBUG_FLAGS}
.endif

.if !defined(DEBUG_FLAGS)
STRIP?=	-s
.endif

.if ${OBJFORMAT} != aout || make(checkdpadd) || defined(NEED_LIBNAMES)
.include <bsd.libnames.mk>
.endif

# prefer .s to a .c, add .po, remove stuff not used in the BSD libraries
# .So used for PIC object files
.SUFFIXES:
.SUFFIXES: .out .o .po .So .S .s .asm .c .cc .cpp .cxx .m .C .f .y .l .ln

.c.ln:
	${LINT} ${LINTOBJFLAGS} ${CFLAGS:M-[DIU]*} ${.IMPSRC} || \
	    touch ${.TARGET}

.cc.ln .C.ln .cpp.ln .cxx.ln:
	${LINT} ${LINTOBJFLAGS} ${CXXFLAGS:M-[DIU]*} ${.IMPSRC} || \
	    touch ${.TARGET}

.c.o:
	${CC} ${CFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.c.po:
	${CC} -pg ${CFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} -o ${.TARGET}.tmp -X -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.c.So:
	${CC} ${PICFLAG} -DPIC ${CFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} ${LDFLAGS} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.cc.o .C.o .cpp.o .cxx.o:
	${CXX} ${CXXFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.cc.po .C.po .cpp.po .cxx.po:
	${CXX} -pg ${CXXFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} -o ${.TARGET}.tmp -X -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.cc.So .C.So .cpp.So .cxx.So:
	${CXX} ${PICFLAG} -DPIC ${CXXFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} ${LDFLAGS} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.f.o:
	${FC} ${FFLAGS} -o ${.TARGET} -c ${.IMPSRC} 
	@${LD} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.f.po:
	${FC} -pg ${FFLAGS} -o ${.TARGET} -c ${.IMPSRC} 
	@${LD} -o ${.TARGET}.tmp -X -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.f.So:
	${FC} ${PICFLAG} -DPIC ${FFLAGS} -o ${.TARGET} -c ${.IMPSRC}
	@${LD} ${LDFLAGS} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.m.o:
	${OBJC} ${OBJCFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.m.po:
	${OBJC} ${OBJCFLAGS} -pg -c ${.IMPSRC} -o ${.TARGET}
	@${LD} -o ${.TARGET}.tmp -X -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.m.So:
	${OBJC} ${PICFLAG} -DPIC ${OBJCFLAGS} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} ${LDFLAGS} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.s.o .asm.o:
	${CC} -x assembler-with-cpp ${CFLAGS:M-[BID]*} ${AINC} -c \
	    ${.IMPSRC} -o ${.TARGET}
	@${LD} ${LDFLAGS} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.s.po .asm.po:
	${CC} -x assembler-with-cpp -DPROF ${CFLAGS:M-[BID]*} ${AINC} -c \
	    ${.IMPSRC} -o ${.TARGET}
	@${LD} ${LDFLAGS} -o ${.TARGET}.tmp -X -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.s.So .asm.So:
	${CC} -x assembler-with-cpp ${PICFLAG} -DPIC ${CFLAGS:M-[BID]*} \
	    ${AINC} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.S.o:
	${CC} ${CFLAGS:M-[BID]*} ${AINC} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} ${LDFLAGS} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.S.po:
	${CC} -DPROF ${CFLAGS:M-[BID]*} ${AINC} -c ${.IMPSRC} -o ${.TARGET}
	@${LD} ${LDFLAGS} -o ${.TARGET}.tmp -X -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.S.So:
	${CC} ${PICFLAG} -DPIC ${CFLAGS:M-[BID]*} ${AINC} -c ${.IMPSRC} \
	    -o ${.TARGET}
	@${LD} -o ${.TARGET}.tmp -x -r ${.TARGET}
	@mv ${.TARGET}.tmp ${.TARGET}

.if !defined(INTERNALLIB) || defined(INTERNALSTATICLIB)
.if !defined(NOPROFILE) && !defined(INTERNALLIB)
_LIBS=lib${LIB}.a lib${LIB}_p.a
.else
_LIBS=lib${LIB}.a
.endif
.endif

.if defined(SHLIB_NAME)
_LIBS+=${SHLIB_NAME}
.endif
.if defined(INSTALL_PIC_ARCHIVE)
_LIBS+=lib${LIB}_pic.a
.endif

.if !defined(PICFLAG)
.if ${MACHINE_ARCH} == "sparc64"
PICFLAG=-fPIC
.else
PICFLAG=-fpic
.endif
.endif

LINTOBJS+= ${SRCS:M*.c:C/\..+$/.ln/}

.if defined(WANT_LINT) && defined(LIB) && defined(LINTOBJS) && !empty(LINTOBJS)
LINTLIB=llib-l${LIB}.ln
_LIBS+=${LINTLIB}
.endif

all: objwarn ${_LIBS}

.if !defined(NOMAN)
all: _manpages
.endif

OBJS+=	${SRCS:N*.h:R:S/$/.o/g}

lib${LIB}.a:: ${OBJS} ${STATICOBJS}
	@${ECHO} building static ${LIB} library
	@rm -f lib${LIB}.a
	@${AR} cq lib${LIB}.a `lorder ${OBJS} ${STATICOBJS} | tsort -q` ${ARADD}
	${RANLIB} lib${LIB}.a

POBJS+=	${OBJS:.o=.po} ${STATICOBJS:.o=.po}
.if !defined(NOPROFILE)
lib${LIB}_p.a:: ${POBJS}
	@${ECHO} building profiled ${LIB} library
	@rm -f lib${LIB}_p.a
	@${AR} cq lib${LIB}_p.a `lorder ${POBJS} | tsort -q` ${ARADD}
	${RANLIB} lib${LIB}_p.a
.endif

SOBJS+= ${OBJS:.o=.So}

.if defined(SHLIB_NAME)
${SHLIB_NAME}: ${SOBJS}
	@${ECHO} building shared library ${SHLIB_NAME}
	@rm -f ${SHLIB_NAME} ${SHLIB_LINK}
.if defined(SHLIB_LINK)
	@ln -sf ${SHLIB_NAME} ${SHLIB_LINK}
.endif
.if ${OBJFORMAT} == aout
	@${CC} -shared -Wl,-x,-assert,pure-text \
	    -o ${SHLIB_NAME} \
	    `lorder ${SOBJS} | tsort -q` ${LDADD}
.else
	@${CC} ${LDFLAGS} -shared -Wl,-x \
	    -o ${SHLIB_NAME} -Wl,-soname,${SONAME} \
	    `lorder ${SOBJS} | tsort -q` ${LDADD}
.endif
.endif

.if defined(INSTALL_PIC_ARCHIVE)
lib${LIB}_pic.a:: ${SOBJS}
	@${ECHO} building special pic ${LIB} library
	@rm -f lib${LIB}_pic.a
	@${AR} cq lib${LIB}_pic.a ${SOBJS} ${ARADD}
	${RANLIB} lib${LIB}_pic.a
.endif

.if defined(WANT_LINT) && defined(LIB) && defined(LINTOBJS) && !empty(LINTOBJS)
${LINTLIB}: ${LINTOBJS}
	@${ECHO} building lint library ${LINTLIB}
	@rm -f ${LINTLIB}
	${LINT} ${LINTLIBFLAGS} ${CFLAGS:M-[DIU]*} ${.ALLSRC}
.endif

.if !target(clean)
clean:
	rm -f a.out ${OBJS} ${STATICOBJS} ${OBJS:S/$/.tmp/} ${CLEANFILES}
	rm -f lib${LIB}.a
	rm -f ${POBJS} ${POBJS:S/$/.tmp/} lib${LIB}_p.a
	rm -f ${SOBJS} ${SOBJS:.So=.so} ${SOBJS:S/$/.tmp/} \
	    ${SHLIB_NAME} ${SHLIB_LINK} \
	    lib${LIB}.so.* lib${LIB}.so lib${LIB}_pic.a
	rm -f ${LINTOBJS} ${LINTLIB}
.if defined(CLEANDIRS) && !empty(CLEANDIRS)
	rm -rf ${CLEANDIRS}
.endif
.endif

_EXTRADEPEND:
	@TMP=_depend$$$$; \
	sed -e 's/^\([^\.]*\).o[ ]*:/\1.o \1.po \1.So:/' < ${DEPENDFILE} \
	    > $$TMP; \
	mv $$TMP ${DEPENDFILE}
.if !defined(NOEXTRADEPEND) && defined(SHLIB_NAME)
.if ${OBJFORMAT} == aout
	echo ${SHLIB_NAME}: \
	    `${CC} -shared -Wl,-f ${LDADD}` \
	    >> ${DEPENDFILE}
.else
.if defined(DPADD) && !empty(DPADD)
	echo ${SHLIB_NAME}: ${DPADD} >> ${DEPENDFILE}
.endif
.endif
.endif

.if !target(install)

.if defined(PRECIOUSLIB) && !defined(NOFSCHG)
SHLINSTALLFLAGS+= -fschg
.endif

_INSTALLFLAGS:=	${INSTALLFLAGS}
.for ie in ${INSTALLFLAGS_EDIT}
_INSTALLFLAGS:=	${_INSTALLFLAGS${ie}}
.endfor
_SHLINSTALLFLAGS:=	${SHLINSTALLFLAGS}
.for ie in ${INSTALLFLAGS_EDIT}
_SHLINSTALLFLAGS:=	${_SHLINSTALLFLAGS${ie}}
.endfor

realinstall: _libinstall
_libinstall:
.if !defined(INTERNALLIB)
	${INSTALL} -C -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	    ${_INSTALLFLAGS} lib${LIB}.a ${DESTDIR}${LIBDIR}
.if !defined(NOPROFILE)
	${INSTALL} -C -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	    ${_INSTALLFLAGS} lib${LIB}_p.a ${DESTDIR}${LIBDIR}
.endif
.endif
.if defined(SHLIB_NAME)
	${INSTALL} ${COPY} ${STRIP} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	    ${_INSTALLFLAGS} ${_SHLINSTALLFLAGS} \
	    ${SHLIB_NAME} ${DESTDIR}${SHLIBDIR}
.if defined(SHLIB_LINK)
	ln -sf ${SHLIB_NAME} ${DESTDIR}${SHLIBDIR}/${SHLIB_LINK}
.endif
.endif
.if defined(INSTALL_PIC_ARCHIVE)
	${INSTALL} ${COPY} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	    ${_INSTALLFLAGS} lib${LIB}_pic.a ${DESTDIR}${LIBDIR}
.endif
.if defined(WANT_LINT) && defined(LIB) && defined(LINTOBJS) && !empty(LINTOBJS)
	${INSTALL} ${COPY} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	    ${_INSTALLFLAGS} ${LINTLIB} ${DESTDIR}${LINTLIBDIR}
.endif

realinstall:
.if defined(LINKS) && !empty(LINKS)
	@set ${LINKS}; \
	while test $$# -ge 2; do \
		l=${DESTDIR}$$1; \
		shift; \
		t=${DESTDIR}$$1; \
		shift; \
		${ECHO} $$t -\> $$l; \
		ln -f $$l $$t; \
	done; true
.endif
.if defined(SYMLINKS) && !empty(SYMLINKS)
	@set ${SYMLINKS}; \
	while test $$# -ge 2; do \
		l=$$1; \
		shift; \
		t=${DESTDIR}$$1; \
		shift; \
		${ECHO} $$t -\> $$l; \
		ln -fs $$l $$t; \
	done; true
.endif

realinstall: _incsinstall

.if !defined(NOMAN)
realinstall: _maninstall
.endif

.endif

.if !target(lint)
lint: ${SRCS:M*.c}
	${LINT} ${LINTOBJFLAGS} ${CFLAGS:M-[DIU]*} ${.ALLSRC}
.endif

.include <bsd.incs.mk>

.if !defined(NOMAN)
.include <bsd.man.mk>
.endif

.include <bsd.dep.mk>

.if !exists(${.OBJDIR}/${DEPENDFILE})
${OBJS} ${STATICOBJS} ${POBJS} ${SOBJS}: ${SRCS:M*.h}
.endif

.include <bsd.obj.mk>

.include <bsd.sys.mk>
