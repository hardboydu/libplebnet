#
#	$Id: Makefile,v 1.25 1994/10/08 15:08:14 ache Exp $
#
# Make command line options:
#	-DCLOBBER will remove /usr/include and MOST of /usr/lib 
#	-DMAKE_LOCAL to add ./local to the SUBDIR list
#	-DMAKE_PORTS to add ./ports to the SUBDIR list
# XXX1	-DMAKE_KERBEROS to build KerberosIV
#	-DMAKE_EBONES to build eBones (KerberosIV)
#
#	-DNOCLEANDIR run ${MAKE} clean, instead of ${MAKE} cleandir
#	-DNOCRYPT will prevent building of crypt versions
#	-DNOLKM do not build loadable kernel modules
#	-DNOOBJDIR do not run ``${MAKE} obj''
#	-DNOPROFILE do not build profiled libraries
#	-DNOSECURE do not go into secure subdir
#
#
# XXX1	The kerberos IV off the 4.4-Lite tape (src/kerberosIV)
#	will not build successfully yet.  MAKE_KERBEROS should not be
#	defined.

# Put initial settings here.
SUBDIR=

.if exists(bin)
SUBDIR+= bin
.endif
.if exists(contrib)
SUBDIR+= contrib
.endif
.if exists(etc)
# XXX until etc vs release conversion is done
# SUBDIR+= etc
.endif
.if exists(games)
SUBDIR+= games
.endif
.if exists(gnu)
SUBDIR+= gnu
.endif
.if exists(include)
SUBDIR+= include
.endif
.if exists(lib)
SUBDIR+= lib
.endif
.if exists(kerberosIV) && !defined(NOCRYPT) && defined(MAKE_KERBEROS)
SUBDIR+= kerberosIV
.endif
.if exists(eBones) && !defined(NOCRYPT) && defined(MAKE_EBONES)
SUBDIR+= eBones
.endif
.if exists(libexec)
SUBDIR+= libexec
.endif
.if exists(sbin)
SUBDIR+= sbin
.endif
.if exists(share)
SUBDIR+= share
.endif
.if exists(sys)
SUBDIR+= sys
.endif
.if exists(usr.bin)
SUBDIR+= usr.bin
.endif
.if exists(usr.sbin)
SUBDIR+= usr.sbin
.endif
.if exists(secure) && !defined(NOCRYPT) && !defined(NOSECURE)
SUBDIR+= secure
.endif
.if exists(lkm) && !defined(NOLKM)
SUBDIR+= lkm
.endif

# These are last, since it is nice to at least get the base system
# rebuilt before you do them.
.if defined(MAKE_LOCAL) & exists(local) & exists(local/Makefile)
SUBDIR+= local
.endif
.if defined(MAKE_PORTS) & exists(ports) & exists(ports/Makefile)
SUBDIR+= ports
.endif

# Handle the -DNOOBJDIR and -DNOCLEANDIR
.if defined(NOOBJDIR)
OBJDIR=
.else
OBJDIR=		obj
.endif
.if defined(NOCLEANDIR)
CLEANDIR=	clean
.else 
CLEANDIR=	cleandir
.endif

world:	hierarchy cleandist mk includes libraries tools
	@echo "--------------------------------------------------------------"
	@echo " Rebuilding ${DESTDIR} The whole thing"
	@echo "--------------------------------------------------------------"
	@echo
	${MAKE} depend all install
	cd ${.CURDIR}/share/man &&		${MAKE} makedb


hierarchy:
	@echo "--------------------------------------------------------------"
	@echo " Making hierarchy"
	@echo "--------------------------------------------------------------"
	cd ${.CURDIR}/release &&		${MAKE} hierarchy

update:
.if defined(SUP_UPDATE)
	@echo "--------------------------------------------------------------"
	@echo "Running sup"
	@echo "--------------------------------------------------------------"
	@sup -v ${SUPFILE}
.endif
.if defined(CVS_UPDATE)
	@echo "--------------------------------------------------------------"
	@echo "Updating /usr/src from cvs repository" ${CVSROOT}
	@echo "--------------------------------------------------------------"
	cd ${.CURDIR} &&  cvs update -P -d
.endif

cleandist:
.if !defined(NOCLEANDIR)
	@echo "--------------------------------------------------------------"
	@echo " Cleaning up the source tree, and rebuilding the obj tree"
	@echo "--------------------------------------------------------------"
	@echo
	here=`pwd`; dest=/usr/obj`echo $$here | sed 's,^/usr/src,,'`; \
	if test -d /usr/obj -a ! -d $$dest; then \
		mkdir -p $$dest; \
	else \
		true; \
	fi; \
	cd $$dest && rm -rf ${SUBDIR}
	find . -name obj | xargs rm -rf
.if defined(MAKE_LOCAL) & exists(local) & exists(local/Makefile)
	# The cd is done as local may well be a symbolic link
	-cd local && find . -name obj | xargs rm -rf
.endif
.if defined(MAKE_PORTS) & exists(ports) & exists(ports/Makefile)
	# The cd is done as local may well be a symbolic link
	-cd ports && find . -name obj | xargs rm -rf
.endif
	${MAKE} cleandir
	${MAKE} obj
.endif

mk:
	@echo "--------------------------------------------------------------"
	@echo " Rebuilding ${DESTDIR}/usr/share/mk"
	@echo "--------------------------------------------------------------"
	cd ${.CURDIR}/share/mk &&		${MAKE} install

includes:
	@echo "--------------------------------------------------------------"
	@echo " Rebuilding ${DESTDIR}/usr/include"
	@echo "--------------------------------------------------------------"
	@echo
.if defined(CLOBBER)
	rm -rf ${DESTDIR}/usr/include
	mkdir ${DESTDIR}/usr/include
	chown ${BINOWN}.${BINGRP} ${DESTDIR}/usr/include
	chmod 755 ${DESTDIR}/usr/include
.endif
	cd ${.CURDIR}/include &&		${MAKE} install
	cd ${.CURDIR}/gnu/lib/libreadline &&	${MAKE} beforeinstall
	cd ${.CURDIR}/gnu/lib/libg++ &&         ${MAKE} beforeinstall
	cd ${.CURDIR}/gnu/lib/libdialog &&      ${MAKE} beforeinstall
.if exists(kerberosIV) && !defined(NOCRYPT) && defined(MAKE_KERBEROS)
	cd ${.CURDIR}/kerberosIV/include &&	${MAKE} install
.endif
.if exists(eBones) && !defined(NOCRYPT) && defined(MAKE_EBONES)
	cd ${.CURDIR}/eBones/include &&		${MAKE} beforeinstall
.endif
	cd ${.CURDIR}/lib/libc &&		${MAKE} beforeinstall
	cd ${.CURDIR}/lib/libcurses &&		${MAKE} beforeinstall
	cd ${.CURDIR}/lib/libedit &&		${MAKE} beforeinstall
	cd ${.CURDIR}/lib/libmd &&		${MAKE} beforeinstall
	cd ${.CURDIR}/lib/libmytinfo &&		${MAKE}	beforeinstall
	cd ${.CURDIR}/lib/libncurses &&		${MAKE}	beforeinstall
.if defined(WANT_MSUN)
	cd ${.CURDIR}/lib/msun &&		${MAKE} beforeinstall
.endif
	cd ${.CURDIR}/lib/librpcsvc &&		${MAKE} beforeinstall
	cd ${.CURDIR}/lib/libskey &&		${MAKE} beforeinstall

libraries:
	@echo "--------------------------------------------------------------"
	@echo " Rebuilding ${DESTDIR}/usr/lib"
	@echo "--------------------------------------------------------------"
	@echo
.if defined(CLOBBER)
	find ${DESTDIR}/usr/lib \! -name '*.s[ao].*' -a \! -type d | \
		xargs rm -rf
.endif
	cd ${.CURDIR}/gnu/lib && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
	cd ${.CURDIR}/gnu/usr.bin/cc/libgcc && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
.if exists(secure) && !defined(NOCRYPT) && !defined(NOSECURE)
	cd ${.CURDIR}/secure/lib && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
.endif
.if exists(lib)
	cd ${.CURDIR}/lib && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
.endif
	cd ${.CURDIR}/usr.bin/lex/lib && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
.if exists(kerberosIV) && !defined(NOCRYPT) && defined(MAKE_KERBEROS)
	cd ${.CURDIR}/kerberosIV/acl && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
	cd ${.CURDIR}/kerberosIV/des && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
	cd ${.CURDIR}/kerberosIV/kdb && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
	cd ${.CURDIR}/kerberosIV/krb && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
.endif
.if exists(eBones) && !defined(NOCRYPT) && defined(MAKE_EBONES)
	cd ${.CURDIR}/eBones/des && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
	cd ${.CURDIR}/eBones/acl && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
	cd ${.CURDIR}/eBones/kdb && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
	cd ${.CURDIR}/eBones/krb && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
.endif

tools:
	@echo "--------------------------------------------------------------"
	@echo " Rebuilding ${DESTDIR} Compiler and Make"
	@echo "--------------------------------------------------------------"
	@echo
	cd ${.CURDIR}/gnu/usr.bin/cc && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}
	cd ${.CURDIR}/usr.bin/make && \
		${MAKE} depend all install ${CLEANDIR} ${OBJDIR}

.include <bsd.subdir.mk>
