#-*- mode: Fundamental; tab-width: 4; -*-
#
#	bsd.port.mk - 940820 Jordan K. Hubbard.
#	This file is in the public domain.
#
# $Id: bsd.port.mk,v 1.142 1995/04/18 08:24:18 asami Exp $
#
# Please view me with 4 column tabs!


# Supported Variables and their behaviors:
#
# Variables that typically apply to all ports:
# 
# PORTSDIR		- The root of the ports tree (default: /usr/ports).
# DISTDIR 		- Where to get gzip'd, tarballed copies of original sources
#				  (default: ${PORTSDIR}/distfiles).
# PREFIX		- Where to install things in general (default: /usr/local).
# MASTER_SITES	- Primary location(s) for distribution files if not found
#				  locally (default:
#				   ftp://ftp.freebsd.org/pub/FreeBSD/ports/distfiles)
# PATCH_SITES	- Primary location(s) for distributed patch files
#				  (see PATCHFILES below) if not found locally (default:
#				   ftp://ftp.freebsd.org/pub/FreeBSD/ports/distfiles)
#
# MASTER_SITE_OVERRIDE - If set, override the MASTER_SITES setting with this
#				  value.
# MASTER_SITE_FREEBSD - If set, only use the FreeBSD master repository for
#				  MASTER_SITES.
# PACKAGES		- A top level directory where all packages go (rather than
#				  going locally to each port). (default: ${PORTSDIR}/packages).
# GMAKE			- Set to path of GNU make if not in $PATH (default: gmake).
# XMKMF			- Set to path of `xmkmf' if not in $PATH (default: xmkmf -a ).
# MAINTAINER	- The e-mail address of the contact person for this port
#				  (default: ports@FreeBSD.ORG).
# CATEGORIES	- A list of descriptive categories into which this port falls
#				  (default: orphans).
# KEYWORDS		- A list of descriptive keywords that might index well for this
#				  port (default: orphans).
#
# Variables that typically apply to an individual port.  Non-Boolean
# variables without defaults are *mandatory*.
# 
#
# WRKDIR 		- A temporary working directory that gets *clobbered* on clean
#				  (default: ${.CURDIR}/work).
# WRKSRC		- A subdirectory of ${WRKDIR} where the distribution actually
#				  unpacks to.  (Default: ${WRKDIR}/${DISTNAME} unless
#				  NO_WRKSUBDIR is set, in which case simply ${WRKDIR}).
# DISTNAME		- Name of port or distribution.
# DISTFILES		- Name(s) of archive file(s) containing distribution
#				  (default: ${DISTDIR}/${DISTNAME}${EXTRACT_SUFX}).
# PATCHFILES	- Name(s) of additional files that contain distributed
#				  patches (default: none).  make will look for them at
#				  PATCH_SITES (see above).  They will automatically be
#				  uncompressed before patching if the names end with
#				  ".gz" or ".Z".
# PKGNAME		- Name of the package file to create if the DISTNAME 
#				  isn't really relevant for the port/package
#				  (default: ${DISTNAME}).
# EXTRACT_ONLY	- If defined, a subset of ${DISTFILES} you want to
#			  	  actually extract.
# PATCHDIR 		- A directory containing any additional patches you made
#				  to port this software to FreeBSD (default:
#				  ${.CURDIR}/patches)
# SCRIPTDIR 	- A directory containing any auxiliary scripts
#				  (default: ${.CURDIR}/scripts)
# FILESDIR 		- A directory containing any miscellaneous additional files.
#				  (default: ${.CURDIR}/files)
# PKGDIR 		- A direction containing any package creation files.
#				  (default: ${.CURDIR}/pkg)
# PKG_DBDIR		- Where package installation is recorded (default: /var/db/pkg)
#
# NO_EXTRACT	- Use a dummy (do-nothing) extract target.
# NO_CONFIGURE	- Use a dummy (do-nothing) configure target.
# NO_BUILD		- Use a dummy (do-nothing) build target.
# NO_PACKAGE	- Use a dummy (do-nothing) package target.
# NO_INSTALL	- Use a dummy (do-nothing) install target.
# NO_WRKSUBDIR	- Assume port unpacks directly into ${WRKDIR}.
# NO_WRKDIR		- There's no work directory at all; port does this someplace
#				  else.
# NO_DEPENDS	- Don't verify build of dependencies.
# USE_GMAKE		- Says that the port uses gmake.
# USE_IMAKE		- Says that the port uses imake.
# USE_X11		- Says that the port uses X11.
# NO_INSTALL_MANPAGES - For imake ports that don't like the install.man
#						target.
# HAS_CONFIGURE	- Says that the port has its own configure script.
# GNU_CONFIGURE	- Set if you are using GNU configure (optional).
# CONFIGURE_SCRIPT - Name of configure script, defaults to 'configure'.
# CONFIGURE_ARGS - Pass these args to configure, if ${HAS_CONFIGURE} set.
# IS_INTERACTIVE - Set this if your port needs to interact with the user
#				  during a build.  User can then decide to skip this port by
#				  setting ${BATCH}, or compiling only the interactive ports
#				  by setting ${INTERACTIVE}.
# EXEC_DEPENDS	- A list of "prog:dir" pairs of other ports this
#				  package depends on.  "prog" is the name of an
#				  executable.  make will search your $PATH for it and go
#				  into "dir" to do a "make all install" if it's not found.
# LIB_DEPENDS	- A list of "lib:dir" pairs of other ports this package
#				  depends on.  "lib" is the name of a shared library.
#				  make will use "ldconfig -r" to search for the
#				  library.  Note that lib can be any regular expression,
#				  and you need two backslashes in front of dots (.) to
#				  supress its special meaning (e.g., use
#				  "foo\\.2\\.:${PORTSDIR}/utils/foo" to match "libfoo.2.*").
# DEPENDS		- A list of other ports this package depends on being
#				  made first.  Use this for things that don't fall into
#				  the above two categories.
# EXTRACT_CMD	- Command for extracting archive (default: tar).
# EXTRACT_SUFX	- Suffix for archive names (default: .tar.gz).
# EXTRACT_BEFORE_ARGS -
#				  Arguments to ${EXTRACT_CMD} before filename
#				  (default: -C ${WRKDIR} -xzf).
# EXTRACT_AFTER_ARGS -
#				  Arguments to ${EXTRACT_CMD} following filename
#				  (default: none).
#
# NCFTP			- Full path to ncftp command if not in $PATH (default: ncftp).
# NCFTPFLAGS    - Arguments to ${NCFTP} (default: -N).
#
#
# Default targets and their behaviors:
#
# fetch			- Retrieves ${DISTFILES} (and ${PATCHFILES} if defined)
#				  into ${DISTDIR} as necessary.
# fetch-list	- Show list of files that would be retrieved by fetch
# extract		- Unpacks ${DISTFILES} into ${WRKDIR}.
# patch			- Apply any provided patches to the source.
# configure		- Runs either GNU configure, one or more local configure
#				  scripts or nothing, depending on what's available.
# build			- Actually compile the sources.
# install		- Install the results of a build.
# reinstall		- Install the results of a build, ignoring "already installed"
#				  flag.
# package		- Create a package from an _installed_ port.
# describe		- Try to generate a one-line description for each port for
#				  use in INDEX files and the like.
# checksum		- Use files/md5 to ensure that your distfiles are valid
# makesum		- Generate files/md5 (only do this for your own ports!)
#
# Default sequence for "all" is:  fetch extract patch configure build

.if exists(${.CURDIR}/../Makefile.inc)
.include "${.CURDIR}/../Makefile.inc"
.endif

# These need to be absolute since we don't know how deep in the ports
# tree we are and thus can't go relative.  They can, of course, be overridden
# by individual Makefiles.
PORTSDIR?=		${DESTDIR}/usr/ports
X11BASE?=		/usr/X11R6
DISTDIR?=		${PORTSDIR}/distfiles
PACKAGES?=		${PORTSDIR}/packages
.if !defined(NO_WRKDIR)
WRKDIR?=		${.CURDIR}/work
.else
WRKDIR?=		${.CURDIR}
.endif
.if defined(NO_WRKSUBDIR)
WRKSRC?=		${WRKDIR}
.else
WRKSRC?=		${WRKDIR}/${DISTNAME}
.endif
PATCHDIR?=		${.CURDIR}/patches
SCRIPTDIR?=		${.CURDIR}/scripts
FILESDIR?=		${.CURDIR}/files
PKGDIR?=		${.CURDIR}/pkg
.if defined(USE_IMAKE) || defined(USE_X11)
PREFIX?=		${X11BASE}
.else
PREFIX?=		/usr/local
.endif
.if defined(USE_GMAKE)
EXEC_DEPENDS+=               gmake:${PORTSDIR}/devel/gmake
.endif

.if exists(${PORTSDIR}/../Makefile.inc)
.include "${PORTSDIR}/../Makefile.inc"
.endif


# Change these if you'd prefer to keep the cookies someplace else.
EXTRACT_COOKIE?=	${WRKDIR}/.extract_done
CONFIGURE_COOKIE?=	${WRKDIR}/.configure_done
INSTALL_COOKIE?=	${WRKDIR}/.install_done
BUILD_COOKIE?=		${WRKDIR}/.build_done
PATCH_COOKIE?=		${WRKDIR}/.patch_done

# How to do nothing.  Override if you, for some strange reason, would rather
# do something.
DO_NADA?=		echo -n

# Miscellaneous overridable commands:
GMAKE?=			gmake
XMKMF?=			xmkmf -a
MD5?=			/sbin/md5
MD5_FILE?=		${FILESDIR}/md5
MAKE_FLAGS?=	-f
MAKEFILE?=		Makefile

NCFTP?=			ncftp
NCFTPFLAGS?=	-N

TOUCH?=			touch
TOUCH_FLAGS?=	-f

PATCH?=			patch
PATCH_STRIP?=	-p0
PATCH_DIST_STRIP?=	-p0
.if defined(PATCH_DEBUG)
PATCH_ARGS?=	-d ${WRKSRC} -E ${PATCH_STRIP}
PATCH_DIST_ARGS?=	-d ${WRKSRC} -E ${PATCH_DIST_STRIP}
.else
PATCH_ARGS?=	-d ${WRKSRC} --forward --quiet -E ${PATCH_STRIP}
PATCH_DIST_ARGS?=	-d ${WRKSRC} --forward --quiet -E ${PATCH_DIST_STRIP}
.endif

EXTRACT_CMD?=	tar
EXTRACT_SUFX?=	.tar.gz
# Backwards compatability.
.if defined(EXTRACT_ARGS)
EXTRACT_BEFORE_ARGS?=   ${EXTRACT_ARGS}
.else
EXTRACT_BEFORE_ARGS?=   -xzf
.endif

# Figure out where the local mtree file is
.if !defined(MTREE_LOCAL) && exists(/etc/mtree/BSD.local.dist)
MTREE_LOCAL=	/etc/mtree/BSD.local.dist
.endif

PKG_CMD?=		pkg_create
.if !defined(PKG_ARGS)
PKG_ARGS=		-v -c ${PKGDIR}/COMMENT -d ${PKGDIR}/DESCR -f ${PKGDIR}/PLIST -p ${PREFIX} -P "`${MAKE} package-depends|sort|uniq`"
.if exists(${PKGDIR}/INSTALL)
PKG_ARGS+=		-i ${PKGDIR}/INSTALL
.endif
.if exists(${PKGDIR}/DEINSTALL)
PKG_ARGS+=		-k ${PKGDIR}/DEINSTALL
.endif
.if exists(${PKGDIR}/REQ)
PKG_ARGS+=		-r ${PKGDIR}/REQ
.endif
.if !defined(USE_X11) && !defined(USE_IMAKE) && defined(MTREE_LOCAL)
PKG_ARGS+=		-m ${MTREE_LOCAL}
.endif
.endif
PKG_SUFX?=		.tgz
# where pkg_add records its dirty deeds.
PKG_DBDIR?=		/var/db/pkg

# Used to print all the '===>' style prompts - override this to turn them off.
ECHO_MSG?=		echo

ALL_TARGET?=		all
INSTALL_TARGET?=	install

# If the user has this set, go to the FreeBSD respository for everything.
.if defined(MASTER_SITE_FREEBSD)
MASTER_SITE_OVERRIDE=  ftp://freebsd.cdrom.com/pub/FreeBSD/FreeBSD-current/ports/distfiles/ 
.endif

# I guess we're in the master distribution business! :)  As we gain mirror
# sites for distfiles, add them to this list.
.if !defined(MASTER_SITE_OVERRIDE)
MASTER_SITES+=	ftp://ftp.freebsd.org/pub/FreeBSD/FreeBSD-current/ports/distfiles/
PATCH_SITES+=	ftp://ftp.freebsd.org/pub/FreeBSD/FreeBSD-current/ports/distfiles/
.else
MASTER_SITES=	${MASTER_SITE_OVERRIDE}
PATCH_SITES=	${MASTER_SITE_OVERRIDE}
.endif

# Derived names so that they're easily overridable.
DISTFILES?=		${DISTNAME}${EXTRACT_SUFX}
PKGNAME?=		${DISTNAME}

# Documentation
MAINTAINER?=	ports@FreeBSD.ORG
CATEGORIES?=	orphans
CATEGORIES+=	all
KEYWORDS+=		${CATEGORIES}

PKGREPOSITORYSUBDIR?=	.packages
PKGREPOSITORY?=		${PACKAGES}/${PKGREPOSITORYSUBDIR}
.if exists(${PACKAGES})
PKGFILE?=		${PKGREPOSITORY}/${PKGNAME}${PKG_SUFX}
.else
PKGFILE?=		${PKGNAME}${PKG_SUFX}
.endif

CONFIGURE_SCRIPT?=	configure

.if defined(GNU_CONFIGURE)
CONFIGURE_ARGS?=	--prefix=${PREFIX}
HAS_CONFIGURE=		yes
.endif

.MAIN: all

# If we're in BATCH mode and the port is interactive, or we're in
# interactive mode and the port is non-interactive, skip all the important
# targets.  The reason we have two modes is that one might want to leave
# a build in BATCH mode running overnight, then come back in the morning
# and do _only_ the interactive ones that required your intervention.
# This allows you to do both.
#
.if (defined(IS_INTERACTIVE) && defined(BATCH)) || (!defined(IS_INTERACTIVE) && defined(INTERACTIVE))
all:
	@${DO_NADA}
pre-build:
	@${DO_NADA}
build:
	@${DO_NADA}
pre-install:
	@${DO_NADA}
install:
	@${DO_NADA}
pre-fetch:
	@${DO_NADA}
fetch:
	@${DO_NADA}
pre-configure:
	@${DO_NADA}
configure:
	@${DO_NADA}
package:
	@${DO_NADA}
.endif

.if !target(all)
all: build
.endif

.if !target(is_depended)
is_depended:	all install
.endif

# The following are used to create easy dummy targets for disabling some
# bit of default target behavior you don't want.  They still check to see
# if the target exists, and if so don't do anything, since you might want
# to set this globally for a group of ports in a Makefile.inc, but still
# be able to override from an individual Makefile (since you can't _undefine_
# a variable in make!).
.if defined(NO_EXTRACT) && !target(extract)
extract:
	@${TOUCH} ${TOUCH_FLAGS} ${EXTRACT_COOKIE}
checksum:
	@${DO_NADA}
makesum:
	@${DO_NADA}
.endif
.if defined(NO_CONFIGURE) && !target(configure)
configure:
	@${TOUCH} ${TOUCH_FLAGS} ${CONFIGURE_COOKIE}
.endif
.if defined(NO_BUILD) && !target(build)
build:
	@${TOUCH} ${TOUCH_FLAGS} ${BUILD_COOKIE}
.endif
.if defined(NO_PACKAGE) && !target(package)
package:
	@${DO_NADA}
.endif
.if defined(NO_PACKAGE) && !target(repackage)
repackage:
	@${DO_NADA}
.endif
.if defined(NO_INSTALL) && !target(install)
install:
	@${TOUCH} ${TOUCH_FLAGS} ${INSTALL_COOKIE}
.endif
.if defined(NO_PATCH) && !target(patch)
patch:
	@${TOUCH} ${TOUCH_FLAGS} ${PATCH_COOKIE}
.endif

# More standard targets start here.

# This target generates an index entry suitable for aggregation into
# a large index.  Format is:
#
# distribution-name|port-path|installation-prefix|comment| \
#  description-file|maintainer
#
.if !target(describe)
describe:
	@echo -n "${PKGNAME}|${.CURDIR}/${PKGNAME}|"
	@echo -n "${PREFIX}|"
	@if [ -f ${PKGDIR}/COMMENT ]; then \
		echo -n "`cat ${PKGDIR}/COMMENT`"; \
	else \
		echo -n "** No Description"; \
	fi
	@if [ -f ${PKGDIR}/DESCR ]; then \
		echo -n "|${PKGDIR}/DESCR"; \
	else \
		echo -n "|/dev/null"; \
	fi
	@echo -n "|${MAINTAINER}|${CATEGORIES}|${KEYWORDS}"
	@echo ""
.endif

.if !target(reinstall)
reinstall: pre-reinstall install

pre-reinstall:
	@rm -f ${INSTALL_COOKIE}
.endif

.if !target(pre-install)
pre-install:
	@${DO_NADA}
.endif

.if !target(install)
install: build ${INSTALL_COOKIE}

${INSTALL_COOKIE}:
	@${ECHO_MSG} "===>  Installing for ${PKGNAME}"
	@${MAKE} ${.MAKEFLAGS} pre-install
.if defined(USE_GMAKE)
	@(cd ${WRKSRC}; ${GMAKE} PREFIX=${PREFIX} ${MAKE_FLAGS} ${MAKEFILE} ${INSTALL_TARGET})
.if defined(USE_IMAKE) && !defined(NO_INSTALL_MANPAGES)
	@(cd ${WRKSRC}; ${GMAKE} ${MAKE_FLAGS} ${MAKEFILE} install.man)
.endif
.else defined(USE_GMAKE)
	@(cd ${WRKSRC}; ${MAKE} PREFIX=${PREFIX} ${MAKE_FLAGS} ${MAKEFILE} ${INSTALL_TARGET})
.if defined(USE_IMAKE) && !defined(NO_INSTALL_MANPAGES)
	@(cd ${WRKSRC}; ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} install.man)
.endif
.endif
.if !defined(NO_PACKAGE)
	@if [ ! -f ${PKGDIR}/PLIST -o ! -f ${PKGDIR}/COMMENT -o ! -f ${PKGDIR}/DESCR ]; then echo "** Missing patch files for ${PKGNAME} - installation not recorded."; exit 1; fi
	@if [ ! -d ${PKG_DBDIR} ]; then rm -f ${PKG_DBDIR}; mkdir -p ${PKG_DBDIR}; fi
	@if [ ! -d ${PKG_DBDIR}/${PKGNAME} ]; then \
		${ECHO_MSG} "===> Registering installation for ${PKGNAME}"; \
		mkdir -p ${PKG_DBDIR}/${PKGNAME}; \
		cp ${PKGDIR}/PLIST ${PKG_DBDIR}/${PKGNAME}/+CONTENTS; \
		cp ${PKGDIR}/DESCR ${PKG_DBDIR}/${PKGNAME}/+DESC; \
		cp ${PKGDIR}/COMMENT ${PKG_DBDIR}/${PKGNAME}/+COMMENT; \
	else \
		${ECHO_MSG} "===> ${PKGNAME} is already installed - perhaps an older version?"; \
		${ECHO_MSG} "     If so, you may wish to \`\`pkg_delete ${PKGNAME}'' and install"; \
		${ECHO_MSG} "     this port again to upgrade it properly."; \
	fi
.endif
	@${TOUCH} ${TOUCH_FLAGS} ${INSTALL_COOKIE}
.endif

# package-name and package-depends are internal targets and really
# shouldn't be touched by anybody but the release engineers.

# Nobody should want to override this unless PKGNAME is simply bogus.
.if !target(package-name)
package-name:
.if !defined(NO_PACKAGE)
	@echo ${PKGNAME}
.endif
.endif

# Show (recursively) all the packages this package depends on.
.if !target(package-depends)
package-depends:
	@for i in ${EXEC_DEPENDS} ${LIB_DEPENDS} ${DEPENDS}; do \
		dir=`echo $$i | sed -e 's/.*://'`; \
		(cd $$dir ; ${MAKE} package-name package-depends); \
	done
.endif

.if !target(pre-package)
pre-package:
	@${DO_NADA}
.endif

.if !target(package)
package: install
	@${MAKE} ${.MAKEFLAGS} pre-package
	@${MAKE} ${.MAKEFLAGS} do-package
.endif

.if !target(repackage)
repackage:
	@${MAKE} ${.MAKEFLAGS} pre-package
	@${MAKE} ${.MAKEFLAGS} do-package
.endif

.if !target(do-package)
do-package:
	@if [ -e ${PKGDIR}/PLIST ]; then \
		${ECHO_MSG} "===>  Building package for ${PKGNAME}"; \
		if [ -d ${PACKAGES} ]; then \
			if [ ! -d ${PKGREPOSITORY} ]; then \
				if ! mkdir -p ${PKGREPOSITORY}; then \
					${ECHO_MSG} ">> Can't create directory ${PKGREPOSITORY}."; \
					exit 1; \
				fi; \
			fi; \
		fi; \
		${PKG_CMD} ${PKG_ARGS} ${PKGFILE}; \
		if [ -d ${PACKAGES} ]; then \
			rm -f ${PACKAGES}/*/${PKGNAME}${PKG_SUFX}; \
			for cat in ${CATEGORIES}; do \
				if [ ! -d ${PACKAGES}/$$cat ]; then \
					if ! mkdir -p ${PACKAGES}/$$cat; then \
						${ECHO_MSG} ">> Can't create directory ${PACKAGES}/$$cat."; \
						exit 1; \
					fi; \
				fi; \
				ln -s ../${PKGREPOSITORYSUBDIR}/${PKGNAME}${PKG_SUFX} ${PACKAGES}/$$cat; \
			done; \
		fi; \
	fi
.endif

.if !target(depends)
depends: exec_depends lib_depends misc_depends

exec_depends:
.if defined(EXEC_DEPENDS)
.if defined(NO_DEPENDS)
# Just print out messages
	@for i in ${EXEC_DEPENDS}; do \
		prog=`echo $$i | sed -e 's/:.*//'`; \
		dir=`echo $$i | sed -e 's/.*://'`; \
		${ECHO_MSG} "===>  ${PKGNAME} depends on executable:  $$prog ($$dir)"; \
	done
.else
	@for i in ${EXEC_DEPENDS}; do \
		prog=`echo $$i | sed -e 's/:.*//'`; \
		dir=`echo $$i | sed -e 's/.*://'`; \
		if which -s "$$prog"; then \
			${ECHO_MSG} "===>  ${PKGNAME} depends on executable: $$prog - found"; \
		else \
			${ECHO_MSG} "===>  ${PKGNAME} depends on executable: $$prog - not found"; \
			${ECHO_MSG} "===>  Verifying build for $$prog in $$dir"; \
			if [ ! -d "$$dir" ]; then \
				${ECHO_MSG} ">> No directory for $$prog.  Skipping.."; \
			else \
				(cd $$dir; ${MAKE} ${.MAKEFLAGS} is_depended) ; \
				${ECHO_MSG} "===>  Returning to build of ${PKGNAME}"; \
			fi; \
		fi; \
	done
.endif
.else
	@${DO_NADA}
.endif

lib_depends:
.if defined(LIB_DEPENDS)
.if defined(NO_DEPENDS)
# Just print out messages
	@for i in ${LIB_DEPENDS}; do \
		lib=`echo $$i | sed -e 's/:.*//'`; \
		dir=`echo $$i | sed -e 's/.*://'`; \
		${ECHO_MSG} "===>  ${PKGNAME} depends on shared library:  $$lib ($$dir)"; \
	done
.else
	@for i in ${LIB_DEPENDS}; do \
		lib=`echo $$i | sed -e 's/:.*//'`; \
		dir=`echo $$i | sed -e 's/.*://'`; \
		if ldconfig -r | grep -q -e "-l$$lib"; then \
			${ECHO_MSG} "===>  ${PKGNAME} depends on shared library: $$lib - found"; \
		else \
			${ECHO_MSG} "===>  ${PKGNAME} depends on shared library: $$lib - not found"; \
			${ECHO_MSG} "===>  Verifying build for $$lib in $$dir"; \
			if [ ! -d "$$dir" ]; then \
				${ECHO_MSG} ">> No directory for $$lib.  Skipping.."; \
			else \
				(cd $$dir; ${MAKE} ${.MAKEFLAGS} is_depended) ; \
				${ECHO_MSG} "===>  Returning to build of ${PKGNAME}"; \
			fi; \
		fi; \
	done
.endif
.else
	@${DO_NADA}
.endif

misc_depends:
.if defined(DEPENDS)
	@${ECHO_MSG} "===>  ${PKGNAME} depends on:  ${DEPENDS}"
.if !defined(NO_DEPENDS)
	@for i in ${DEPENDS}; do \
		${ECHO_MSG} "===>  Verifying build for $$i"; \
		if [ ! -d $$i ]; then \
			${ECHO_MSG} ">> No directory for $$i.  Skipping.."; \
		else \
			(cd $$i; ${MAKE} ${.MAKEFLAGS} is_depended) ; \
		fi \
	done
	@${ECHO_MSG} "===>  Returning to build of ${PKGNAME}"
.endif
.else
	@${DO_NADA}
.endif

.endif

.if !target(pre-build)
pre-build:
	@${DO_NADA}
.endif

.if !target(build)
build: configure ${BUILD_COOKIE}

${BUILD_COOKIE}:
	@${ECHO_MSG} "===>  Building for ${PKGNAME}"
	@${MAKE} ${.MAKEFLAGS} pre-build
.if defined(USE_GMAKE)
	@(cd ${WRKSRC}; ${GMAKE} PREFIX=${PREFIX} ${MAKE_FLAGS} ${MAKEFILE} ${ALL_TARGET})
.else defined(USE_GMAKE)
	@(cd ${WRKSRC}; ${MAKE} PREFIX=${PREFIX} ${MAKE_FLAGS} ${MAKEFILE} ${ALL_TARGET})
.endif
	@if [ -f ${SCRIPTDIR}/post-build ]; then \
		env CURDIR=${.CURDIR} DISTDIR=${DISTDIR} WRKDIR=${WRKDIR} \
		  WRKSRC=${WRKSRC} PATCHDIR=${PATCHDIR} SCRIPTDIR=${SCRIPTDIR} \
		  FILESDIR=${FILESDIR} PORTSDIR=${PORTSDIR} PREFIX=${PREFIX} \
		  DEPENDS="${DEPENDS}" \
		sh ${SCRIPTDIR}/post-build; \
	fi
	@${TOUCH} ${TOUCH_FLAGS} ${BUILD_COOKIE}
.endif

.if !target(pre-patch)
pre-patch:
	@${DO_NADA}
.endif

.if !target(patch)
patch: extract ${PATCH_COOKIE}

${PATCH_COOKIE}:
	@${MAKE} ${.MAKEFLAGS} pre-patch
.if defined(PATCHFILES)
	@${ECHO_MSG} "===>  Applying distributed patches for ${PKGNAME}"
.if defined(PATCH_DEBUG)
	@(cd ${DISTDIR}; \
	  for i in ${PATCHFILES}; do \
		${ECHO_MSG} "===>   Applying distributed patch $$i" ; \
		case $$i in \
			*.Z|*.gz) \
				zcat $$i | ${PATCH} ${PATCH_DIST_ARGS}; \
				;; \
			*) \
				${PATCH} ${PATCH_DIST_ARGS} < $$i; \
				;; \
		esac; \
	  done)
.else
	@(cd ${DISTDIR}; \
	  for i in ${PATCHFILES}; do \
		case $$i in \
			*.Z|*.gz) \
				zcat $$i | ${PATCH} ${PATCH_DIST_ARGS}; \
				;; \
			*) \
				${PATCH} ${PATCH_DIST_ARGS} < $$i; \
				;; \
		esac; \
	  done)
.endif
.endif
.if defined(PATCH_DEBUG)
	@if [ -d ${PATCHDIR} ]; then \
		${ECHO_MSG} "===>  Applying FreeBSD patches for ${PKGNAME}" ; \
		for i in ${PATCHDIR}/patch-*; do \
			${ECHO_MSG} "===>   Applying FreeBSD patch $$i" ; \
			${PATCH} ${PATCH_ARGS} < $$i; \
		done; \
	fi
	@${TOUCH} ${TOUCH_FLAGS} ${PATCH_COOKIE}
.else
	@if [ -d ${PATCHDIR} ]; then \
		${ECHO_MSG} "===>  Applying FreeBSD patches for ${PKGNAME}" ; \
		for i in ${PATCHDIR}/patch-*; \
			do ${PATCH} ${PATCH_ARGS} < $$i; \
		done;\
	fi
	@${TOUCH} ${TOUCH_FLAGS} ${PATCH_COOKIE}
.endif
.endif

.if !target(pre-configure)
pre-configure:
	@${DO_NADA}
.endif

.if !target(configure)
configure: depends patch ${CONFIGURE_COOKIE}

${CONFIGURE_COOKIE}:
	@${ECHO_MSG} "===>  Configuring for ${PKGNAME}"
	@${MAKE} ${.MAKEFLAGS} pre-configure
	@if [ -f ${SCRIPTDIR}/pre-configure ]; then \
		env CURDIR=${.CURDIR} DISTDIR=${DISTDIR} WRKDIR=${WRKDIR} \
		  WRKSRC=${WRKSRC} PATCHDIR=${PATCHDIR} SCRIPTDIR=${SCRIPTDIR} \
		  FILESDIR=${FILESDIR} PORTSDIR=${PORTSDIR} PREFIX=${PREFIX} \
		  DEPENDS="${DEPENDS}" \
		sh ${SCRIPTDIR}/pre-configure; \
	fi
	@if [ -f ${SCRIPTDIR}/configure ]; then \
		env CURDIR=${.CURDIR} DISTDIR=${DISTDIR} WRKDIR=${WRKDIR} \
		  WRKSRC=${WRKSRC} PATCHDIR=${PATCHDIR} SCRIPTDIR=${SCRIPTDIR} \
		  FILESDIR=${FILESDIR} PORTSDIR=${PORTSDIR} PREFIX=${PREFIX} \
		  DEPENDS="${DEPENDS}" \
		sh ${SCRIPTDIR}/configure; \
	fi
.if defined(HAS_CONFIGURE)
	@(cd ${WRKSRC}; CC="${CC}" ac_cv_path_CC="${CC}" CFLAGS="${CFLAGS}" \
	    INSTALL="/usr/bin/install -c -o ${BINOWN} -g ${BINGRP}" \
	    INSTALL_PROGRAM="/usr/bin/install ${COPY} ${STRIP} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE}" \
	    ./${CONFIGURE_SCRIPT} ${CONFIGURE_ARGS})
.endif
.if defined(USE_IMAKE)
.if defined(USE_GMAKE)
	@(cd ${WRKSRC}; ${XMKMF} && ${GMAKE} Makefiles)
.else
	@(cd ${WRKSRC}; ${XMKMF} && ${MAKE} Makefiles)
.endif
.endif
	@if [ -f ${SCRIPTDIR}/post-configure ]; then \
		env CURDIR=${.CURDIR} DISTDIR=${DISTDIR} WRKDIR=${WRKDIR} \
		  WRKSRC=${WRKSRC} PATCHDIR=${PATCHDIR} SCRIPTDIR=${SCRIPTDIR} \
		  FILESDIR=${FILESDIR} PORTSDIR=${PORTSDIR} PREFIX=${PREFIX} \
		  DEPENDS="${DEPENDS}" \
		sh ${SCRIPTDIR}/post-configure; \
	fi
	@${TOUCH} ${TOUCH_FLAGS} ${CONFIGURE_COOKIE}
.endif

.if !target(pre-fetch)
pre-fetch:
	@${DO_NADA}
.endif

.if !target(fetch)
fetch: pre-fetch
	@if [ ! -d ${DISTDIR} ]; then mkdir -p ${DISTDIR}; fi
	@(cd ${DISTDIR}; \
	 for file in ${DISTFILES}; do \
		if [ ! -f $$file -a ! -f `basename $$file` ]; then \
			${ECHO_MSG} ">> $$file doesn't seem to exist on this system."; \
			for site in ${MASTER_SITES}; do \
			    ${ECHO_MSG} ">> Attempting to fetch from $${site}"; \
				if ${NCFTP} ${NCFTPFLAGS} $${site}$${file}; then \
					break; \
				fi \
			done; \
			if [ ! -f $$file -a ! -f `basename $$file` ]; then \
				${ECHO_MSG} ">> Couldn't fetch it - please try to retreive this";\
				${ECHO_MSG} ">> port manually into ${DISTDIR} and try again."; \
				exit 1; \
			fi; \
	    fi \
	 done)
.if defined(PATCHFILES)
	@(cd ${DISTDIR}; \
	 for file in ${PATCHFILES}; do \
		if [ ! -f $$file -a ! -f `basename $$file` ]; then \
			${ECHO_MSG} ">> $$file doesn't seem to exist on this system."; \
			for site in ${PATCH_SITES}; do \
			    ${ECHO_MSG} ">> Attempting to fetch from $${site}."; \
				if ${NCFTP} ${NCFTPFLAGS} $${site}$${file}; then \
					break; \
				fi \
			done; \
			if [ ! -f $$file -a ! -f `basename $$file` ]; then \
				${ECHO_MSG} ">> Couldn't fetch it - please try to retreive this";\
				${ECHO_MSG} ">> port manually into ${DISTDIR} and try again."; \
				exit 1; \
			fi; \
	    fi \
	 done)
.endif
.endif

.if !target(fetch-list)
fetch-list:
	@if [ ! -d ${DISTDIR} ]; then mkdir -p ${DISTDIR}; fi
	@(cd ${DISTDIR}; \
	 for file in ${DISTFILES}; do \
		if [ ! -f $$file -a ! -f `basename $$file` ]; then \
			for site in ${MASTER_SITES}; do \
				echo -n ${NCFTP} ${NCFTPFLAGS} $${site}$${file} '||' ; \
					break; \
			done; \
			echo "echo $${file} not fetched" ; \
		fi \
	done)
.if defined(PATCHFILES)
	@(cd ${DISTDIR}; \
	 for file in ${PATCHFILES}; do \
		if [ ! -f $$file -a ! -f `basename $$file` ]; then \
			for site in ${PATCH_SITES}; do \
				echo -n ${NCFTP} ${NCFTPFLAGS} $${site}$${file} '||' ; \
					break; \
			done; \
			echo "echo $${file} not fetched" ; \
		fi \
	done)
.endif
.endif

.if !target(makesum)
makesum: fetch
	@if [ ! -d ${FILESDIR} ]; then mkdir -p ${FILESDIR}; fi
	@if [ -f ${MD5_FILE} ]; then rm -f ${MD5_FILE}; fi
	@(cd ${DISTDIR}; \
	for file in ${DISTFILES} ${PATCHFILES}; do \
		${MD5} $$file >> ${MD5_FILE}; \
	done)
.endif

.if !target(checksum)
checksum: fetch
	@if [ ! -f ${MD5_FILE} ]; then \
		${ECHO_MSG} ">> No MD5 checksum file."; \
	else \
		(cd ${DISTDIR}; OK=""; \
		for file in ${DISTFILES} ${PATCHFILES}; do \
			CKSUM=`${MD5} $$file | awk '{print $$4}'`; \
			CKSUM2=`grep "($$file)" ${MD5_FILE} | awk '{print $$4}'`; \
			if [ "$$CKSUM2" = "" ]; then \
				${ECHO_MSG} ">> No checksum recorded for $$file"; \
				OK="false"; \
			elif [ "$$CKSUM" != "$$CKSUM2" ]; then \
				${ECHO_MSG} ">> Checksum mismatch for $$file"; \
				exit 1; \
			fi; \
			done; \
			if [ "$$OK" = "" ]; then \
				${ECHO_MSG} "Checksums OK."; \
			else \
				${ECHO_MSG} "Checksums OK for files that have them."; \
   	     fi) ; \
	fi
.endif

.if !target(pre-extract)
pre-extract:
	@${DO_NADA}
.endif

.if !target(extract)
# We need to depend on .extract_done rather than the presence of ${WRKDIR}
# because if the user interrupts the extract in the middle (and it's often
# a long procedure), we get tricked into thinking that we've got a good dist
# in ${WRKDIR}.
extract: fetch ${EXTRACT_COOKIE}

${EXTRACT_COOKIE}:
	@${MAKE} ${.MAKEFLAGS} checksum pre-extract
	@${ECHO_MSG} "===>  Extracting for ${PKGNAME}"
	@rm -rf ${WRKDIR}
	@mkdir -p ${WRKDIR}
.if defined(EXTRACT_ONLY)
	@for file in ${EXTRACT_ONLY}; do \
		if ! (cd ${WRKDIR};${EXTRACT_CMD} ${EXTRACT_BEFORE_ARGS} ${DISTDIR}/$$file ${EXTRACT_AFTER_ARGS});\
		then \
			exit 1; \
		fi \
	done
.else
	@for file in ${DISTFILES}; do \
		if ! (cd ${WRKDIR};${EXTRACT_CMD} ${EXTRACT_BEFORE_ARGS} ${DISTDIR}/$$file ${EXTRACT_AFTER_ARGS});\
		then \
			exit 1; \
		fi \
	done
.endif
	@${TOUCH} ${TOUCH_FLAGS} ${EXTRACT_COOKIE}
.endif

.if !target(pre-clean)
pre-clean:
	@${DO_NADA}
.endif

.if !target(clean)
clean: pre-clean
	@${ECHO_MSG} "===>  Cleaning for ${PKGNAME}"
	@rm -f ${EXTRACT_COOKIE} ${CONFIGURE_COOKIE} ${INSTALL_COOKIE} \
		${BUILD_COOKIE} ${PATCH_COOKIE}
.if !defined(NO_WRKDIR)
	@rm -rf ${WRKDIR}
.endif
.endif

# No pre-targets for depend or tags.  It would be silly.

# Depend is generally meaningless for arbitrary ports, but if someone wants
# one they can override this.  This is just to catch people who've gotten into
# the habit of typing `make depend all install' as a matter of course.
#
.if !target(depend)
depend:
.endif

# Same goes for tags
.if !target(tags)
tags:
.endif
