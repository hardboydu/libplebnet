#	from: @(#)bsd.subdir.mk	5.9 (Berkeley) 2/1/91
# $FreeBSD$
#
# The include file <bsd.subdir.mk> contains the default targets
# for building subdirectories. 
#
# For all of the directories listed in the variable SUBDIRS, the
# specified directory will be visited and the target made. There is
# also a default target which allows the command "make subdir" where
# subdir is any directory listed in the variable SUBDIRS.
#
#
# +++ variables +++
#
# DISTRIBUTION	Name of distribution. [base]
#
# SUBDIR	A list of subdirectories that should be built as well.
#		Each of the targets will execute the same target in the
#		subdirectories.
#
# +++ targets +++
#
#	distribute:
# 		This is a variant of install, which will
# 		put the stuff into the right "distribution".
#
#	afterdistribute, afterinstall, all, all-man, beforeinstall, checkdpadd,
#	clean, cleandepend, cleandir, depend, install, lint,
#	obj, objlink, realinstall, regress, tags
#

.include <bsd.init.mk>

_SUBDIR: .USE
.if defined(SUBDIR) && !empty(SUBDIR)
	@for entry in ${SUBDIR}; do \
		if test -d ${.CURDIR}/$${entry}.${MACHINE_ARCH}; then \
			${ECHODIR} "===> ${DIRPRFX}$${entry}.${MACHINE_ARCH}"; \
			edir=$${entry}.${MACHINE_ARCH}; \
			cd ${.CURDIR}/$${edir}; \
		else \
			${ECHODIR} "===> ${DIRPRFX}$$entry"; \
			edir=$${entry}; \
			cd ${.CURDIR}/$${edir}; \
		fi; \
		${MAKE} ${.TARGET:realinstall=install} \
		    DIRPRFX=${DIRPRFX}$$edir/; \
	done
.endif

${SUBDIR}::
	@if test -d ${.TARGET}.${MACHINE_ARCH}; then \
		cd ${.CURDIR}/${.TARGET}.${MACHINE_ARCH}; \
	else \
		cd ${.CURDIR}/${.TARGET}; \
	fi; \
	${MAKE} all


.for __target in all all-man checkdpadd clean cleandepend cleandir depend lint \
    obj objlink realinstall regress tags
${__target}: _SUBDIR
.endfor

.if !target(install)
.if !target(beforeinstall)
beforeinstall:
.endif
.if !target(afterinstall)
afterinstall:
.endif
install: afterinstall
afterinstall: realinstall
realinstall: beforeinstall
.endif

DISTRIBUTION?=	base
.if !target(afterdistribute)
afterdistribute:
.endif
.if !target(distribute)
distribute: _SUBDIR
.for dist in ${DISTRIBUTION}
	cd ${.CURDIR} ; ${MAKE} afterdistribute DESTDIR=${DISTDIR}/${dist}
.endfor
.endif
