# $FreeBSD$

.include <bsd.own.mk>

PROG=	jail
MAN=	jail.8
DPADD=	${LIBJAIL} ${LIBUTIL}
LDADD=	-ljail -lutil

WARNS?=	6

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
.endif

.include <bsd.prog.mk>
