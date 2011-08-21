.include <bsd.init.mk>

LIB=	plebconf


PC_OBJS =		\
	pc_client_syscalls.o \
	pc_user_sysctl.o


PC_SRCS= ${PC_OBJS:C/.o$/.c/}

SRCS+=	${PC_SRCS}
CFLAGS=		-I/usr/include
CFLAGS+=	-I../include

CFLAGS+=	-nostdinc
CFLAGS+=	-g
CFLAGS+=	-O0
NO_WERROR=	1
WARNS=2
CSTD="c99"
WFORMAT=0
SHLIB_MAJOR= 1
SHLIB_MINOR= 1

.include <bsd.dep.mk>
.include <bsd.lib.mk>

