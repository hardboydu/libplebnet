.include <bsd.init.mk>

LIB=	plebconf

PC_OBJS =		\
	pc_client_syscalls.o


PC_SRCS= ${PC_OBJS:C/.o$/.c/}

SRCS=	${PC_SRCS}
CFLAGS=		-I../include


.include <bsd.lib.mk>