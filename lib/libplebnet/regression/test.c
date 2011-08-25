#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>


int 
main(void)
{
	int fd, error;
	struct iovec iov[3];
	struct msghdr msg;
	static struct addrinfo hint;
	struct addrinfo *ai, *ai0;
	static char slash_w[] = "/W "; 
        static char neteol[] = "\r\n"; 
	static char *name = "john";

	hint.ai_flags = AI_CANONNAME;
	hint.ai_family = PF_INET;
	hint.ai_socktype = SOCK_DGRAM;
        error = getaddrinfo("localhost", "finger", &hint, &ai0); 

	msg.msg_name = (void *)ai0->ai_addr;
	msg.msg_namelen = ai0->ai_addrlen; 
        msg.msg_iov = iov; 
        msg.msg_iovlen = 0; 
        msg.msg_control = 0; 
        msg.msg_controllen = 0; 
        msg.msg_flags = 0; 

        iov[msg.msg_iovlen].iov_base = strdup(name); 
        iov[msg.msg_iovlen++].iov_len = strlen(name); 
        iov[msg.msg_iovlen].iov_base = neteol; 
        iov[msg.msg_iovlen++].iov_len = 2; 
	

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	printf("fd=%d\n", fd);
	sleep(180);
	error = sendmsg(fd, &msg, 0);
	printf("sendmsg returned %s\n", strerror(errno));
	return (0);
}
	
