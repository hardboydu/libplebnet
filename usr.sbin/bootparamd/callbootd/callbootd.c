/*

This code is not copyright, and is placed in the public domain. Feel free to
use and modify. Please send modifications and/or suggestions + bug fixes to

        Klas Heggemann <klas@nada.kth.se>

	$Id: callbootd.c,v 1.2 1995/03/26 03:15:39 wpaul Exp $
*/


#include "bootparam_prot.h"
#include <rpc/rpc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


/* #define bp_address_u bp_address */
#include <stdio.h>

int broadcast;

char cln[MAX_MACHINE_NAME+1];
char dmn[MAX_MACHINE_NAME+1];
char path[MAX_PATH_LEN+1];
extern char *inet_ntoa();

eachres_whoami(resultp, raddr)
bp_whoami_res *resultp;
struct sockaddr_in *raddr;
{
  struct hostent *he;

  he = gethostbyaddr((char *)&raddr->sin_addr.s_addr,4,AF_INET);
  printf("%s answered:\n", he ? he->h_name : inet_ntoa(raddr->sin_addr));
  printwhoami(resultp);
  printf("\n");
  return(0);
}

eachres_getfile(resultp, raddr)
bp_getfile_res *resultp;
struct sockaddr_in *raddr;
{
  struct hostent *he;

  he = gethostbyaddr((char *)&raddr->sin_addr.s_addr,4,AF_INET);
  printf("%s answered:\n", he ? he->h_name : inet_ntoa(raddr->sin_addr));
  printgetfile(resultp);
  printf("\n");
  return(0);
}


main(argc, argv)
int argc;
char **argv;
{
  int stat;
  char *server;

  bp_whoami_arg whoami_arg;
  bp_whoami_res *whoami_res, stat_whoami_res;
  bp_getfile_arg getfile_arg;
  bp_getfile_res *getfile_res, stat_getfile_res;


  long the_inet_addr;
  CLIENT *clnt;
  enum clnt_stat clnt_stat;

  stat_whoami_res.client_name = cln;
  stat_whoami_res.domain_name = dmn;

  stat_getfile_res.server_name = cln;
  stat_getfile_res.server_path = path;

  if (argc < 3) {
    fprintf(stderr,
	    "Usage: %s server procnum (IP-addr | host fileid)\n", argv[0]);
    exit(1);
  }


  server = argv[1];
  if ( ! strcmp(server , "all") ) broadcast = 1;

  if ( ! broadcast ) {
    clnt = clnt_create(server,BOOTPARAMPROG, BOOTPARAMVERS, "udp");
  }

  if ( clnt == NULL ) {
     fprintf (stderr, "%s: could not contact bootparam server on host %s\n",
			argv[0], server);
     exit (1);
  }

  switch (argc) {
  case 3:
    whoami_arg.client_address.address_type = IP_ADDR_TYPE;
    the_inet_addr = inet_addr(argv[2]);
    if ( the_inet_addr == -1) {
      fprintf(stderr, "bogus addr %s\n", argv[2]);
      exit(1);
    }
    bcopy(&the_inet_addr,&whoami_arg.client_address.bp_address_u.ip_addr,4);

    if (! broadcast ) {
      whoami_res = bootparamproc_whoami_1(&whoami_arg, clnt);
      printf("Whoami returning:\n");
      if (printwhoami(whoami_res)) {
	fprintf(stderr, "Bad answer returned from server %s\n", server);
	exit(1);
      } else
	exit(0);
     } else {
       clnt_stat=clnt_broadcast(BOOTPARAMPROG, BOOTPARAMVERS,
			       BOOTPARAMPROC_WHOAMI,
			       xdr_bp_whoami_arg, &whoami_arg,
			       xdr_bp_whoami_res, &stat_whoami_res, eachres_whoami);
       exit(0);
     }

  case 4:

    getfile_arg.client_name = argv[2];
    getfile_arg.file_id = argv[3];

    if (! broadcast ) {
      getfile_res = bootparamproc_getfile_1(&getfile_arg,clnt);
      printf("getfile returning:\n");
      if (printgetfile(getfile_res)) {
	fprintf(stderr, "Bad answer returned from server %s\n", server);
	exit(1);
      } else
	exit(0);
    } else {
      clnt_stat=clnt_broadcast(BOOTPARAMPROG, BOOTPARAMVERS,
			       BOOTPARAMPROC_GETFILE,
			       xdr_bp_getfile_arg, &getfile_arg,
			       xdr_bp_getfile_res, &stat_getfile_res,eachres_getfile);
      exit(0);
    }

  default:

    fprintf(stderr,
	    "Usage: %s server procnum (IP-addr | host fileid)\n", argv[0]);
    exit(1);
  }

}



int printwhoami(res)
bp_whoami_res *res;
{
      if ( res) {
	printf("client_name:\t%s\ndomain_name:\t%s\n",
	     res->client_name, res->domain_name);
	printf("router:\t%d.%d.%d.%d\n",
	     255 &  res->router_address.bp_address_u.ip_addr.net,
	     255 & res->router_address.bp_address_u.ip_addr.host,
	     255 &  res->router_address.bp_address_u.ip_addr.lh,
	     255 & res->router_address.bp_address_u.ip_addr.impno);
	return(0);
      } else {
	fprintf(stderr,"Null answer!!!\n");
	return(1);
      }
    }




int
printgetfile(res)
bp_getfile_res *res;
{
      if (res) {
	printf("server_name:\t%s\nserver_address:\t%s\npath:\t%s\n",
	       res->server_name,
	       inet_ntoa(res->server_address.bp_address_u.ip_addr),
	       res->server_path);
	return(0);
      } else {
	fprintf(stderr,"Null answer!!!\n");
	return(1);
      }
    }
