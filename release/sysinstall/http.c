#include "sysinstall.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <netdb.h>

int HttpPort;

Boolean
mediaInitHTTP(Device *dev)
{
/* 
 * Some proxies think that files with the extension ".ai" are postscript
 * files and use "ascii mode" instead of "binary mode" for ftp.
 * The FTP server then translates all LF to CRLF.
 * I don't know how to handle this elegantly...
 * Squid uses ascii mode, ftpget uses binary mode and both tell us:
 * "Content-Type: application/postscript"
 *
 * Probably the safest way would be to get the file, look at its checksum
 * and, if it doesn't match, replace all CRLF by LF and check again.
 *
 * You can force Squid to use binary mode by appending ";type=i" to the URL,
 * which is what I do here.
 *
 */

    extern int h_errno;
    int rv,s;
    bool el;                    /* end of header line */
    char *cp, buf[PATH_MAX], req[1000];
    struct sockaddr_in peer;
    struct hostent *peer_in;

    s=socket(PF_INET, SOCK_STREAM, 6);    /* tcp */
    if (s == -1) {
      msgConfirm("Network error");
      return FALSE;
    }

    peer_in=gethostbyname(variable_get(VAR_HTTP_HOST));
    if (peer_in == NULL) {
      msgConfirm("%s",hstrerror(h_errno));
      return FALSE;
    }

    peer.sin_len=peer_in->h_length;
    peer.sin_family=peer_in->h_addrtype;
    peer.sin_port=htons((u_short) HttpPort);
    bcopy(peer_in->h_addr_list[0], &peer.sin_addr, peer_in->h_length);

    rv=connect(s,(struct sockaddr *)&peer,sizeof(peer));
    if (rv == -1) {
      msgConfirm("Couldn't connect to proxy %s:%s",
                  variable_get(VAR_HTTP_HOST),variable_get(VAR_FTP_PORT));
      return FALSE;
    }

    sprintf(req,"GET / HTTP/1.0\r\n\r\n");
    write(s,req,strlen(req));
/*
 *  scan the headers of the response
 *  this is extremely quick'n dirty
 *
 */
    cp=buf;
    el=FALSE;
    rv=read(s,cp,1);
    variable_set2(VAR_HTTP_FTP_MODE,"",0);
    while (rv>0) {
      if ((*cp == '\012') && el) { 
        /* reached end of a header line */
        if (!strncmp(buf,"Server: ",8)) {
          if (!strncmp(buf,"Server: Squid",13)) {
            variable_set2(VAR_HTTP_FTP_MODE,";type=i",1);
          } else {
            variable_set2(VAR_HTTP_FTP_MODE,"",1);
          }
        }
        /* ignore other headers */
        /* check for "\015\012" at beginning of line, i.e. end of headers */
        if ((cp-buf) == 1)
          break;
        cp=buf;
        rv=read(s,cp,1);
      } else {
        el=FALSE;
        if (*cp == '\015')
          el=TRUE;
        cp++;
        rv=read(s,cp,1);
      }
    }
    close(s);
    return TRUE;
} 


FILE *
mediaGetHTTP(Device *dev, char *file, Boolean probe)
{
    FILE *fp;
    int rv,s;
    bool el;			/* end of header line */
    char *cp, buf[PATH_MAX], req[1000];
    struct sockaddr_in peer;
    struct hostent *peer_in;

    s=socket(PF_INET, SOCK_STREAM, 6);    /* tcp */
    if (s == -1) {
      msgConfirm("Network error");
      return NULL;
    }
      
    peer_in=gethostbyname(variable_get(VAR_HTTP_HOST));
    peer.sin_len=peer_in->h_length;
    peer.sin_family=peer_in->h_addrtype;
    peer.sin_port=htons((u_short) HttpPort);
    bcopy(peer_in->h_addr_list[0], &peer.sin_addr, peer_in->h_length);

    rv=connect(s,(struct sockaddr *)&peer,sizeof(peer));
    if (rv == -1) {
      msgConfirm("Couldn't connect to proxy %s:%s",
                  variable_get(VAR_HTTP_HOST),variable_get(VAR_FTP_PORT));
      return NULL;
    }
                                                   
    sprintf(req,"GET ftp://%s:%s%s%s/%s%s HTTP/1.0\r\n\r\n",
            variable_get(VAR_FTP_HOST), variable_get(VAR_FTP_PORT),
            "/pub/FreeBSD/", variable_get(VAR_RELNAME),
            file,variable_get(VAR_HTTP_FTP_MODE));
    msgDebug("sending http request: %s",req);
    write(s,req,strlen(req));

/*
 *  scan the headers of the response
 *  this is extremely quick'n dirty
 *
 */
    cp=buf;
    el=FALSE;
    rv=read(s,cp,1);
    while (rv>0) {
      if ((*cp == '\012') && el) {
        /* reached end of a header line */
        if (!strncmp(buf,"HTTP",4)) {
          rv=strtol((char *)(buf+9),0,0);
          *(cp-1)='\0';		/* chop the CRLF off */
          if (rv >= 500) {
            msgConfirm("Server error %s, you could try an other server",buf);
            return NULL;
          } else if (rv == 404) {
            msgConfirm("%s was not found, maybe directory or release-version are wrong?",req);
            return NULL;
          } else if (rv >= 400) {
            msgConfirm("Client error %s, you could try an other server",buf);
            return NULL;
          } else if (rv >= 300) {
            msgConfirm("Error %s,",buf);
            return NULL;
          } else if (rv != 200) {
            msgConfirm("Error %s when trying to fetch %s",buf,req);
            return NULL;
          }
        }
        /* ignore other headers */
        /* check for "\015\012" at beginning of line, i.e. end of headers */
        if ((cp-buf) == 1) 
          break;
        cp=buf;
        rv=read(s,cp,1);
      } else {
        el=FALSE;
        if (*cp == '\015')
          el=TRUE;
        cp++;
        rv=read(s,cp,1);
      }
    }
    fp=fdopen(s,"r");
    return fp;
}
