#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <dirent.h>
#include <md5.h>

int barf[256];

int 
pstrcmp(char **p, char **q)
{
    return strcmp(*p,*q);
}

int
Do(char *path)
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    int ret=0;
    u_char buf[BUFSIZ];
    u_char data[BUFSIZ],*q;
    int bufp;
    MD5_CTX ctx;
    int fd,i,j,k,l,npde,nde=0;
    char **pde;
 
    npde = 1;
    pde = malloc(sizeof *pde * (npde+1));
    d = opendir(path);
    if(!d) { perror(path); return 2; }
    if(!strcmp(path,".")) {
	*buf = 0;
    } else {
	strcpy(buf,path);
	if(buf[strlen(buf)-1] != '/')
	    strcat(buf,"/");
    }
    bufp = strlen(buf);
    while((de=readdir(d))) {
	if(!strcmp(de->d_name,".")) continue;
	if(!strcmp(de->d_name,"..")) continue;
	if(nde >= npde) {
	    npde *= 2;
	    pde = realloc(pde,sizeof *pde * (npde+1));
	}
	strcpy(buf+bufp,de->d_name);
	if(stat(buf,&st)) {
	    ret |= 1;
	    continue;
	}
	if((st.st_mode & S_IFMT) == S_IFDIR) {
	    strcat(buf,"/");
	}
	pde[nde] = malloc(strlen(buf+bufp)+1);
        strcpy(pde[nde++],buf+bufp);
    }
    closedir(d);
    if(!nde) return 0;
    qsort(pde,nde,sizeof *pde,pstrcmp);
    for(k=0;k<nde;k++) {
	strcpy(buf+bufp,pde[k]);
        free(pde[k]);
	if(stat(buf,&st)) {
	    ret |= 1;
	    continue;
	}
	switch(st.st_mode & S_IFMT) {
	    case S_IFDIR:
		i = printf("d %s %o %d %d - - -\n",	
		    buf,st.st_mode & (~S_IFMT),st.st_uid,st.st_gid);
		if(!i) 
		    exit(-1);
		ret |= Do(buf);
		break;
	    case S_IFREG:
		fd = open(buf,O_RDONLY);
		if(fd < 0) {
		    ret |= 1;
		    continue;
		}
		MD5Init(&ctx);
		l = j = 0;
		while(0 < (i = read(fd,data,sizeof data))) {
		    l = (data[i-1] == '\n');
		    MD5Update(&ctx,data,i);
		    for(q=data;i && !j;i--)
			if(barf[*q++])
			    j=1;
		}
		if(!l)
		    j=1;
		close(fd);
		i = printf("f %s %o %d %d %d %d %s\n",
		    buf,st.st_mode & (~S_IFMT),st.st_uid,st.st_gid,
		    j,st.st_size,MD5End(&ctx));
		if(!i) 
		    exit(-1);
		break;
	    default:
		fprintf(stderr,"%s: type 0%o\n",buf, st.st_mode & S_IFMT);
		ret |= 4;
		break;
	}
    }
    free(pde);
    return ret;
}

int
main(int argc, char **argv)
{
    /*
     * Initialize barf[], characters diff/patch will not appreciate.
     */

    barf[0x00] = 1;
    barf[0x7f] = 1;
    barf[0x80] = 1;
    barf[0xff] = 1;

    /*
     * First argument, if any, is where to do the work.
     */
    if (argc > 1) {
	if(chdir(argv[1])) {
	    perror(argv[1]);
	    return 2;
	}
    }

    /* 
     * Scan the directories recursively.
     */
    return Do(".");
}
