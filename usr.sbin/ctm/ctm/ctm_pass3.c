#include "ctm.h"

/*---------------------------------------------------------------------------*/
/* Pass3 -- Validate the incomming CTM-file.
 */

int
Pass3(FILE *fd)
{
    u_char *p,*q,buf[BUFSIZ];
    MD5_CTX ctx;
    int i,j,sep,cnt;
    u_char *md5=0,*md5before=0,*trash=0,*name=0,*uid=0,*gid=0,*mode=0;
    struct CTM_Syntax *sp;
    FILE *ed=0;
    struct stat st;

    if(Verbose>3) 
	printf("Pass3 -- Applying the CTM-patch\n");
    MD5Init (&ctx);

    GETFIELD(p,' '); if(strcmp("CTM_BEGIN",p)) WRONG
    GETFIELD(p,' '); if(strcmp(Version,p)) WRONG
    GETFIELD(p,' '); if(strcmp(Name,p)) WRONG
    GETFIELD(p,' '); if(strcmp(Nbr,p)) WRONG
    GETFIELD(p,' '); if(strcmp(TimeStamp,p)) WRONG
    GETFIELD(p,'\n'); if(strcmp(Prefix,p)) WRONG

    for(;;) {
	if(md5)		{Free(md5), md5 = 0;}
	if(uid)		{Free(uid), uid = 0;}
	if(gid)		{Free(gid), gid = 0;}
	if(mode)	{Free(mode), mode = 0;}
	if(md5before)	{Free(md5before), md5before = 0;}
	if(trash)	{Free(trash), trash = 0;}
	if(name)	{Free(name), name = 0;}
	cnt = -1;

	GETFIELD(p,' ');

	if (p[0] != 'C' || p[1] != 'T' || p[2] != 'M') WRONG

	if(!strcmp(p+3,"_END"))
	    break;

	for(sp=Syntax;sp->Key;sp++)
	    if(!strcmp(p+3,sp->Key))
		goto found;
	WRONG
    found:
	for(i=0;(j = sp->List[i]);i++) {
	    if (sp->List[i+1] && (sp->List[i+1] & CTM_F_MASK) != CTM_F_Bytes)
		sep = ' ';
	    else
		sep = '\n';

	    switch (j & CTM_F_MASK) {
		case CTM_F_Name: GETFIELDCOPY(name,sep); break;
		case CTM_F_Uid:  GETFIELDCOPY(uid,sep); break;
		case CTM_F_Gid:  GETFIELDCOPY(gid,sep); break;
		case CTM_F_Mode: GETFIELDCOPY(mode,sep); break;
		case CTM_F_MD5:
		    if(j & CTM_Q_MD5_Before)
			GETFIELDCOPY(md5before,sep); 
		    else
			GETFIELDCOPY(md5,sep); 
		    break;
		case CTM_F_Count: GETBYTECNT(cnt,sep); break;
		case CTM_F_Bytes: GETDATA(trash,cnt); break;
		default: WRONG
		}
	    }
	j = strlen(name)-1;
	if(name[j] == '/') name[j] = '\0';
	fprintf(stderr,"> %s %s\n",sp->Key,name);
	if(!strcmp(sp->Key,"FM") || !strcmp(sp->Key, "FS")) {
	    i = open(name,O_WRONLY|O_CREAT|O_TRUNC,0644);
	    if(i < 0) {
		perror(name);
		continue;
	    }
	    if(cnt != write(i,trash,cnt)) {
		perror(name);
		continue;
	    }
	    close(i);
	    if(strcmp(md5,MD5File(name))) {
		fprintf(stderr,"  %s %s MD5 didn't come out right\n",
		   sp->Key,name);
		continue;
	    }
	    continue;
	} 
	if(!strcmp(sp->Key,"FE")) {
	    ed = popen("ed","w");
	    if(!ed) {
		WRONG
	    }
	    fprintf(ed,"e %s\n",name);
	    if(cnt != fwrite(trash,1,cnt,ed)) {
		perror(name);
		pclose(ed);
		continue;
	    }
	    fprintf(ed,"w %s\n",name);
	    if(pclose(ed)) {
		perror("ed");
		continue;
	    }
	    if(strcmp(md5,MD5File(name))) {
		fprintf(stderr,"  %s %s MD5 didn't come out right\n",
		   sp->Key,name);
		continue;
	    }
	    continue;
	}
	if(!strcmp(sp->Key,"DM")) {
	    if(0 > mkdir(name,0755)) {
		sprintf(buf,"mkdir -p %s",name);
		system(buf);
	    }
	    if(0 > stat(name,&st) || ((st.st_mode & S_IFMT) != S_IFDIR)) {
		fprintf(stderr,"<%s> mkdir failed\n",name);
		exit(1);
	    }
	    continue;
	} 
	if(!strcmp(sp->Key,"DR") || !strcmp(sp->Key,"FR")) {
	    if(0 > unlink(name)) {
		sprintf(buf,"rm -rf %s",name);
		system(buf);
	    }
	    continue;
	} 
	WRONG
    }
    q = MD5End (&ctx);
    GETFIELD(p,'\n');
    if(strcmp(q,p)) WRONG
    if (-1 != getc(fd)) WRONG
    return 0;
}
