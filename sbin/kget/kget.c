/*-
 * Copyright (c) 1999 Andrzej Bialecki <abial@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: kget.c,v 1.1 1999/02/27 02:24:18 jkh Exp $
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <isa/isa_device.h>
#include <isa/pnp.h>

struct isa_device *id;
struct pnp_cinfo *c;
char *p;

int
main(int argc, char *argv[])
{
	int len,i;
	char *buf;
	char *mib1="machdep.uc_devlist";
	char *mib2="machdep.uc_pnplist";
	char name[9];
	FILE *fout;

	if(argc<2) {
		fout=stdout;
	} else {
		if(strcmp(argv[1],"-")==0) {
			fout=stdout;
		} else {
			fout=fopen(argv[1],"w");
			if(fout==NULL) {
				perror("opening output file");
				exit(1);
			}
		}
	}

	/* We use sysctlbyname, because the oid is unknown (OID_AUTO) */

	/* First, print the changes made to ISA devices */
	/* get the buffer size */
	i=sysctlbyname(mib1,NULL,&len,NULL,NULL);
	if(i) {
		perror("buffer sizing");
		exit(-1);
	}
	buf=(char *)malloc(len*sizeof(char));
	i=sysctlbyname(mib1,buf,&len,NULL,NULL);
	if(i) {
		perror("retrieving data");
		exit(-1);
	}
	i=0;
	while(i<len) {
		id=(struct isa_device *)(buf+i);
		p=(buf+i+sizeof(struct isa_device));
		strncpy(name,p,8);
		if(!id->id_enabled) {
			fprintf(fout,"di %s%d\n",name,id->id_unit);
		} else {
			fprintf(fout,"en %s%d\n",name,id->id_unit);
			if(id->id_iobase>0) {
				fprintf(fout,"po %s%d %#x\n",name,id->id_unit,
					id->id_iobase);
			}
			if(id->id_irq>0) {
				fprintf(fout,"ir %s%d %d\n",name,id->id_unit,
					ffs(id->id_irq)-1);
			}
			if(id->id_drq>0) {
				fprintf(fout,"dr %s%d %d\n",name,id->id_unit,
					id->id_drq);
			}
			if(id->id_maddr>0) {
				fprintf(fout,"iom %s%d %#x\n",name,id->id_unit,
					id->id_maddr);
			}
			if(id->id_msize>0) {
				fprintf(fout,"ios %s%d %d\n",name,id->id_unit,
					id->id_msize);
			}
			fprintf(fout,"f %s%d %#x\n",name,id->id_unit,
				id->id_flags);
		}
		i+=sizeof(struct isa_device)+8;
	}
	free(buf);
	/* Now, print the changes to PnP override table */
	/* get the buffer size */
	i=sysctlbyname(mib2,NULL,&len,NULL,NULL);
	if(i) {
		/* Hmm.. No PnP table? */
		goto finish;
	}
	buf=(char *)malloc(len*sizeof(char));
	i=sysctlbyname(mib2,buf,&len,NULL,NULL);
	if(i) {
		perror("retrieving data");
		exit(-1);
	}
	i=0;
	/* Print the PnP override table. Taken from userconfig.c */
	do {
		c = (struct pnp_cinfo *)(buf+i);
		if (c->csn >0 && c->csn != 255) {
	    		int pmax, mmax;
	    		char buf1[256];

			if(c->enable==0) {
				fprintf(fout,"pnp %d %d disable\n",
					c->csn, c->ldn);
				continue;
			}
			fprintf(fout,"pnp %d %d %s irq0 %d irq1 %d drq0 %d drq1 %d",
				c->csn, c->ldn,
				c->override ? "os":"bios",
				c->irq[0], c->irq[1], c->drq[0], c->drq[1]);
	    		if (c->flags)
				fprintf(fout," flags 0x%lx",c->flags);
			pmax=0;
			while(c->port[pmax]!=0 && pmax<8) {
				fprintf(fout," port%d %d",pmax,c->port[pmax]);
				pmax++;
			}
			mmax=0;
			while(c->mem[mmax].base!=0 && mmax<8) {
				fprintf(fout," mem%d %d",mmax,c->mem[mmax].base);
				mmax++;
			}
	    		fprintf(fout,"\n");
    		}

	} while ((i+=sizeof(struct pnp_cinfo))<len);
	free(buf);
finish:
	fprintf(fout,"q\n");
	fclose(fout);
	exit(0);
}
