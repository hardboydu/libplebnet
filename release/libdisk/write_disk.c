/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $Id: write_disk.c,v 1.2 1995/04/30 06:09:29 phk Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/disklabel.h>
#include <sys/diskslice.h>
#include "libdisk.h"

#define DOSPTYP_EXTENDED        5
#define DOSPTYP_ONTRACK         84      
#define BBSIZE			8192 

#define WHERE(offset,disk) (disk->flags & DISK_ON_TRACK ? offset + 63 : offset)
int
Write_FreeBSD(int fd, struct disk *new, struct disk *old, struct chunk *c1)
{
	struct disklabel *dl;
	struct chunk *c2;
	int i,j;
	void *p;
	u_char buf[BBSIZE];

	for(i=0;i<BBSIZE/512;i++) {
		p = read_block(fd,i + c1->offset);
		memcpy(buf+512*i,p,512);
		free(p);
	}
	if(new->boot1)
		memcpy(buf,new->boot1,512);

	if(new->boot2)
		memcpy(buf+512,new->boot2,BBSIZE-512);

	dl = (struct disklabel *) (buf+512*LABELSECTOR+LABELOFFSET);
	memset(dl,0,sizeof *dl);

	printf("--> Write_FreeBSD()\n");

	for(c2=c1->part;c2;c2=c2->next) {
		if (c2->type == unused) continue;
		if (c2->type == reserved) continue;
		if (!strcmp(c2->name,"X")) continue;
		j = c2->name[5] - 'a';
		if (j < 0 || j >= MAXPARTITIONS || j == RAW_PART) {
			warn("Weird parititon letter %c",c2->name[5]);
			continue;
		}
		dl->d_partitions[j].p_size = c2->size;
		dl->d_partitions[j].p_offset = c2->offset - c1->offset;
		
	}

	dl->d_bbsize = BBSIZE;

	strcpy(dl->d_typename,c1->name);

	dl->d_secperunit = new->chunks->size;
	dl->d_secpercyl = new->real_cyl ? new->real_cyl : new->bios_cyl;
	dl->d_ntracks = new->real_hd ? new->real_hd : new->bios_hd;
	dl->d_nsectors = new->real_sect ? new->real_sect : new->bios_sect;

	dl->d_npartitions = MAXPARTITIONS;

	dl->d_type = new->name[0] == 's' ? DTYPE_SCSI : DTYPE_ESDI;
	dl->d_partitions[RAW_PART].p_size = c1->size;
	dl->d_partitions[RAW_PART].p_offset = 0;

	dl->d_magic = DISKMAGIC;
	dl->d_magic2 = DISKMAGIC;
	dl->d_checksum = dkcksum(dl);

	for(i=0;i<BBSIZE/512;i++) {
		write_block(fd,WHERE(i + c1->offset,new),buf+512*i);
	}
		
	return 0;
}

int
Write_Extended(int fd, struct disk *new, struct disk *old, struct chunk *c1)
{
	printf("--> Write_Extended()\n");
	Print_Chunk(c1);	
	return 0;
}

int
Write_Disk(struct disk *d1)
{
	int fd,i,j;
	struct disk *old = 0;
	struct chunk *c1;
	int ret = 0;
	char device[64];
	u_char *mbr;
	struct dos_partition *dp;
	int s[4];

	strcpy(device,"/dev/r");
        strcat(device,d1->name);

        fd = open(device,O_RDWR);
        if (fd < 0) {
                warn("open(%s) failed",device);
                return 1;
        }

	memset(s,0,sizeof s);
	mbr = read_block(fd,0);
	dp = (struct dos_partition*) (mbr + DOSPARTOFF);
	for (c1=d1->chunks->part; c1 ; c1 = c1->next) {
		if (c1->type == unused) continue;
		if (c1->type == reserved) continue;
		if (!strcmp(c1->name,"X")) continue;
		if (c1->type == extended)
			ret += Write_Extended(fd, d1,old,c1);
		if (c1->type == freebsd)
			ret += Write_FreeBSD(fd, d1,old,c1);
		j = c1->name[4] - '1';
		if (j < 0 || j > 3)
			continue;
		s[j]++;
		dp[j].dp_start = c1->offset;
		dp[j].dp_size = c1->size;

		i = c1->offset;
		if (i >= 1024*d1->bios_sect*d1->bios_hd) {
			dp[j].dp_ssect = 0xff;
			dp[j].dp_shd = 0xff;
			dp[j].dp_scyl = 0xff;
			
		} else {
			dp[j].dp_ssect = i % d1->bios_sect;
			i -= dp[j].dp_ssect;
			i /= d1->bios_sect;	
			dp[j].dp_ssect++;
			dp[j].dp_shd =  i % d1->bios_hd;
			i -= dp[j].dp_shd;
			i /= d1->bios_hd;
			dp[j].dp_scyl = i;
		}

		i = c1->end;
		if (i >= 1024*d1->bios_sect*d1->bios_hd) {
			dp[j].dp_esect = 0xff;
			dp[j].dp_ehd = 0xff;
			dp[j].dp_ecyl = 0xff;
		} else {
			dp[j].dp_esect = i % d1->bios_sect;
			i -= dp[j].dp_esect;
			i /= d1->bios_sect;	
			dp[j].dp_esect++;
			dp[j].dp_ehd =  i % d1->bios_hd;
			i -= dp[j].dp_ehd;
			i /= d1->bios_hd;
			dp[j].dp_ecyl = i;
		}

		switch (c1->type) {
			case freebsd:
				dp[j].dp_typ = 0xa5;
				break;
			case fat:
				dp[j].dp_typ = 1;
				break;
			case extended:
				dp[j].dp_typ = 5;
				break;
			case foo:
				dp[j].dp_typ = - c1->subtype;
				break;
		}	
	}
	for(i=0;i<NDOSPART;i++)
		if (!s[i])
			memset(dp+i,0,sizeof *dp);
	
	mbr[512-2] = 0x55;
	mbr[512-1] = 0xaa;
	write_block(fd,WHERE(0,d1),mbr);

	close(fd);
	return 0;
}

