/*
 *   Copyright (c) 1996, 1999 Hellmuth Michaelis.  All rights reserved.
 *
 *   Copyright (c) 1996 Gary Jennejohn.  All rights reserved. 
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *   3. Neither the name of the author nor the names of any co-contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *   4. Altered versions must be plainly marked as such, and must not be
 *      misrepresented as being the original software and/or documentation.
 *   
 *   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *   SUCH DAMAGE.
 *
 *---------------------------------------------------------------------------*
 *
 *	trace.c - print traces of D (B) channel activity for isdn4bsd
 *	-------------------------------------------------------------
 *
 *	$Id: trace.c,v 1.11 1999/02/14 09:44:58 hm Exp $ 
 *
 *      last edit-date: [Sun Feb 14 10:23:28 1999]
 *
 *	-hm	rewriting for isic and new trace format
 *	-hm	new option -f, use automatic name for -o
 *	-hm	changed default option setting
 *	-hm	multi unit support
 *	-hm	analyzer functionality
 *	-hm	binary record/playback
 *	-hm	-p option
 *	-hm	cleanup
 *	-hm	adding date to timestamp field
 *	-hm	reopen files on SIGUSR1 for rotation
 *	-hm	Joerg reported a bug with commandline options
 *	-hm	I.430 INFO signals from layer 1
 *
 *---------------------------------------------------------------------------*/

#include "trace.h"

unsigned char buf[BSIZE];
FILE *Fout = NULL;
FILE *BP = NULL;
int outflag = 1;
int header = 1;
int print_q921 = 1;
int unit = 0;
int dchan = 0;
int bchan = 0;
int traceon = 0;
int analyze = 0;
int Rx = RxUDEF;
int Tx = TxUDEF;
int f;
int Bopt = 0;
int Popt = 0;
int bpopt = 0;
int info = 0;
int Fopt = 0;

static char outfilename[1024];
static char BPfilename[1024];
static struct stat fst;

static void dumpbuf( int n, unsigned char *buf, i4b_trace_hdr_t *hdr, int raw );
static int switch_driver( int value, int rx, int tx );
static void usage( void );
static void exit_hdl( void );
static void reopenfiles( int );

/*---------------------------------------------------------------------------*
 *	usage instructions
 *---------------------------------------------------------------------------*/
void
usage(void)
{
	fprintf(stderr,"\n");
	fprintf(stderr,"isdntrace - i4b package ISDN trace facility for passive cards (%02d.%02d.%d)\n", VERSION, REL, STEP);
	fprintf(stderr,"usage: isdntrace -a -b -d -f <file> -h -i -l -n <val> -o -p <file> -r -u <unit>\n");
	fprintf(stderr,"                 -B -F -P -R <unit> -T <unit>\n");
	fprintf(stderr,"       -a        analyzer mode ................................... (default off)\n");
	fprintf(stderr,"       -b        switch B channel trace on ....................... (default off)\n");
	fprintf(stderr,"       -d        switch D channel trace off ....................... (default on)\n");
	fprintf(stderr,"       -f <file> write output to file filename ............ (default %s0)\n", TRACE_FILE_NAME);
	fprintf(stderr,"       -h        don't print header for each message ............. (default off)\n");
	fprintf(stderr,"       -i        print I.430 (layer 1) INFO signals .............. (default off)\n");	
	fprintf(stderr,"       -l        don't decode low layer Q.921 messages ........... (default off)\n");
	fprintf(stderr,"       -n <val>  process packet if it is longer than <val> octetts . (default 0)\n");
	fprintf(stderr,"       -o        don't write output to a file .................... (default off)\n");
	fprintf(stderr,"       -p <file> specify filename for -B and -P ........ (default %s0)\n", BIN_FILE_NAME);
	fprintf(stderr,"       -r        don't print raw hex/ASCII dump of protocol ...... (default off)\n");
	fprintf(stderr,"       -u <unit> specify controller unit number ............... (default unit 0)\n");
	fprintf(stderr,"       -B        write binary trace data to file filename ........ (default off)\n");
	fprintf(stderr,"       -F        with -P and -p: wait for more data at EOF ....... (default off)\n");
	fprintf(stderr,"       -P        playback from binary trace data file ............ (default off)\n");
	fprintf(stderr,"       -R <unit> analyze Rx controller unit number (for -a) ... (default unit %d)\n", RxUDEF);
	fprintf(stderr,"       -T <unit> analyze Tx controller unit number (for -a) ... (default unit %d)\n", TxUDEF);
	fprintf(stderr,"\n");
	exit(1);
}

/*---------------------------------------------------------------------------*
 *	main
 *---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	extern int optind;
	extern int opterr;
	extern char *optarg;
	char devicename[80];
	char headerbuf[256];
		
	int n;
	int c;
	char *b;

	int enable_trace = TRACE_D_RX | TRACE_D_TX;	
	char *outfile = TRACE_FILE_NAME;
	char *binfile = BIN_FILE_NAME;
	int outfileset = 0;
	int raw = 1;
	int noct = -1;
	time_t tm;
	i4b_trace_hdr_t *ithp = NULL;
	int l;
	static struct stat fstnew;	

	b = &buf[sizeof(i4b_trace_hdr_t)];
	
	while( (c = getopt(argc, argv, "abdf:hiln:op:ru:BFPR:T:?")) != EOF)
	{
		switch(c)
		{
			case 'a':
				analyze = 1;
				break;
				
			case 'b':
				enable_trace |= (TRACE_B_RX | TRACE_B_TX);
				break;

			case 'd':
				enable_trace &= (~(TRACE_D_TX | TRACE_D_RX));
				break;

			case 'o':
				outflag = 0;
				break;

			case 'f':
				outfile = optarg;
				outfileset = 1;
				break;
			
			case 'n':
				noct = atoi(optarg);
				break;

			case 'h':
				header = 0;
				break;

			case 'i':
				enable_trace |= TRACE_I;
				info = 1;
				break;

			case 'l':
				print_q921 = 0;
				break;

			case 'p':
				binfile = optarg;
				bpopt = 1;
				break;
			
			case 'r':
				raw = 0;
				break;

			case 'u':
				unit = atoi(optarg);
				if(unit < 0 || unit >= MAX_CONTROLLERS)
					usage();
				break;

			case 'B':
				Bopt = 1;
				break;
			
			case 'F':
				Fopt = 1;
				break;
			
			case 'P':
				Popt = 1;
				break;
			
			case 'R':
				Rx = atoi(optarg);
				if(Rx < 0 || Rx >= MAX_CONTROLLERS)
					usage();
				break;

			case 'T':
				Tx = atoi(optarg);
				if(Tx < 0 || Tx >= MAX_CONTROLLERS)
					usage();
				break;

			case '?':
			default:
				usage();
				break;
		}
	}

	if(enable_trace == 0)
		usage();

	if(Bopt && Popt)
		usage();
		
	atexit(exit_hdl);

	if(Bopt)
	{
		if(bpopt)
			sprintf(BPfilename, "%s", binfile);
		else
			sprintf(BPfilename, "%s%d", BIN_FILE_NAME, unit);
			
		if((BP = fopen(BPfilename, "r")) != NULL)
		{
			char buffer[1024];
			fclose(BP);
			sprintf(buffer, "%s%s", BPfilename, TRACE_FILE_NAME_BAK); 
			rename(BPfilename, buffer);
		}			
		if((BP = fopen(BPfilename, "w")) == NULL)
		{
			char buffer[80];

			sprintf(buffer, "Error opening file [%s]", BPfilename);
			perror(buffer);
			exit(1);
		}
		
		if((setvbuf(BP, (char *)NULL, _IONBF, 0)) != 0)
		{
			char buffer[80];

			sprintf(buffer, "Error setting file [%s] to unbuffered", BPfilename);
			perror(buffer);
			exit(1);
		}
	}		

	if(Popt)
	{
		if(bpopt)
			sprintf(BPfilename, "%s", binfile);
		else
			sprintf(BPfilename, "%s%d", BIN_FILE_NAME, unit);
  			
		if((BP = fopen(BPfilename, "r")) == NULL)
		{
			char buffer[80];

			sprintf(buffer, "Error opening file [%s]", BPfilename);
			perror(buffer);
			exit(1);
		}
		if(Fopt)
		{
			if(fstat(fileno(BP), &fst))
			{
				char buffer[80];
				sprintf(buffer, "Error fstat file [%s]", BPfilename);
				perror(buffer);
				exit(1);
			}
		}
	}
	else
	{		
		sprintf(devicename, "%s%d", I4BTRC_DEVICE, unit);
	
		if((f = open(devicename, O_RDWR)) < 0)
		{
			char buffer[80];
	
			sprintf(buffer, "Error opening trace device [%s]", devicename);
			perror(buffer);
			exit(1);
		}
	}
	
	if(outflag)
	{
		if(outfileset == 0)
			sprintf(outfilename, "%s%d", TRACE_FILE_NAME, unit);
		else
			strcpy(outfilename, outfile);
			
			
		if((Fout = fopen(outfilename, "r")) != NULL)
		{
			char buffer[1024];
			fclose(Fout);
			sprintf(buffer, "%s%s", outfilename, TRACE_FILE_NAME_BAK); 
			rename(outfilename, buffer);
		}
			
		if((Fout = fopen(outfilename, "w")) == NULL)
		{
			char buffer[80];

			sprintf(buffer, "Error opening file [%s]", outfilename);
			perror(buffer);
			exit(1);
		}
		
		if((setvbuf(Fout, (char *)NULL, _IONBF, 0)) != 0)
		{
			char buffer[80];

			sprintf(buffer, "Error setting file [%s] to unbuffered", outfile);
			perror(buffer);
			exit(1);
		}
	}

	if((setvbuf(stdout, (char *)NULL, _IOLBF, 0)) != 0)
	{
		char buffer[80];

		sprintf(buffer, "Error setting stdout to line-buffered");
		perror(buffer);
		exit(1);
	}

	if(!Popt)
	{
		if((switch_driver(enable_trace, Rx, Tx)) == -1)
			exit(1);
		else
			traceon = 1;
	}
		
	signal(SIGHUP, SIG_IGN);	/* ignore hangup signal */
	signal(SIGUSR1, reopenfiles);	/* rotate logfile(s)	*/	

	time(&tm);
	
	if(analyze)
	{
		sprintf(headerbuf, "\n==== isdnanalyze controller rx #%d - tx #%d ==== started %s",
				Rx, Tx, ctime(&tm));
	}
	else
	{
		sprintf(headerbuf, "\n=========== isdntrace controller #%d =========== started %s",
				unit, ctime(&tm));
	}
	
	printf("%s", headerbuf);
	
	if(outflag)
		fprintf(Fout, "%s", headerbuf);

	for (;;)
	{
		if(Popt == 0)
		{
			n = read(f, buf, BSIZE);

			if(Bopt)
			{
				if((fwrite(buf, 1, n, BP)) != n)
				{
					char buffer[80];
					sprintf(buffer, "Error writing file [%s]", BPfilename);
					perror(buffer);
					exit(1);
				}
			}

			n -= sizeof(i4b_trace_hdr_t);			
		}
		else
		{			
again:
			if((fread(buf, 1, sizeof(i4b_trace_hdr_t), BP)) != sizeof(i4b_trace_hdr_t))
			{
				if(feof(BP))
				{
					if(Fopt)
					{
						if(ferror(BP))
						{
							char buffer[80];
							sprintf(buffer, "Error reading hdr from file [%s]", BPfilename);
							perror(buffer);
							exit(1);
						}

						usleep(250000);
						clearerr(BP);

						if(stat(BPfilename, &fstnew) != -1)
						{
							if((fst.st_ino != fstnew.st_ino) ||
							   (fstnew.st_nlink == 0))
							{
								if((BP = freopen(BPfilename, "r", BP)) == NULL)
								{
									char buffer[80];
									sprintf(buffer, "Error reopening file [%s]", BPfilename);
									perror(buffer);
									exit(1);
								}
								stat(BPfilename, &fst);
							}
						}
						goto again;
					}
					else
					{
						printf("\nEnd of playback input file reached.\n");
						exit(0);
					}
				}
				else
				{
					char buffer[80];
					sprintf(buffer, "Error reading hdr from file [%s]", BPfilename);
					perror(buffer);
					exit(1);
				}
			}

			ithp = (i4b_trace_hdr_t *)buf;
			l = ithp->length - sizeof(i4b_trace_hdr_t);
			
			if((n = fread(buf+sizeof(i4b_trace_hdr_t), 1, l , BP)) != l)
			{
				char buffer[80];
				sprintf(buffer, "Error reading data from file [%s]", BPfilename);
				perror(buffer);
				exit(1);
			}

		}

		if((n > 0) && (n > noct))
		{
			dumpbuf(n, b, (i4b_trace_hdr_t *)buf, raw);
		}
	}
}

/*---------------------------------------------------------------------------*
 *	format header into static buffer, return buffer address
 *---------------------------------------------------------------------------*/
char *
fmt_hdr(i4b_trace_hdr_t *hdr, int frm_len)
{
	struct tm *s;
	static char hbuf[256];
	int i = 0;

	s = localtime(&(hdr->time.tv_sec));

	if(hdr->type == TRC_CH_I)		/* Layer 1 INFO's */
	{
		sprintf(hbuf,"\n-- %s - unit:%d ---------------- time:%2.2d.%2.2d %2.2d:%2.2d:%2.2d.%6u ",
			((hdr->dir) ? "NT->TE" : "TE->NT"),
			hdr->unit,
			s->tm_mday,
			s->tm_mon + 1,
			s->tm_hour,
			s->tm_min,
			s->tm_sec,
			(u_int32_t)hdr->time.tv_usec);
	}
	else
	{
		if(hdr->trunc > 0)
		{
			sprintf(hbuf,"\n-- %s - unit:%d - frame:%6.6u - time:%2.2d.%2.2d %2.2d:%2.2d:%2.2d.%6u - length:%d (%d) ",
				((hdr->dir) ? "NT->TE" : "TE->NT"),
				hdr->unit,
				hdr->count,
				s->tm_mday,
				s->tm_mon + 1,
				s->tm_hour,
				s->tm_min,
				s->tm_sec,
				(u_int32_t)hdr->time.tv_usec,
				frm_len,
				hdr->trunc);
		}
		else
		{
			sprintf(hbuf,"\n-- %s - unit:%d - frame:%6.6u - time:%2.2d.%2.2d %2.2d:%2.2d:%2.2d.%6u - length:%d ",
				((hdr->dir) ? "NT->TE" : "TE->NT"),
				hdr->unit,
				hdr->count,
				s->tm_mday,
				s->tm_mon + 1,
				s->tm_hour,
				s->tm_min,
				s->tm_sec,
				(u_int32_t)hdr->time.tv_usec,
				frm_len);
		}
	}
	
	for(i=strlen(hbuf); i <= NCOLS;)
		hbuf[i++] = '-';

	hbuf[i++] = '\n';
	hbuf[i] = '\0';
	
	return(hbuf);
}

/*---------------------------------------------------------------------------*
 *	decode protocol and output to file(s)
 *---------------------------------------------------------------------------*/
static void
dumpbuf(int n, unsigned char *buf, i4b_trace_hdr_t *hdr, int raw)
{
	static char l1buf[128];
	static unsigned char l2buf[32000];
	static unsigned char l3buf[32000];
	int cnt;
	int nsave = n;
	char *pbuf;
	int i, j;

	l1buf[0] = '\0';
	l2buf[0] = '\0';
	l3buf[0] = '\0';

	switch(hdr->type)
	{
		case TRC_CH_I:		/* Layer 1 INFO's */
			pbuf = &l1buf[0];

			switch(buf[0])
			{
				case INFO0:
					sprintf((pbuf+strlen(pbuf)),"I430: INFO0 (No Signal)\n");
					break;
	
				case INFO1_8:
					sprintf((pbuf+strlen(pbuf)),"I430: INFO1 (Activation Request, Priority = 8, from TE)\n");
					break;
	
				case INFO1_10:
					sprintf((pbuf+strlen(pbuf)),"I430: INFO1 (Activation Request, Priority = 10, from TE)\n");
					break;
	
				case INFO2:
					sprintf((pbuf+strlen(pbuf)),"I430: INFO2 (Pending Activation, from NT)\n");
					break;
	
				case INFO3:
					sprintf((pbuf+strlen(pbuf)),"I430: INFO3 (Synchronized, from TE)\n");
					break;
	
				case INFO4_8:
					sprintf((pbuf+strlen(pbuf)),"I430: INFO4 (Activated, Priority = 8/9, from NT)\n");
					break;
	
				case INFO4_10:
					sprintf((pbuf+strlen(pbuf)),"I430: INFO4 (Activated, Priority = 10/11, from NT)\n");
					break;
	
				default:
					sprintf((pbuf+strlen(pbuf)),"I430: ERROR, invalid INFO value 0x%x!\n", buf[0]);
					break;
			}
			break;
			
		case TRC_CH_D:		/* D-channel data */

			cnt = decode_lapd(l2buf, n, buf, hdr->dir, raw, print_q921);
		
			n -= cnt;
			buf += cnt;
		
			if(n)
			{
				switch(*buf)
				{
					case 0x40:
					case 0x41:
						decode_1tr6(l3buf, n, cnt, buf, raw);
						break;
						
					default:
						decode_q931(l3buf, n, cnt, buf, raw);
						break;
				}
			}
			break;

		default:	/* B-channel data */
	
			pbuf = &l2buf[0];
	
			for (i = 0; i < n; i += 16)
			{
				sprintf((pbuf+strlen(pbuf)),"B%d:%.3x  ", hdr->type, i);
	
				for (j = 0; j < 16; j++)
					if (i + j < n)
						sprintf((pbuf+strlen(pbuf)),"%02x ", buf[i + j]);
					else
						sprintf((pbuf+strlen(pbuf)),"   ");
	
				sprintf((pbuf+strlen(pbuf)),"      ");
	
				for (j = 0; j < 16 && i + j < n; j++)
					if (isprint(buf[i + j]))
						sprintf((pbuf+strlen(pbuf)),"%c", buf[i + j]);
					else
						sprintf((pbuf+strlen(pbuf)),".");
	
				sprintf((pbuf+strlen(pbuf)),"\n");
			}
			break;
	}
	
	if(header && ((l1buf[0] != '\0' || l2buf[0] != '\0') || (l3buf[0] != 0)))
	{
		char *p;
		p = fmt_hdr(hdr, nsave);
		printf("%s", p);
		if(outflag)
			fprintf(Fout, "%s", p);
	}

	if(l1buf[0] != '\0')
	{	
		printf("%s", l1buf);
		if(outflag)
			fprintf(Fout, "%s", l1buf);
	}

	if(l2buf[0] != '\0')
	{	
		printf("%s", l2buf);
		if(outflag)
			fprintf(Fout, "%s", l2buf);
	}

	if(l3buf[0] != '\0')
	{
		printf("%s", l3buf);
		if(outflag)
			fprintf(Fout, "%s", l3buf);
	}
}

/*---------------------------------------------------------------------------*
 *	exit handler function to be called at program exit
 *---------------------------------------------------------------------------*/
void
exit_hdl()
{
	if(traceon)
		switch_driver(TRACE_OFF, Rx, Tx);
}

/*---------------------------------------------------------------------------*
 *	switch driver debugging output on/off
 *---------------------------------------------------------------------------*/
static int
switch_driver(int value, int rx, int tx)
{
	char buffer[80];
	int v = value;

	if(analyze == 0)
	{
		if(ioctl(f, I4B_TRC_SET, &v) < 0)
		{
			sprintf(buffer, "Error ioctl I4B_TRC_SET, val = %d", v);
			perror(buffer);
			return(-1);
		}
	}
	else
	{
		if(value == TRACE_OFF)
		{
			if(ioctl(f, I4B_TRC_RESETA, &v) < 0)
			{
				sprintf(buffer, "Error ioctl I4B_TRC_RESETA - ");
				perror(buffer);
				return(-1);
			}
		}
		else
		{
			i4b_trace_setupa_t tsa;
			
			tsa.rxunit = rx;
			tsa.rxflags = value;
			tsa.txunit = tx;
			tsa.txflags = value;
			
			if(ioctl(f, I4B_TRC_SETA, &tsa) < 0)
			{
				sprintf(buffer, "Error ioctl I4B_TRC_SETA, val = %d", v);
				perror(buffer);
				return(-1);
			}
		}
	}
	return(0);
}

/*---------------------------------------------------------------------------*
 *	reopen files to support rotating logfile(s) on SIGUSR1
 *
 *	based on an idea from Ripley (ripley@nostromo.in-berlin.de)
 *
 *	close file and reopen it for append. this will be a nop
 *	if the previously opened file hasn't moved but will open
 *	a new one otherwise, thus enabling a rotation...
 * 
 *---------------------------------------------------------------------------*/
static void
reopenfiles(int dummy)
{
	if(outflag)
	{
		fclose(Fout);

		if((Fout = fopen(outfilename, "a")) == NULL)
		{
			char buffer[80];

			sprintf(buffer, "Error re-opening file [%s]", outfilename);
			perror(buffer);
			exit(1);
		}

		if((setvbuf(Fout, (char *)NULL, _IONBF, 0)) != 0)
		{
			char buffer[80];

			sprintf(buffer, "Error re-setting file [%s] to unbuffered", outfilename);
			perror(buffer);
			exit(1);
		}
	}

	if(Bopt)
	{
		
		fclose(BP);

		if((BP = fopen(BPfilename, "a")) == NULL)
		{
			char buffer[80];

			sprintf(buffer, "Error re-opening file [%s]", BPfilename);
			perror(buffer);
			exit(1);
		}

		if((setvbuf(BP, (char *)NULL, _IONBF, 0)) != 0)
		{
			char buffer[80];

			sprintf(buffer, "Error re-setting file [%s] to unbuffered", BPfilename);
			perror(buffer);
			exit(1);
		}
	}
}


/* EOF */	                                                                                                            	                               
