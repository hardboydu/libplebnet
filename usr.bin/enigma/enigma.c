/*
 *	"enigma.c" is in file cbw.tar from
 *	anonymous FTP host watmsg.waterloo.edu: pub/crypt/cbw.tar.Z
 *
 *	A one-rotor machine designed along the lines of Enigma
 *	but considerably trivialized.
 *
 *	A public-domain replacement for the UNIX "crypt" command.
 *
 *	Upgraded to function properly on 64-bit machines.
 */

#define ECHO 010
#include <stdio.h>
#define ROTORSZ 256
#define MASK 0377
char	t1[ROTORSZ];
char	t2[ROTORSZ];
char	t3[ROTORSZ];
char	deck[ROTORSZ];
char	*getpass();
char	buf[13];

void	shuffle();
void	puth();

void
setup(pw)
char *pw;
{
	int ic, i, k, temp, pf[2], pid;
	unsigned random;
	long seed;

	strncpy(buf, pw, 8);
	while (*pw)
		*pw++ = '\0';
	buf[8] = buf[0];
	buf[9] = buf[1];
	pipe(pf);
	if ((pid=fork())==0) {
		close(0);
		close(1);
		dup(pf[0]);
		dup(pf[1]);
		execlp("makekey", "-", 0);
		execl("/usr/libexec/makekey", "-", 0);	/* BSDI */
		execl("/usr/lib/makekey", "-", 0);
		execl("/usr/bin/makekey", "-", 0);	/* IBM */
		execl("/lib/makekey", "-", 0);
		perror("makekey");
		fprintf(stderr, "enigma: cannot execute 'makekey', aborting\n");
		exit(1);
	}
	write(pf[1], buf, 10);
	close(pf[1]);
	i=wait((int *)NULL);
	if (i<0) perror("enigma: wait");
	if (i!=pid) {
		fprintf(stderr, "enigma: expected pid %d, got pid %d\n", pid, i);
		exit(1);
	}
	if ((i=read(pf[0], buf, 13)) != 13) {
		fprintf(stderr, "enigma: cannot generate key, read %d\n",i);
		exit(1);
	}
	seed = 123;
	for (i=0; i<13; i++)
		seed = seed*buf[i] + i;
	for(i=0;i<ROTORSZ;i++) {
		t1[i] = i;
		deck[i] = i;
	}
	for(i=0;i<ROTORSZ;i++) {
		seed = 5*seed + buf[i%13];
		if( sizeof(long) > 4 )  {
			/* Force seed to stay in 32-bit signed math */
			if( seed & 0x80000000 )
				seed = seed | (-1L & ~0xFFFFFFFFL);
			else
				seed &= 0x7FFFFFFF;
		}
		random = seed % 65521;
		k = ROTORSZ-1 - i;
		ic = (random&MASK)%(k+1);
		random >>= 8;
		temp = t1[k];
		t1[k] = t1[ic];
		t1[ic] = temp;
		if(t3[k]!=0) continue;
		ic = (random&MASK) % k;
		while(t3[ic]!=0) ic = (ic+1) % k;
		t3[k] = ic;
		t3[ic] = k;
	}
	for(i=0;i<ROTORSZ;i++)
		t2[t1[i]&MASK] = i;
}

main(argc, argv)
char *argv[];
{
	register int i, n1, n2, nr1, nr2;
	int secureflg = 0;

	if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 's') {
		argc--;
		argv++;
		secureflg = 1;
	}
	if (argc != 2){
		setup(getpass("Enter key:"));
	}
	else
		setup(argv[1]);
	n1 = 0;
	n2 = 0;
	nr2 = 0;

	while((i=getchar()) >=0) {
		if (secureflg) {
			nr1 = deck[n1]&MASK;
			nr2 = deck[nr1]&MASK;
		} else {
			nr1 = n1;
		}
		i = t2[(t3[(t1[(i+nr1)&MASK]+nr2)&MASK]-nr2)&MASK]-nr1;
		putchar(i);
		n1++;
		if(n1==ROTORSZ) {
			n1 = 0;
			n2++;
			if(n2==ROTORSZ) n2 = 0;
			if (secureflg) {
				shuffle(deck);
			} else {
				nr2 = n2;
			}
		}
	}
}

void
shuffle(deck)
	char deck[];
{
	int i, ic, k, temp;
	unsigned random;
	static long seed = 123;

	for(i=0;i<ROTORSZ;i++) {
		seed = 5*seed + buf[i%13];
		random = seed % 65521;
		k = ROTORSZ-1 - i;
		ic = (random&MASK)%(k+1);
		temp = deck[k];
		deck[k] = deck[ic];
		deck[ic] = temp;
	}
}

void
puth( title, cp, len )
char	*title;
char	*cp;
int	len;
{
	fprintf( stderr, "%s = ", title);
	while( len-- > 0 )  {
		fprintf(stderr, "%2.2x ", (*cp++) & 0xFF );
	}
	fprintf(stderr,"\n");
}
