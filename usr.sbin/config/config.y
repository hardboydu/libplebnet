%union {
	char	*str;
	int	val;
	struct	file_list *file;
}

%token	AND
%token	ANY
%token	ARGS
%token	AT
%token	BIO
%token	BUS
%token	CAM
%token	COMMA
%token	CONFIG
%token	CONFLICTS
%token	CONTROLLER
%token	CPU
%token	DEVICE
%token	DISABLE
%token	DISK
%token	DRIVE
%token	DRQ
%token	DUMPS
%token	EQUALS
%token	FLAGS
%token	IDENT
%token	IOMEM
%token	IOSIZ
%token	IRQ
%token	MACHINE
%token	MAJOR
%token	MASTER
%token	MAXUSERS
%token	MINOR
%token	MINUS
%token	NET
%token	NEXUS
%token	ON
%token	OPTIONS
%token	MAKEOPTIONS
%token	PORT
%token	PRIORITY
%token	PSEUDO_DEVICE
%token	ROOT
%token	SEMICOLON
%token	SEQUENTIAL
%token	SIZE
%token	SLAVE
%token	SWAP
%token	TARGET
%token	TTY
%token	TRACE
%token	UNIT
%token	VECTOR

%token	<str>	ID
%token	<val>	NUMBER
%token	<val>	FPNUMBER

%type	<str>	Save_id
%type	<str>	Opt_value
%type	<str>	Dev
%type	<str>	device_name
%type	<val>	major_minor
%type	<val>	root_device_spec root_device_specs
%type	<val>	dump_device_spec
%type	<file>	swap_device_spec

%{

/*
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)config.y	8.1 (Berkeley) 6/6/93
 */

#include <sys/disklabel.h>
#include <sys/diskslice.h>

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

static struct	device cur;
static struct	device *curp = 0;

struct  device *dtab;
char	*ident;
int	yyline;
struct  file_list *ftab, *conf_list, **confp, *comp_list, **compp;
char	errbuf[80];
int	maxusers;
int	do_trace;

int	seen_scbus;

#define ns(s)	strdup(s)

static int alreadychecked __P((dev_t, dev_t[], dev_t *));
static void deverror __P((char *, char *));
static int finddev __P((dev_t));
static struct device *connect __P((char *, int));
static struct device *huhcon __P((char *));
static dev_t *verifyswap __P((struct file_list *, dev_t *, dev_t *));
static void yyerror __P((char *s));


%}
%%
Configuration:
	Many_specs
		= { verifysystemspecs(); }
		;

Many_specs:
	Many_specs Spec
		|
	/* lambda */
		;

Spec:
	Device_spec SEMICOLON
	      = { newdev(&cur); } |
	Config_spec SEMICOLON
		|
	TRACE SEMICOLON
	      = { do_trace = !do_trace; } |
	SEMICOLON
		|
	error SEMICOLON
		;

Config_spec:
	MACHINE Save_id
	    = {
		if (!strcmp($2, "i386")) {
			machine = MACHINE_I386;
			machinename = "i386";
		} else if (!strcmp($2, "pc98")) {
			machine = MACHINE_PC98;
			machinename = "pc98";
		} else if (!strcmp($2, "alpha")) {
			machine = MACHINE_ALPHA;
			machinename = "alpha";
		} else
			yyerror("Unknown machine type");
	      } |
	CPU Save_id
	      = {
		struct cputype *cp =
		    (struct cputype *)malloc(sizeof (struct cputype));
		memset(cp, 0, sizeof(*cp));
		cp->cpu_name = $2;
		cp->cpu_next = cputype;
		cputype = cp;
	      } |
	OPTIONS Opt_list
		|
	MAKEOPTIONS Mkopt_list
		|
	IDENT ID
	      = { ident = $2; } |
	System_spec
		|
	MAXUSERS NUMBER
	      = { maxusers = $2; };

System_spec:
	  System_id System_parameter_list
		= { checksystemspec(*confp); }
	;
		
System_id:
	  CONFIG Save_id
		= { mkconf($2); }
	;

System_parameter_list:
	  System_parameter_list System_parameter
	| System_parameter
	;

System_parameter:
	  addr_spec
	| swap_spec
	| root_spec
	| dump_spec
	| arg_spec
	;
	
addr_spec:
	  AT NUMBER
		= { loadaddress = $2; }
	;

swap_spec:
	  SWAP optional_on swap_device_list
		= { yyerror("swap specification obsolete, ignored"); }
	;
	
swap_device_list:
	  swap_device_list AND swap_device
	| swap_device
	;
	
swap_device:
	  swap_device_spec optional_size optional_sflag
	;

swap_device_spec:
	  device_name
		= {
			struct file_list *fl = newflist(SWAPSPEC);

			if (eq($1, "generic"))
				fl->f_fn = $1;
			else {
				fl->f_swapdev = nametodev($1, 0,
						    COMPATIBILITY_SLICE, 'b');
				fl->f_fn = devtoname(fl->f_swapdev);
			}
			$$ = fl;
		}
	| major_minor
		= {
			struct file_list *fl = newflist(SWAPSPEC);

			fl->f_swapdev = $1;
			fl->f_fn = devtoname($1);
			$$ = fl;
		}
	;

root_spec:
	  ROOT optional_on root_device_specs
		= {
			struct file_list *fl = *confp;

			if (fl && fl->f_rootdev != NODEV)
				yyerror("extraneous root device specification");
			else
				fl->f_rootdev = $3;
		}
	;

root_device_specs:
	  root_device_spec AND root_device_specs
		= {
			warnx("extraneous root devices ignored");
			$$ = $1;
		  }
	| root_device_spec
	;

root_device_spec:
	  device_name
		= { $$ = nametodev($1, 0, COMPATIBILITY_SLICE, 'a'); }
	| major_minor
	;

dump_spec:
	  DUMPS optional_on dump_device_spec
		= {
			struct file_list *fl = *confp;

			if (fl && fl->f_dumpdev != NODEV)
				yyerror("extraneous dump device specification");
			else
				fl->f_dumpdev = $3;
		}

	;

dump_device_spec:
	  device_name
		= { $$ = nametodev($1, 0, COMPATIBILITY_SLICE, 'b'); }
	| major_minor
	;

arg_spec:
	  ARGS optional_on arg_device_spec
		= { yyerror("arg device specification obsolete, ignored"); }
	;

arg_device_spec:
	  device_name
	| major_minor
	;

major_minor:
	  MAJOR NUMBER MINOR NUMBER
		= { $$ = makedev($2, $4); }
	;

optional_on:
	  ON
	| /* empty */
	;

optional_size:
	  SIZE NUMBER
	      = { yyerror("`size nnn' swap spec obsolete"); }
	| /* empty */
	;

optional_sflag:
	  SEQUENTIAL
	      = { yyerror("`sequential' swap spec obsolete"); }
	| /* empty */
	;

device_name:
	  Save_id
		= { $$ = $1; }
	| Save_id NUMBER
		= {
			char buf[80];

			(void) snprintf(buf, sizeof(buf), "%s%d", $1, $2);
			$$ = ns(buf); free($1);
		}
	| Save_id NUMBER ID
		= {
			char buf[80];

			(void) snprintf(buf, sizeof(buf), "%s%d%s", $1, $2, $3);
			$$ = ns(buf); free($1);
		}
	| Save_id NUMBER ID NUMBER
		= {
			char buf[80];

			(void) snprintf(buf, sizeof(buf), "%s%d%s%d",
			     $1, $2, $3, $4);
			$$ = ns(buf); free($1);
		}
	| Save_id NUMBER ID NUMBER ID
		= {
			char buf[80];

			(void) snprintf(buf, sizeof(buf), "%s%d%s%d%s",
			     $1, $2, $3, $4, $5);
			$$ = ns(buf); free($1);
		}
	;

Opt_list:
	Opt_list COMMA Option
		|
	Option
		;

Option:
	Save_id
	      = {
		struct opt *op = (struct opt *)malloc(sizeof (struct opt));
		char *s;
		memset(op, 0, sizeof(*op));
		op->op_name = $1;
		op->op_next = opt;
		op->op_value = 0;
		/*
		 * op->op_line is 1-based; yyline is 0-based but is now 1
		 * larger than when `Save_id' was lexed.
		 */
		op->op_line = yyline;
		opt = op;
		if ((s = strchr(op->op_name, '='))) {
			warnx("line %d: The `=' in options should not be quoted", yyline);
			*s = '\0';
			op->op_value = ns(s + 1);
		}
	      } |
	Save_id EQUALS Opt_value
	      = {
		struct opt *op = (struct opt *)malloc(sizeof (struct opt));
		memset(op, 0, sizeof(*op));
		op->op_name = $1;
		op->op_next = opt;
		op->op_value = $3;
		op->op_line = yyline + 1;
		opt = op;
	      } ;

Opt_value:
	ID
		= { $$ = $1; } |
	NUMBER
		= {
			char buf[80];

			(void) snprintf(buf, sizeof(buf), "%d", $1);
			$$ = ns(buf);
		} ;

Save_id:
	ID
	      = { $$ = $1; }
	;

Mkopt_list:
	Mkopt_list COMMA Mkoption
		|
	Mkoption
		;

Mkoption:
	Save_id EQUALS Opt_value
	      = {
		struct opt *op = (struct opt *)malloc(sizeof (struct opt));
		memset(op, 0, sizeof(*op));
		op->op_name = $1;
		op->op_ownfile = 0;	/* for now */
		op->op_next = mkopt;
		op->op_value = $3;
		op->op_line = yyline + 1;
		mkopt = op;
	      } ;

Dev:
	ID
	      = { $$ = $1; }
	;

Device_spec:
	DEVICE Dev_name Dev_info Int_spec
	      = { cur.d_type = DEVICE; } |
	MASTER Dev_name Dev_info Int_spec
	      = { cur.d_type = MASTER; } |
	DISK Dev_name Dev_info Int_spec
	      = { cur.d_dk = 1; cur.d_type = DEVICE; } |
	CONTROLLER Dev_name Dev_info Int_spec
	      = { cur.d_type = CONTROLLER; } |
	PSEUDO_DEVICE Init_dev Dev
	      = {
		cur.d_name = $3;
		cur.d_type = PSEUDO_DEVICE;
		} |
	PSEUDO_DEVICE Init_dev Dev NUMBER
	      = {
		cur.d_name = $3;
		cur.d_type = PSEUDO_DEVICE;
		cur.d_slave = $4;
		} ;

Dev_name:
	Init_dev Dev NUMBER
	      = {
		cur.d_name = $2;
		if (eq($2, "scbus"))
			seen_scbus = 1;
		cur.d_unit = $3;
		};

Init_dev:
	/* lambda */
	      = { init_dev(&cur); };

Dev_info:
	Con_info Info_list
		|
	/* lambda */
		;

Con_info:
	AT Dev NUMBER
	      = {
		if (eq(cur.d_name, "mba") || eq(cur.d_name, "uba")) {
			(void) snprintf(errbuf, sizeof(errbuf), 
				"%s must be connected to a nexus", cur.d_name);
			yyerror(errbuf);
		}
		cur.d_conn = connect($2, $3);
		} |
	AT NEXUS NUMBER
	      = { check_nexus(&cur, $3); cur.d_conn = TO_NEXUS; };
    
Info_list:
	Info_list Info
		|
	/* lambda */
		;

Info:
	BUS NUMBER
	      = {
		if (cur.d_conn != 0 && cur.d_conn->d_type == CONTROLLER)
			cur.d_slave = $2;
		else
			yyerror("can't specify a bus to something "
				 "other than a controller");
		} |
	TARGET NUMBER
	      = { cur.d_target = $2; } |
	UNIT NUMBER
	      = { cur.d_lun = $2; } |
	DRIVE NUMBER
	      = { cur.d_drive = $2; } |
	SLAVE NUMBER
	      = {
		if (cur.d_conn != 0 && cur.d_conn != TO_NEXUS &&
		    cur.d_conn->d_type == MASTER)
			cur.d_slave = $2;
		else
			yyerror("can't specify slave--not to master");
		} |
	IRQ NUMBER
	      = { cur.d_irq = $2; } |
	DRQ NUMBER
	      = { cur.d_drq = $2; } |
	IOMEM NUMBER
	      = { cur.d_maddr = $2; } |
	IOSIZ NUMBER
	      = { cur.d_msize = $2; } |
	PORT device_name
	      = { cur.d_port = $2; } |
	PORT NUMBER
	      = { cur.d_portn = $2; } |
	TTY 
	      = { yyerror("`tty' interrupt label obsolete"); } |
	BIO 
	      = { yyerror("`bio' interrupt label obsolete"); } |
	CAM 
	      = { yyerror("`cam' interrupt label obsolete"); } |
	NET 
	      = { yyerror("`net' interrupt label obsolete"); } |
	FLAGS NUMBER
	      = { cur.d_flags = $2; } |
	DISABLE	
	      = { cur.d_disabled = 1; } |
	CONFLICTS
	      = { cur.d_conflicts = 1; };

Int_spec:
	VECTOR ID
	      = { yyerror("`vector xxxintr' interrupt vector obsolete"); } |
	PRIORITY NUMBER
	      = { yyerror("`priority nnn' interrupt priority obsolete"); } |
	/* lambda */
		;

%%

static void
yyerror(s)
	char *s;
{

	warnx("line %d: %s", yyline + 1, s);
}

/*
 * add a device to the list of devices
 */
static void
newdev(dp)
	register struct device *dp;
{
	register struct device *np, *xp;

	if (dp->d_unit >= 0) {
		for (xp = dtab; xp != 0; xp = xp->d_next) {
			if ((xp->d_unit == dp->d_unit) &&
			    eq(xp->d_name, dp->d_name)) {
				warnx("line %d: already seen device %s%d",
				    yyline, xp->d_name, xp->d_unit);
			}
		}
	}
	np = (struct device *) malloc(sizeof *np);
	memset(np, 0, sizeof(*np));
	*np = *dp;
	np->d_next = 0;
	if (curp == 0)
		dtab = np;
	else
		curp->d_next = np;
	curp = np;
}

/*
 * note that a configuration should be made
 */
static void
mkconf(sysname)
	char *sysname;
{
	register struct file_list *fl, **flp;

	fl = (struct file_list *) malloc(sizeof *fl);
	memset(fl, 0, sizeof(*fl));
	fl->f_type = SYSTEMSPEC;
	fl->f_needs = sysname;
	fl->f_rootdev = NODEV;
	fl->f_dumpdev = NODEV;
	fl->f_fn = 0;
	fl->f_next = 0;
	for (flp = confp; *flp; flp = &(*flp)->f_next)
		;
	*flp = fl;
	confp = flp;
}

static struct file_list *
newflist(ftype)
	u_char ftype;
{
	struct file_list *fl = (struct file_list *)malloc(sizeof (*fl));
	memset(fl, 0, sizeof(*fl));

	fl->f_type = ftype;
	fl->f_next = 0;
	fl->f_swapdev = NODEV;
	fl->f_swapsize = 0;
	fl->f_needs = 0;
	fl->f_fn = 0;
	return (fl);
}

/*
 * Add a swap device to the system's configuration
 */
static void
mkswap(system, fl, size, flag)
	struct file_list *system, *fl;
	int size, flag;
{
	register struct file_list **flp;

	if (system == 0 || system->f_type != SYSTEMSPEC) {
		yyerror("\"swap\" spec precedes \"config\" specification");
		return;
	}
	if (size < 0) {
		yyerror("illegal swap partition size");
		return;
	}
	/*
	 * Append swap description to the end of the list.
	 */
	flp = &system->f_next;
	for (; *flp && (*flp)->f_type == SWAPSPEC; flp = &(*flp)->f_next)
		;
	fl->f_next = *flp;
	*flp = fl;
	fl->f_swapsize = size;
	fl->f_swapflag = flag;
	/*
	 * If first swap device for this system,
	 * set up f_fn field to insure swap
	 * files are created with unique names.
	 */
	if (system->f_fn)
		return;
	if (eq(fl->f_fn, "generic"))
		system->f_fn = ns(fl->f_fn);
	else
		system->f_fn = ns(system->f_needs);
}

/*
 * find the pointer to connect to the given device and number.
 * returns 0 if no such device and prints an error message
 */
static struct device *
connect(dev, num)
	register char *dev;
	register int num;
{
	register struct device *dp;

	if (num == QUES)
		return (huhcon(dev));
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if ((num != dp->d_unit) || !eq(dev, dp->d_name))
			continue;
		if (dp->d_type != CONTROLLER && dp->d_type != MASTER) {
			(void) snprintf(errbuf, sizeof(errbuf), 
			    "%s connected to non-controller", dev);
			yyerror(errbuf);
			return (0);
		}
		return (dp);
	}
	(void) snprintf(errbuf, sizeof(errbuf), "%s %d not defined", dev, num);
	yyerror(errbuf);
	return (0);
}

/*
 * connect to an unspecific thing
 */
static struct device *
huhcon(dev)
	register char *dev;
{
	register struct device *dp, *dcp;
	struct device rdev;
	int oldtype;

	/*
	 * First make certain that there are some of these to wildcard on
	 */
	for (dp = dtab; dp != 0; dp = dp->d_next)
		if (eq(dp->d_name, dev))
			break;
	if (dp == 0) {
		(void) snprintf(errbuf, sizeof(errbuf), "no %s's to wildcard",
		   dev);
		yyerror(errbuf);
		return (0);
	}
	oldtype = dp->d_type;
	dcp = dp->d_conn;
	/*
	 * Now see if there is already a wildcard entry for this device
	 * (e.g. Search for a "uba ?")
	 */
	for (; dp != 0; dp = dp->d_next)
		if (eq(dev, dp->d_name) && dp->d_unit == -1)
			break;
	/*
	 * If there isn't, make one because everything needs to be connected
	 * to something.
	 */
	if (dp == 0) {
		dp = &rdev;
		init_dev(dp);
		dp->d_unit = QUES;
		dp->d_name = ns(dev);
		dp->d_type = oldtype;
		newdev(dp);
		dp = curp;
		/*
		 * Connect it to the same thing that other similar things are
		 * connected to, but make sure it is a wildcard unit
		 * (e.g. up connected to sc ?, here we make connect sc? to a
		 * uba?).  If other things like this are on the NEXUS or
		 * if they aren't connected to anything, then make the same
		 * connection, else call ourself to connect to another
		 * unspecific device.
		 */
		if (dcp == TO_NEXUS || dcp == 0)
			dp->d_conn = dcp;
		else
			dp->d_conn = connect(dcp->d_name, QUES);
	}
	return (dp);
}

void
init_dev(dp)
	register struct device *dp;
{

	dp->d_name = "OHNO!!!";
	dp->d_type = DEVICE;
	dp->d_conn = 0;
	dp->d_conflicts = 0;
	dp->d_disabled = 0;
	dp->d_flags = dp->d_dk = 0;
	dp->d_slave = dp->d_lun = dp->d_target = dp->d_drive = dp->d_unit = UNKNOWN;
	dp->d_port = (char *)0;
	dp->d_portn = -1;
	dp->d_irq = -1;
	dp->d_drq = -1;
	dp->d_maddr = 0;
	dp->d_msize = 0;
}

/*
 * make certain that this is a reasonable type of thing to connect to a nexus
 */
static void
check_nexus(dev, num)
	register struct device *dev;
	int num;
{

	switch (machine) {

	case MACHINE_I386:
	case MACHINE_PC98:
#if 0
		if (!eq(dev->d_name, "isa"))
			yyerror("only isa's should be connected to the nexus");
#endif
		break;

	}
}

/*
 * Check system specification and apply defaulting
 * rules on root, argument, dump, and swap devices.
 */
static void
checksystemspec(fl)
	register struct file_list *fl;
{
	char buf[BUFSIZ];
	register struct file_list *swap;
	int generic;

	if (fl == 0 || fl->f_type != SYSTEMSPEC) {
		yyerror("internal error, bad system specification");
		exit(1);
	}
	swap = fl->f_next;
	generic = swap && swap->f_type == SWAPSPEC && eq(swap->f_fn, "generic");
	if (fl->f_rootdev == NODEV && !generic) {
		yyerror("no root device specified");
		exit(1);
	}
	/*
	 * Default swap area to be in 'b' partition of root's
	 * device.  If root specified to be other than on 'a'
	 * partition, give warning, something probably amiss.
	 */
	if (swap == 0 || swap->f_type != SWAPSPEC) {
		dev_t dev;

		swap = newflist(SWAPSPEC);
		dev = fl->f_rootdev;
		if (dkpart(dev) != 0) {
			(void) snprintf(buf, sizeof(buf),
"Warning, swap defaulted to 'b' partition with root on '%c' partition",
				dkpart(dev) + 'a');
			yyerror(buf);
		}
		swap->f_swapdev = dkmodpart(dev, SWAP_PART);
		swap->f_fn = devtoname(swap->f_swapdev);
		mkswap(fl, swap, 0);
	}
	/*
	 * Make sure a generic swap isn't specified, along with
	 * other stuff (user must really be confused).
	 */
	if (generic) {
		if (fl->f_rootdev != NODEV)
			yyerror("root device specified with generic swap");
		if (fl->f_dumpdev != NODEV)
			yyerror("dump device specified with generic swap");
		return;
	}
	/*
	 * Warn if dump device is not a swap area.
	 */
	if (fl->f_dumpdev != NODEV && fl->f_dumpdev != swap->f_swapdev) {
		struct file_list *p = swap->f_next;

		for (; p && p->f_type == SWAPSPEC; p = p->f_next)
			if (fl->f_dumpdev == p->f_swapdev)
				return;
		(void) snprintf(buf, sizeof(buf),
		    "Warning: dump device is not a swap partition");
		yyerror(buf);
	}
}

/*
 * Verify all devices specified in the system specification
 * are present in the device specifications.
 */
static void
verifysystemspecs()
{
	register struct file_list *fl;
	dev_t checked[50];
	register dev_t *pchecked = checked;

	for (fl = conf_list; fl; fl = fl->f_next) {
		if (fl->f_type != SYSTEMSPEC)
			continue;
		if (!finddev(fl->f_rootdev))
			deverror(fl->f_needs, "root");
		*pchecked++ = fl->f_rootdev;
		pchecked = verifyswap(fl->f_next, checked, pchecked);
		if (!alreadychecked(fl->f_dumpdev, checked, pchecked)) {
			if (!finddev(fl->f_dumpdev))
				deverror(fl->f_needs, "dump");
			*pchecked++ = fl->f_dumpdev;
		}
	}
}

/*
 * Do as above, but for swap devices.
 */
static dev_t *
verifyswap(fl, checked, pchecked)
	register struct file_list *fl;
	dev_t checked[];
	register dev_t *pchecked;
{

	for (;fl && fl->f_type == SWAPSPEC; fl = fl->f_next) {
		if (eq(fl->f_fn, "generic"))
			continue;
		if (alreadychecked(fl->f_swapdev, checked, pchecked))
			continue;
		if (!finddev(fl->f_swapdev))
			warnx("swap device %s not configured", fl->f_fn);
		*pchecked++ = fl->f_swapdev;
	}
	return (pchecked);
}

/*
 * Has a device already been checked
 * for its existence in the configuration?
 */
static int
alreadychecked(dev, list, last)
	dev_t dev, list[];
	register dev_t *last;
{
	register dev_t *p;

	for (p = list; p < last; p++)
		if (dkmodpart(*p, 0) != dkmodpart(dev, 0))
			return (1);
	return (0);
}

static void
deverror(systemname, devtype)
	char *systemname, *devtype;
{

	warnx("%s: %s device not configured", systemname, devtype);
}

/*
 * Look for the device in the list of
 * configured hardware devices.  Must
 * take into account stuff wildcarded.
 */
/*ARGSUSED*/
static int
finddev(dev)
	dev_t dev;
{

	/* punt on this right now */
	return (1);
}
