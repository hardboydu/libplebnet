/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: menus.c,v 1.43 1995/09/18 16:52:32 peter Exp $
 *
 * Copyright (c) 1995
 *	Jordan Hubbard.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    verbatim and that no modifications are made prior to this
 *    point in the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Jordan Hubbard
 *	for the FreeBSD Project.
 * 4. The name of Jordan Hubbard or the FreeBSD project may not be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JORDAN HUBBARD ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JORDAN HUBBARD OR HIS PETS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, LIFE OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "sysinstall.h"

/* All the system menus go here.
 *
 * Hardcoded things like version number strings will disappear from
 * these menus just as soon as I add the code for doing inline variable
 * expansion.
 */

/* The initial installation menu */
DMenu MenuInitial = {
    DMENU_NORMAL_TYPE,
    "Welcome to FreeBSD!",	/* title */
    "This is the main menu of the FreeBSD installation system.  Please\n\
select one of the options below by using the arrow keys or typing the\n\
first character of the option name you're interested in.  Invoke an\n\
option by pressing [ENTER].",		/* prompt */
    "Press F1 for usage instructions",			/* help line */
    "usage",						/* help file */
{ { "Usage",		"Quick start - How to use this menu system",		/* U */
	DMENU_DISPLAY_FILE,	"usage", 0, 0			},
  { "Doc",			"More detailed documentation on FreeBSD",	/* D */
	DMENU_SUBMENU,		&MenuDocumentation, 0, 0	},
  { "Options",			"Go to options editor",				/* O */
	DMENU_CALL,		optionsEditor, 0, 0		},
  { "Novice",			"Begin a novice installation (for beginners)",	/* N */
	DMENU_CALL,		installNovice, 0, 0		},
  { "Express",			"Begin a quick installation (for the impatient)", /* E */
	DMENU_CALL,		installExpress, 0, 0		},
  { "Custom",			"Begin a custom installation (for experts)",	/* C */
	DMENU_SUBMENU,		&MenuInstallCustom, 0, 0	},
  { "Fixit",			"Mount fixit floppy and go into repair mode",	/* F */
	DMENU_CALL,		installFixit, 0, 0		},
  { "Upgrade",			"Upgrade an existing 2.0.5 system",		/* U */
	DMENU_CALL,		installUpgrade, 0, 0		},
  { "Configure",		"Do post-install configuration of FreeBSD",	/* C (dup) */
	DMENU_SUBMENU,		&MenuConfigure, 0, 0		},
  { "Quit",			"Exit this menu (and the installation)",	/* Q */
	DMENU_CANCEL,		NULL, 0, 0			},
  { "Load",			"Load a pre-configuration file from floppy",
	DMENU_CALL,		installPreconfig, 0,		},
  { NULL } },
};

/* The main documentation menu */
DMenu MenuDocumentation = {
DMENU_NORMAL_TYPE,
"Documentation for FreeBSD " RELEASE_NAME,	/* Title */
"If you are at all unsure about the configuration of your hardware\n\
or are looking to build a system specifically for FreeBSD, read the\n\
Hardware guide!  New users should also read the Install document for\n\
a step-by-step tutorial on installing FreeBSD.  For general information,\n\
consult the README file.",
"Confused?  Press F1 for help.",
"usage",
{ { "README",			"Read this for a general description of FreeBSD",
	DMENU_DISPLAY_FILE,	"readme", 0, 0		},
  { "Hardware",			"The FreeBSD survival guide for PC hardware.",
	DMENU_DISPLAY_FILE,	"hardware", 0, 0	},
  { "Install",			"A step-by-step guide to installing FreeBSD.",
	DMENU_DISPLAY_FILE,	"install", 0, 0		},
  { "Copyright",		"The FreeBSD Copyright notices.",
	DMENU_DISPLAY_FILE,	"COPYRIGHT", 0, 0	},
  { "Release",			"The release notes for this version of FreeBSD.",
	DMENU_DISPLAY_FILE,	"relnotes", 0, 0	},
  { "HTML Docs",		"Go to the HTML documentation menu (post-install).",
	DMENU_CALL,		docBrowser, 0, 0			},
  { "Exit",			"Exit this menu (returning to previous)",
	DMENU_CANCEL,		NULL, 0, 0		},
  { NULL } },
};

DMenu MenuMouse = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"Please select your mouse type from the following menu",
"There are many different types of mice currently on the market,\n\
but this configuration menu should at least narrow down the choices\n\
somewhat.  Once you've selected one of the below, you can specify\n\
/dev/mouse as your mouse device when running the XFree86 configuration\n\
utility (see Configuration menu).  Please note that for PS/2 mice,\n\
a kernel recompile is also required!  See the handbook for more details\n\
on building a kernel.",
"For more information, visit the Documentation menu",
NULL,
{ { "COM1",		"Serial mouse on COM1",
	DMENU_SYSTEM_COMMAND,	"ln -fs /dev/cuaa0 /dev/mouse", 0, 0	},
  { "COM2",		"Serial mouse on COM2",
	DMENU_SYSTEM_COMMAND,	"ln -fs /dev/cuaa1 /dev/mouse", 0, 0	},
  { "COM3",		"Serial mouse on COM3",
	DMENU_SYSTEM_COMMAND,	"ln -fs /dev/cuaa2 /dev/mouse", 0, 0	},
  { "COM4",		"Serial mouse on COM4",
	DMENU_SYSTEM_COMMAND,	"ln -fs /dev/cuaa3 /dev/mouse", 0, 0	},
  { "BusMouse",		"Logitech or ATI bus mouse",
	DMENU_SYSTEM_COMMAND,	"ln -fs /dev/mse0 /dev/mouse", 0, 0	},
  { "PS/2",		"PS/2 style mouse (requires new kernel)",
	DMENU_SYSTEM_COMMAND,	"ln -fs /dev/psm0 /dev/mouse", 0, 0	},
  { NULL } },
};

DMenu MenuMediaCDROM = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"Choose a CDROM type",
"FreeBSD can be installed directly from a CDROM containing a valid\n\
FreeBSD distribution.  If you are seeing this menu it is because\n\
more than one CDROM drive was found on your system.  Please select one\n\
of the following CDROM drives as your installation drive.",
"Press F1 to read the installation guide",
"install",
{ { NULL } },
};

DMenu MenuMediaFloppy = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"Choose a Floppy drive",
"You have more than one floppy drive.  Please chose the drive\n\
you would like to use for this operation",
NULL,
NULL,
{ { NULL } },
};

DMenu MenuMediaDOS = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"Choose a DOS partition",
"FreeBSD can be installed directly from a DOS partition\n\
assuming, of course, that you have copied the relevant\n\
distributions into your DOS partition before starting this\n\
installation.  If this is not the case then you should reboot\n\
DOS at this time and copy the distributions you wish to install\n\
into a \"FREEBSD\" subdirectory on one of your DOS partitions.\n\
Otherwise, please select the DOS partition containing the FreeBSD\n\
distribution files.",
"Press F1 to read the installation guide",
"install",
{ { NULL } },
};

DMenu MenuMediaFTP = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"Please select a FreeBSD FTP distribution site",
"Please select the site closest to you or \"other\" if you'd like to\n\
specify a different choice.  Also note that not every site listed here\n\
carries more than the base distribution kits. Only the Primary site is\n\
guaranteed to carry the full range of possible distributions.",
"Select a site that's close!",
"install",
{ { "Primary Site",		"ftp.freebsd.org",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.freebsd.org/pub/FreeBSD/", 0, 0		},
  { "Other",			"Specify some other ftp site by URL",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=other", 0, 0						},
  { "Australia",		"ftp.physics.usyd.edu.au",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.physics.usyd.edu.au/FreeBSD/", 0, 0		},
  { "Australia #2",		"minnie.cs.adfa.oz.au",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://minnie.cs.adfa.oz.au/FreeBSD/", 0, 0		},
  { "Canada",			"ftp.synapse.net",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.synapse.net/contrib/FreeBSD/", 0, 0		},
  { "Finland",			"nic.funet.fi",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://nic.funet.fi/pub/unix/FreeBSD/", 0, 0		},
  { "France",			"ftp.ibp.fr",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.ibp.fr/pub/FreeBSD/", 0, 0			},
  { "Germany",			"ftp.fb9dv.uni-duisburg.de",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.fb9dv.uni-duisburg.de/pub/unix/FreeBSD/", 0, 0	},
  { "Germany #2",		"gil.physik.rwth-aachen.de",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://gil.physik.rwth-aachen.de/pub/FreeBSD/", 0, 0	},
  { "Germany #3",		"ftp.uni-paderborn.de",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.uni-paderborn.de/freebsd/", 0, 0		},
  { "Germany #4",		"ftp.leo.org",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.leo.org/pub/comp/os/bsd/FreeBSD/", 0, 0	},
  { "Germany #5",		"ftp.tu-dresden.de",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.tu-dresden.de/pub/soft/unix/bsd/FreeBSD/", 0, 0 },
  { "Hong Kong",		"ftp.hk.super.net",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.hk.super.net/pub/FreeBSD/", 0, 0		},
  { "Ireland",			"ftp.internet-eireann.ie",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.internet-eireann.ie/pub/FreeBSD/", 0, 0	},
  { "Israel",			"orgchem.weizmann.ac.il",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://orgchem.weizmann.ac.il/pub/FreeBSD/", 0, 0		},
  { "Japan",			"ftp.tokyonet.ad.jp",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.tokyonet.ad.jp/pub/FreeBSD/", 0, 0		},
  { "Japan #2",			"ftp.nisiq.net",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.nisiq.net/pub/os/FreeBSD/", 0, 0		},
  { "Japan #3",			"ftp.iij.ad.jp",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.iij.ad.jp/pub/FreeBSD/", 0, 0			},
  { "Japan #4",			"ftp.kuis.kyoto-u.ac.jp",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.kuis.kyoto-u.ac.jp/BSD/FreeBSD/", 0, 0		},
  { "Japan #5",			"ftp.ee.uec.ac.jp",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.ee.uec.ac.jp/pub/os/mirror/ftp.freebsd.org/", 0, 0 },
  { "Japan #6",			"ftp.u-aizu.ac.jp",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.u-aizu.ac.jp/pub/os/FreeBSD/", 0, 0		},
  { "Korea",			"ftp.cau.ac.kr",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.cau.ac.kr/pub/FreeBSD/", 0, 0			},
  { "Netherlands",		"ftp.nl.net",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.nl.net/pub/os/FreeBSD/", 0, 0			},
  { "Poland",			"SunSITE.icm.edu.pl",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://SunSITE.icm.edu.pl/pub/FreeBSD/", 0, 0		},
  { "Russia",			"ftp.kiae.su",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.kiae.su/FreeBSD/", 0, 0			},
  { "Sweden",			"ftp.luth.se",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.luth.se/pub/FreeBSD/", 0, 0			},
  { "Taiwan",			"NCTUCCCA.edu.tw",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://NCTUCCCA.edu.tw/Operating-Systems/FreeBSD", 0, 0	},
  { "Taiwan #2",		"netbsd.csie.nctu.edu.tw",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://netbsd.csie.nctu.edu.tw/pub/FreeBSD/", 0, 0	},
  { "Thailand",			"ftp.nectec.or.th",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.nectec.or.th/pub/mirrors/FreeBSD/", 0, 0	},
  { "UK",			"ftp.demon.co.uk",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.demon.co.uk/pub/BSD/FreeBSD/", 0, 0		},
  { "UK #2",			"src.doc.ic.ac.uk",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://src.doc.ic.ac.uk/packages/unix/FreeBSD/", 0, 0	},
  { "UK #3",			"unix.hensa.ac.uk",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://unix.hensa.ac.uk/mirrors/walnut.creek/FreeBSD/", 0, 0 },
  { "USA",			"ref.tfs.com",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ref.tfs.com/pub/FreeBSD/", 0, 0			},
  { "USA #2",			"ftp.dataplex.net",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.dataplex.net/pub/FreeBSD/", 0, 0		},
  { "USA #3",			"kryten.atinc.com",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://kryten.atinc.com/pub/FreeBSD/", 0, 0		},
  { "USA #4",			"ftp.neosoft.com",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.neosoft.com/systems/FreeBSD/", 0, 0		},
  { "USA #5",			"ftp.cybernetics.net",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.cybernetics.net/pub/FreeBSD/", 0, 0		},
  { "USA #6",			"ftp.cps.cmich.edu",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.cps.cmich.edu/pub/ftp.freebsd.org/", 0, 0	},
  { "USA #7",			"ftp.cslab.vt.edu",
	DMENU_SET_VARIABLE,	VAR_FTP_PATH "=ftp://ftp.cslab.vt.edu/pub/FreeBSD/", 0, 0		},
  { NULL } }
};

DMenu MenuMediaTape = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"Choose a tape drive type",
"FreeBSD can be installed from tape drive, though this installation\n\
method requires a certain amount of temporary storage in addition\n\
to the space required by the distribution itself (tape drives make\n\
poor random-access devices, so we extract _everything_ on the tape\n\
in one pass).  If you have sufficient space for this, then you should\n\
select one of the following tape devices detected on your system.",
"Press F1 to read the installation guide",
"install",
{ { NULL } },
};

DMenu MenuNetworkDevice = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"Network interface information required",
"If you are using PPP over a serial device (cuaa0 or cuaa1) as opposed\n\
to a direct ethernet connection, then you may first need to dial your\n\
service provider using the ppp utility we provide for that purpose.\n\
You can also install over a parallel port using a special \"laplink\"\n\
cable, though this only works if you have another FreeBSD machine running\n\
a fairly recent (2.0R or later) release to talk to.\n\n\
To use PPP, select one of the serial devices, otherwise select lp0 for\n\
the parallel port or one of the ethernet controllers (if you have one)\n\
for an ethernet installation.",
"Press F1 to read network configuration manual",
"network_device",
{ { NULL } },
};

/* The media selection menu */
DMenu MenuMedia = {
DMENU_NORMAL_TYPE,
"Choose Installation Media",
"FreeBSD can be installed from a variety of different installation\n\
media, ranging from floppies to an Internet FTP server.  If you're\n\
installing FreeBSD from a supported CDROM drive then this is generally\n\
the best media to use if you have no overriding reason for using other\n\
media.",
"Press F1 for more information on the various media types",
"media",
{ { "CDROM",	"Install from a FreeBSD CDROM",
	DMENU_CALL,	mediaSetCDROM, 0, 0		},
  { "DOS",		"Install from a DOS partition",
	DMENU_CALL,	mediaSetDOS, 0, 0		},
  { "File System",	"Install from an existing filesystem",
	DMENU_CALL,	mediaSetUFS, 0, 0		},
  { "Floppy",	"Install from a floppy disk set",
	DMENU_CALL,	mediaSetFloppy, 0, 0		},
  { "FTP",		"Install from an FTP server",
	DMENU_CALL,	mediaSetFTPActive, 0, 0		},
  { "FTP Passive",	"Install from an FTP server through a firewall",
	DMENU_CALL,	mediaSetFTPPassive, 0, 0	},
  { "NFS",		"Install over NFS",
	DMENU_CALL,	mediaSetNFS, 0, 0		},
  { "Tape",		"Install from SCSI or QIC tape",
	DMENU_CALL,	mediaSetTape, 0, 0		},
  { NULL } },
};

/* The distributions menu */
DMenu MenuDistributions = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"Choose Distributions",
"As a convenience, we provide several \"canned\" distribution sets.\n\
These select what we consider to be the most reasonable defaults for the\n\
type of system in question.  If you would prefer to pick and choose\n\
the list of distributions yourself, simply select \"Custom\".",
"Press F1 for more information on these options.",
"distributions",
{ { "Developer",	"Full sources, binaries and doc but no games [180MB]",
	DMENU_CALL,	distSetDeveloper, 0, 0		},
  { "X-Developer",	"Same as above, but includes XFree86 [201MB]",
	DMENU_CALL,	distSetXDeveloper, 0, 0		},
  { "Kern-Developer", "Full binaries and doc, kernel sources only [70MB]",
	DMENU_CALL,	distSetKernDeveloper, 0, 0	},
  { "User",		"Average user - binaries and doc but no sources [52MB]",
	DMENU_CALL,	distSetUser, 0, 0		},
  { "X-User",	"Same as above, but includes XFree86 [52MB]",
	DMENU_CALL,	distSetXUser, 0, 0		},
  { "Minimal",	"The smallest configuration possible [44MB]",
	DMENU_CALL,	distSetMinimum, 0, 0		},
  { "Everything",	"All sources, binaries and XFree86 binaries [700MB]",
	DMENU_CALL,	distSetEverything, 0, 0		},
  { "Custom",	"Specify your own distribution set [?]",
	DMENU_SUBMENU,	&MenuSubDistributions, 0, 0	},
  { "Clear",	"Reset selected distribution list to None",
	DMENU_CALL,	distReset, 0, 0			},
  { NULL } },
};

static char *
DESFlagCheck(DMenuItem *item)
{
    return (Dists & DIST_DES) ? "ON" : "OFF";
}

static char *
srcFlagCheck(DMenuItem *item)
{
    return (Dists & DIST_SRC) ? "ON" : "OFF";
}

static char *
x11FlagCheck(DMenuItem *item)
{
    return (Dists & DIST_XF86) ? "ON" : "OFF";
}

DMenu MenuSubDistributions = {
    DMENU_MULTIPLE_TYPE | DMENU_SELECTION_RETURNS,
    "Select the distributions you wish to install.",
    "Please check off the distributions you wish to install.  At the\n\
very minimum, this should be \"bin\".  WARNING:  Do not export the\n\
DES distribution out of the U.S.!  It is for U.S. customers only.",
    NULL,
    NULL,
{ { "bin",		"Binary base distribution (required) [36MB]",
	DMENU_SET_FLAG,	&Dists, DIST_BIN, 0, dmenuFlagCheck		},
  { "commercial",	"Commercial demos and shareware [10MB]",
	DMENU_SET_FLAG,	&Dists, DIST_COMMERCIAL, 0, dmenuFlagCheck	},
  { "compat1x",	"FreeBSD 1.x binary compatibility package [2MB]",
	DMENU_SET_FLAG,	&Dists, DIST_COMPAT1X, 0, dmenuFlagCheck	},
  { "compat20",	"FreeBSD 2.0 binary compatibility package [2MB]",
	DMENU_SET_FLAG,	&Dists, DIST_COMPAT20, 0, dmenuFlagCheck	},
  { "DES",		"DES encryption code - NOT FOR EXPORT! [.3MB]",
	DMENU_CALL,	distSetDES, 0, 0, DESFlagCheck			},
  { "dict",		"Spelling checker dictionary files [4.2MB]",
	DMENU_SET_FLAG,	&Dists, DIST_DICT, 0, dmenuFlagCheck		},
  { "games",	"Games (non-commercial) [6.4MB]",
	DMENU_SET_FLAG,	&Dists, DIST_GAMES, 0, dmenuFlagCheck		},
  { "info",		"GNU info files [4.1MB]",
	DMENU_SET_FLAG,	&Dists, DIST_INFO, 0, dmenuFlagCheck		},
  { "man",		"System manual pages - recommended [3.3MB]",
	DMENU_SET_FLAG,	&Dists, DIST_MANPAGES, 0, dmenuFlagCheck	},
  { "proflibs",	"Profiled versions of the libraries [3.3MB]",
	DMENU_SET_FLAG,	&Dists, DIST_PROFLIBS, 0, dmenuFlagCheck	},
  { "src",		"Sources for everything but DES [120MB]",
	DMENU_CALL,	distSetSrc, 0, 0, srcFlagCheck			},
  { "XFree86",	"The XFree86 3.1.2-S distribution",
	DMENU_CALL,	distSetXF86, 0, 0, x11FlagCheck			},
  { "Experimental",	"Work in progress!",
	DMENU_SET_FLAG,	&Dists, DIST_EXPERIMENTAL, 0, dmenuFlagCheck	},
  { NULL } },
};

DMenu MenuDESDistributions = {
DMENU_MULTIPLE_TYPE | DMENU_SELECTION_RETURNS,
"Select the encryption facilities you wish to install.",
"Please check off any special DES-based encryption distributions\n\
you would like to install.  Please note that these services are NOT FOR\n\
EXPORT from the United States, nor are they available on CDROM (for the\n\
same reason).  For information on non-U.S. FTP distributions of this\n\
software, please consult the release notes.",
NULL,
NULL,
{ { "des",		"Basic DES services (rlogin, init, etc) [1MB]",
	DMENU_SET_FLAG, &DESDists, DIST_DES_DES, 0, dmenuFlagCheck	},
  { "krb",		"Kerberos encryption services [2MB]",
	DMENU_SET_FLAG, &DESDists, DIST_DES_KERBEROS, 0, dmenuFlagCheck	},
  { "sebones",	"Sources for eBones (Kerberos) [1MB]",
	DMENU_SET_FLAG, &DESDists, DIST_DES_SEBONES, 0, dmenuFlagCheck	},
  { "ssecure",	"Sources for DES libs and utilities [1MB]",
	DMENU_SET_FLAG, &DESDists, DIST_DES_SSECURE, 0, dmenuFlagCheck	},
  { NULL } },
};

DMenu MenuSrcDistributions = {
DMENU_MULTIPLE_TYPE | DMENU_SELECTION_RETURNS,
"Select the sub-components of src you wish to install.",
"Please check off those portions of the FreeBSD source tree\n\
you wish to install.",
NULL,
NULL,
{ { "base",		"top-level files in /usr/src [300K]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_BASE, 0, dmenuFlagCheck	},
  { "gnu",		"/usr/src/gnu (software from the GNU Project) [42MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_GNU, 0, dmenuFlagCheck	},
  { "etc",		"/usr/src/etc (miscellaneous system files) [460K]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_ETC, 0, dmenuFlagCheck	},
  { "games",	"/usr/src/games (diversions) [7.8MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_GAMES, 0, dmenuFlagCheck	},
  { "include",	"/usr/src/include (header files) [467K]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_INCLUDE, 0, dmenuFlagCheck	},
  { "lib",		"/usr/src/lib (system libraries) [9.2MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_LIB, 0, dmenuFlagCheck	},
  { "libexec",	"/usr/src/libexec (system programs) [1.2MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_LIBEXEC, 0, dmenuFlagCheck	},
  { "lkm",		"/usr/src/lkm (Loadable Kernel Modules) [193K]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_LKM, 0, dmenuFlagCheck	},
  { "release",	"/usr/src/release (release-generation tools) [533K]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_RELEASE, 0, dmenuFlagCheck	},
  { "bin",		"/usr/src/bin (system binaries) [2.5MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_BIN, 0, dmenuFlagCheck	},
  { "sbin",		"/usr/src/sbin (system binaries) [1.3MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_SBIN, 0, dmenuFlagCheck	},
  { "share",	"/usr/src/share (documents and shared files) [10MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_SHARE, 0, dmenuFlagCheck	},
  { "sys",		"/usr/src/sys (FreeBSD kernel) [13MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_SYS, 0, dmenuFlagCheck	},
  { "ubin",		"/usr/src/usr.bin (user binaries) [13MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_UBIN, 0, dmenuFlagCheck	},
  { "usbin",	"/usr/src/usr.sbin (aux system binaries) [14MB]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_USBIN, 0, dmenuFlagCheck	},
  { "smailcf",	"/usr/src/usr.sbin (sendmail config macros) [341K]",
	DMENU_SET_FLAG,	&SrcDists, DIST_SRC_SMAILCF, 0, dmenuFlagCheck	},
  { NULL } },
};

static int
clearx11(char *str)
{
    XF86Dists = 0;
    XF86ServerDists = 0;
    XF86FontDists = 0;
    Dists &= ~DIST_XF86;
    return 0;
}

DMenu MenuXF86Select = {
    DMENU_NORMAL_TYPE,
    "XFree86 3.1.2-S Distribution",
    "Please select the components you need from the XFree86 3.1.2-S\n\
distribution.  We recommend that you select what you need from the basic\n\
component set and at least one entry from the Server and Font set menus.",
    "Press F1 to read the XFree86 release notes for FreeBSD",
    "XF86",
{ { "Basic",	"Basic component menu (required)",
	DMENU_SUBMENU,	&MenuXF86SelectCore, 0, 0			},
  { "Server",	"X server menu",
	DMENU_SUBMENU,	&MenuXF86SelectServer, 0, 0			},
  { "Fonts",	"Font set menu",
	DMENU_SUBMENU,	&MenuXF86SelectFonts, 0, 0			},
  { "Exit",		"Exit this menu (returning to previous)",
	DMENU_CANCEL,	NULL, 0, 0					},
  { "Clear",	"Reset XFree86 distribution list",
	DMENU_CALL,	clearx11, 0, 0, 0				},
  { NULL } },
};

DMenu MenuXF86SelectCore = {
    DMENU_MULTIPLE_TYPE | DMENU_SELECTION_RETURNS,
"XFree86 3.1.2-S base distribution types",
"Please check off the basic XFree86 components you wish to install.\n\
Bin, lib, xicf, and xdcf are recommended for a minimum installaion.",
"Press F1 to read the XFree86 release notes for FreeBSD",
"XF86",
{ { "bin",		"Client applications and shared libs [4.1MB].",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_BIN, 0, dmenuFlagCheck		},
  { "lib",		"Data files needed at runtime [750K]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_LIB, 0, dmenuFlagCheck		},
  { "xicf",		"Customizable xinit runtime configuration file [10K]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_XINIT, 0, dmenuFlagCheck		},
  { "xdcf",		"Customizable xdm runtime configuration file [20K]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_XDMCF, 0, dmenuFlagCheck		},
  { "etc",		"Clock setting and diagnostic source codes [70K]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_ETC, 0, dmenuFlagCheck		},
  { "doc",		"READMEs and release notes [600K]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_DOC, 0, dmenuFlagCheck		},
  { "man",		"Man pages [1.7MB]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_MAN, 0, dmenuFlagCheck		},
  { "ctrb",		"Various contributed binaries (ico, xman, etc) [550K]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_CTRB, 0, dmenuFlagCheck		},
  { "prog",		"Programmer's header and library files [4.1MB]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_PROG, 0, dmenuFlagCheck		},
  { "link",		"Kit to reconfigure/rebuild X Servers [8.8MB]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_LINK, 0, dmenuFlagCheck		},
  { "ubin",		"rstart daemon [2K]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_UBIN, 0, dmenuFlagCheck		},
  { "pex",		"PEX fonts and libs needed by PEX apps [290K]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_PEX, 0, dmenuFlagCheck		},
  { "sources",	"XFree86 3.1.2-S standard + contrib sources [200MB]",
	DMENU_SET_FLAG,	&XF86Dists, DIST_XF86_SRC, 0, dmenuFlagCheck		},
  { NULL } },
};

DMenu MenuXF86SelectFonts = {
DMENU_MULTIPLE_TYPE | DMENU_SELECTION_RETURNS,
"Font distribution selection.",
"Please check off the individual font distributions you wish to\n\
install.  At the minimum, you should install the standard\n\
75 DPI and misc fonts if you're also installing a server\n\
(these are selected by default).",
    "Press F1 to read the XFree86 release notes for FreeBSD",
    "XF86",
    { { "fnts",		"Standard 75 DPI and miscellaneous fonts [3.6MB]",
	DMENU_SET_FLAG,	&XF86FontDists, DIST_XF86_FONTS_MISC, 0, dmenuFlagCheck		},
      { "f100",		"100 DPI fonts [1.8MB]",
	DMENU_SET_FLAG,	&XF86FontDists, DIST_XF86_FONTS_100, 0, dmenuFlagCheck		},
      { "fcyr",		"Cyrillic Fonts [1.8MB]",
	DMENU_SET_FLAG,	&XF86FontDists, DIST_XF86_FONTS_CYR, 0, dmenuFlagCheck		},
      { "fscl",		"Speedo and Type scalable fonts [1.6MB]",
	DMENU_SET_FLAG,	&XF86FontDists, DIST_XF86_FONTS_SCALE, 0, dmenuFlagCheck	},
      { "non",		"Japanese, Chinese and other non-english fonts [3.3MB]",
	DMENU_SET_FLAG,	&XF86FontDists, DIST_XF86_FONTS_NON, 0, dmenuFlagCheck		},
      { "server",	"Font server [0.3MB]",
	DMENU_SET_FLAG,	&XF86FontDists, DIST_XF86_FONTS_SERVER, 0, dmenuFlagCheck	},
      { NULL } },
};

DMenu MenuXF86SelectServer = {
    DMENU_MULTIPLE_TYPE | DMENU_SELECTION_RETURNS,
    "X Server selection.",
    "Please check off the types of X servers you wish to install.\n\
If you are unsure as to which server will work for your graphics card,\n\
it is recommended that try the SVGA or VGA16 servers (the VGA16 and\n\
Mono servers are particularly well-suited to most LCD displays).",
    "Press F1 to read the XFree86 release notes for FreeBSD",
    "XF86",
    { { "SVGA",		"Standard VGA or Super VGA display [2.8MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_SVGA, 0, dmenuFlagCheck	},
      { "VGA16",	"Standard 16 color VGA display [1.3MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_VGA16, 0, dmenuFlagCheck	},
      { "Mono",		"Standard Monochrome display [1.3MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_MONO, 0, dmenuFlagCheck	},
      { "8514",		"8-bit (256 color) IBM 8514 or compatible card [2.2MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_8514, 0, dmenuFlagCheck	},
      { "AGX",		"8-bit AGX card [2.4MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_AGX, 0, dmenuFlagCheck	},
      { "Ma8",		"8-bit ATI Mach8 card [2.3MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_MACH8, 0, dmenuFlagCheck	},
      { "Ma32",		"8 and 16-bit (65K color) for ATI Mach32 card [2.4MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_MACH32, 0, dmenuFlagCheck	},
      { "Ma64",		"8 and 16-bit (65K color) for ATI Mach64 card [2.5MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_MACH64, 0, dmenuFlagCheck	},
      { "P9K",		"8, 16, and 24-bit color for Weitek P9000 based boards [2.5MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_P9000, 0, dmenuFlagCheck	},
      { "S3",		"8, 16 and 24-bit color for S3 based boards [2.7MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_S3, 0, dmenuFlagCheck	},
      { "W32",		"8-bit Color for ET4000/W32, /W32i and /W32p cards [2.3MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_W32, 0, dmenuFlagCheck	},
      { "nest",		"A nested server for testing purposes [1.8MB]",
	DMENU_SET_FLAG,	&XF86ServerDists, DIST_XF86_SERVER_NEST, 0, dmenuFlagCheck	},
      { NULL } },
};

DMenu MenuDiskDevices = {
    DMENU_MULTIPLE_TYPE | DMENU_SELECTION_RETURNS,
    "Select Drive(s)",
    "Please select the drive, or drives, on which you wish to perform\n\
this operation.  If you are attempting to install a boot partition\n\
on a drive other than the first one or have multiple operating\n\
systems on your machine, you will have the option to install a boot\n\
manager later.  To select a drive, use the arrow keys to move to it\n\
and press [SPACE].",
    "Press F1 for important information regarding disk geometry!",
    "drives",
    { { NULL } },
};

DMenu MenuHTMLDoc = {
    DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
    "Select HTML Documentation pointer",
    "Please select the body of documentation you're interested in, the main\n\
ones right now being the FAQ and the Handbook.  You can also chose \"other\"\n\
to enter an arbitrary URL for browsing.",
    "Press F1 for more help on what you see here.",
    "html",
    { { "Handbook",	"The FreeBSD Handbook.",
	DMENU_CALL,	docShowDocument, 0, 0			},
      { "FAQ",		"The Frequently Asked Questions guide.",
	DMENU_CALL,	docShowDocument, 0, 0			},
      { "Home",		"The Home Pages for the FreeBSD Project (requires net)",
	DMENU_CALL,	docShowDocument, 0, 0			},
      { "Other",	"Enter a URL.",
	DMENU_CALL,	docShowDocument, 0, 0			},
      { NULL } },
};

/* The main installation menu */
DMenu MenuInstallCustom = {
    DMENU_NORMAL_TYPE,
    "Choose Custom Installation Options",
    "This is the custom installation menu. You may use this menu to specify\n\
details on the type of distribution you wish to have, where you wish\n\
to install it from and how you wish to allocate disk storage to FreeBSD.",
    "Press F1 to read the installation guide",
    "install",
    { { "Options",	"Go to Options editor",
	DMENU_CALL,	optionsEditor, 0, 0			},
      { "Partition",	"Allocate disk space for FreeBSD",
        DMENU_CALL,	diskPartitionEditor, 0, 0		},
      { "Label",	"Label allocated disk partitions",
	DMENU_CALL,	diskLabelEditor, 0, 0			},
      { "Distributions", "Select distribution(s) to extract",
	DMENU_SUBMENU,	&MenuDistributions, 0, 0			},
      { "Media",	"Choose the installation media type",
	DMENU_SUBMENU,	&MenuMedia, 0, 0			},
      { "Commit",	"Perform any pending Partition/Label/Extract actions",
	DMENU_CALL,	installCommit, 0, 0			},
      { "Extract",	"Just do distribution extract step",
	DMENU_CALL,	distExtractAll, 0, 0			},
      { "Exit",		"Exit this menu (returning to previous)",
	DMENU_CANCEL, NULL, 0, 0 },
      { NULL } },
};

/* MBR type menu */
DMenu MenuMBRType = {
    DMENU_RADIO_TYPE | DMENU_SELECTION_RETURNS,
    "overwrite me",		/* will be disk specific label */
    "FreeBSD comes with a boot selector that allows you to easily\n"
"select between FreeBSD and any other operating systems on your machine\n"
"at boot time.  If you have more than one drive and want to boot\n"
"from the second one, the boot selector will also make it possible\n"
"to do so (limitations in the PC BIOS usually prevent this otherwise).\n"
"If you do not want a boot selector, or wish to replace an existing\n"
"one, select \"standard\".  If you would prefer your Master Boot\n"
"Record to remain untouched then select \"none\".  NOTE:  PC-DOS users\n"
"will almost certainly NOT want to select one!",
    "Press F1 to read the installation guide",
    "install",
    { { "BootMgr",		"Install the FreeBSD Boot Manager (\"Booteasy\")",
	DMENU_SET_VALUE,	&BootMgr, 0, 0, dmenuRadioCheck		},
      { "Standard",		"Install a standard MBR (no boot manager)",
	DMENU_SET_VALUE,	&BootMgr, 1, 0, dmenuRadioCheck		},
      { "None",			"Leave the Master Boot Record untouched",
	DMENU_SET_VALUE,	&BootMgr, 2, 0, dmenuRadioCheck		},
      { NULL } },
};

/* Final configuration menu */
DMenu MenuConfigure = {
    DMENU_NORMAL_TYPE,
    "FreeBSD Configuration Menu",	/* title */
"If you've already installed FreeBSD, you may use this menu to customize\n\
it somewhat to suit your particular configuration.  Most importantly,\n\
you can use the Packages utility to load extra \"3rd party\"\n\
software not provided in the base distributions.",
    "Press F1 for more information on these options",
    "configure",
    { { "Add User",		"Add users to the system",
	DMENU_SYSTEM_COMMAND,	"adduser -config_create ; adduser -s", 0, 0 },
      { "Console",		"Customize system console behavior",
	DMENU_SUBMENU,		&MenuSyscons, 0, 0			},
      { "Time Zone",		"Set which time zone you're in",
	DMENU_SYSTEM_COMMAND,	"rm -f /etc/wall_cmos_clock /etc/localtime; tzsetup", 0, 0 },
      { "Media",		"Change the installation media type",
	DMENU_SUBMENU,		&MenuMedia, 0, 0			},
      { "Mouse",		"Select the type of mouse you have",
	DMENU_SUBMENU,		&MenuMouse, 0, 0			},
      { "Networking",		"Configure additional network services",
	DMENU_SUBMENU, 		&MenuNetworking, 0, 0			},
      { "Options",		"Go to options editor.",
	DMENU_CALL,		optionsEditor, 0, 0			},
      { "Packages",		"Install pre-packaged software for FreeBSD",
	DMENU_CALL,		configPackages, 0, 0			},
      { "Ports",		"Link to FreeBSD Ports Collection on CD/NFS",
	DMENU_CALL,		configPorts, 0, 1			},
      { "Root Password",	"Set the system manager's password",
	DMENU_SYSTEM_COMMAND,	"passwd root", 0, 0			},
      { "HTML Docs",		"Go to the HTML documentation menu (post-install).",
	DMENU_CALL,		docBrowser, 0, 0			},
      { "XFree86",		"Configure XFree86 (if installed)",
	DMENU_SYSTEM_COMMAND,	"/usr/X11R6/bin/xf86config", 0, 0	},
      { "Exit",			"Exit this menu (returning to previous)",
	DMENU_CANCEL, NULL, 0, 0					},
      { NULL } },
};

DMenu MenuNetworking = {
    DMENU_NORMAL_TYPE,
    "Network Services Menu",
"You may have already configured one network device (and the other\n\
various hostname/gateway/name server parameters) in the process\n\
of installing FreeBSD.  This menu allows you to configure other\n\
aspects of your system's network configuration.",
    NULL,
    NULL,
{ { "Interfaces",		"Configure additional network interfaces",
	DMENU_CALL,		tcpMenuSelect, 0, 0					},
  { "NFS client",		"This machine will be an NFS client",
	DMENU_SET_VARIABLE,	"nfs_client=YES", 0, 0, 0				},
  { "NFS server",		"This machine will be an NFS server",
	DMENU_CALL,		configNFSServer, 0, 0, 0				},
  { "Gateway",			"This machine will route packets between interfaces",
	DMENU_SET_VARIABLE,	"gateway=YES", 0, 0, 0					},
  { "Gated",			"This machine wants to run gated",
	DMENU_CALL,		configGated, 0, 0, 0					},
  { "Ntpdate",			"Select a clock-syncronization server",
	DMENU_SUBMENU,		&MenuNTP, (int)"ntpdate", 0, dmenuVarCheck		},
  { "Routed",			"Set flags for routed (default: -q)",
	DMENU_CALL,		configRoutedFlags, (int)"routed", 0, dmenuVarCheck	},
  { "Rwhod",			"This machine wants to run the rwho daemon",
	DMENU_SET_VARIABLE,	"rwhod=YES", 0, 0, dmenuVarCheck			},
  { "Anon FTP",			"This machine wishes to allow anonymous FTP.",
	DMENU_CALL,		configAnonFTP, 0, 0, 0					},
  { "WEB Server",		"This machine wishes to be a WWW server.",
	DMENU_CALL,		configApache, 0, 0, 0					},
  { "Samba",			"Install Samba for LanManager (NETBUI) access.",
	DMENU_CALL,		configSamba, 0, 0, 0					},
  { "PCNFSD",			"Run authentication server for clients with PC-NFS.",
	DMENU_CALL,		configPCNFSD, 0, 0, 0					},
  { NULL } },
};

DMenu MenuNTP = {
DMENU_NORMAL_TYPE | DMENU_SELECTION_RETURNS,
"NTPDATE Server Selection",
"There are a number of time syncronization servers available\n\
for public use around the Internet.  Please select one reasonably\n\
close to you to have your system time syncronized accordingly.",
"These are the primary open-access NTP servers",
NULL,
{ { "Other",		"Select a site not on this list",
	DMENU_CALL,		configNTP, 0, 0				},
  { "Australia",		"ntp.syd.dms.csiro.au (HP 5061 Cesium Beam)",
	DMENU_SET_VARIABLE,	"ntpdate=ntp.syd.dms.csiro.au", 0, 0	},
  { "Canada",		"tick.usask.ca (GOES clock)",
	DMENU_SET_VARIABLE,	"ntpdate=tick.usask.ca", 0, 0		},
  { "France",		"canon.inria.fr (TDF clock)",
	DMENU_SET_VARIABLE,	"ntpdate=canon.inria.fr", 0, 0		},
  { "Germany",		"ntps1-{0,1,2}.uni-erlangen.de (GPS)",
	DMENU_SET_VARIABLE,	"ntpdate=ntps1-0.uni-erlangen.de", 0, 0	},
  { "Germany #2",		"ntps1-0.cs.tu-berlin.de (GPS)",
	DMENU_SET_VARIABLE,	"ntpdate=ntps1-0.cs.tu-berlin.de", 0, 0	},
  { "Japan",		"clock.nc.fukuoka-u.ac.jp (GPS clock)",
	DMENU_SET_VARIABLE,	"ntpdate=clock.nc.fukuoka-u.ac.jp", 0, 0},
  { "Japan #2",		"clock.tl.fukuoka-u.ac.jp (GPS clock)",
	DMENU_SET_VARIABLE,	"ntpdate=clock.tl.fukuoka-u.ac.jp", 0, 0},
  { "Netherlands",		"ntp0.nl.net (GPS clock)",
	DMENU_SET_VARIABLE,	"ntpdate=ntp0.nl.net", 0, 0		},
  { "Norway",		"timer.unik.no (NTP clock)",
	DMENU_SET_VARIABLE,	"ntpdate=timer.unik.no", 0, 0		},
  { "Sweden",		"Time1.Stupi.SE (Cesium/GPS)",
	DMENU_SET_VARIABLE,	"ntpdate=Time1.Stupi.SE", 0, 0		},
  { "Switzerland",		"swisstime.ethz.ch (DCF77 clock)",
	DMENU_SET_VARIABLE,	"ntpdate=swisstime.ethz.ch", 0, 0	},
  { "U.S. East Coast",	"bitsy.mit.edu (WWV clock)",
	DMENU_SET_VARIABLE,	"ntpdate=bitsy.mit.edu", 0, 0		},
  { "U.S. East Coast #2",	"otc1.psu.edu (WWV clock)",
	DMENU_SET_VARIABLE,	"ntpdate=otc1.psu.edu", 0, 0		},
  { "U.S. West Coast",	"apple.com (WWV clock)",
	DMENU_SET_VARIABLE,	"ntpdate=apple.com", 0, 0		},
  { "U.S. West Coast #2",	"clepsydra.dec.com (GOES clock)",
	DMENU_SET_VARIABLE,	"ntpdate=clepsydra.dec.com", 0, 0	},
  { "U.S. West Coast #3",	"clock.llnl.gov (WWVB clock)",
	DMENU_SET_VARIABLE,	"ntpdate=clock.llnl.gov", 0, 0		},
  { "U.S. Midwest",		"ncar.ucar.edu (WWVB clock)",
	DMENU_SET_VARIABLE,	"ntpdate=ncar.ucar.edu", 0, 0		},
  { "U.S. Pacific",		"chantry.hawaii.net (WWV/H clock)",
	DMENU_SET_VARIABLE,	"ntpdate=chantry.hawaii.net", 0, 0	},
  { "U.S. Southwest",	"shorty.chpc.utexas.edu (WWV clock)",
	DMENU_SET_VARIABLE,	"ntpdate=shorty.chpc.utexas.edu", 0, 0	},
  { NULL } },
};

DMenu MenuSyscons = {
DMENU_NORMAL_TYPE,
"System Console Configuration",
"The default system console driver for FreeBSD (syscons) has a\n\
number of configuration options which may be set according to\n\
your preference.\n\n\
When you are done setting configuration options, select Cancel.",
"Configure your system console settings",
NULL,
{ { "Keymap",		"Choose an alternate keyboard map",
	DMENU_SUBMENU,		&MenuSysconsKeymap, 0, 0	},
  { "Repeat",		"Set the rate at which keys repeat",
	DMENU_SUBMENU,		&MenuSysconsKeyrate, 0, 0	},
  { "Saver",		"Configure the screen saver",
	DMENU_SUBMENU,		&MenuSysconsSaver, 0, 0		},
  { "Exit",			"Exit this menu (returning to previous)",
	DMENU_CANCEL,		NULL, 0, 0			},
  { NULL } },
};

DMenu MenuSysconsKeymap = {
DMENU_RADIO_TYPE | DMENU_SELECTION_RETURNS,
"System Console Keymap",
"The default system console driver for FreeBSD (syscons) defaults\n\
to a standard \"American\" keyboard map.  Users in other countries\n\
(or with different keyboard preferences) may wish to choose one of\n\
the other keymaps below.",
    "Choose a keyboard map",
    NULL,
    { { "Danish CP865",		"Danish Code Page 865 keymap",
	DMENU_SET_VARIABLE,	"keymap=danish.cp865", 0, 0, dmenuVarCheck	},
      { "Danish ISO",		"Danish ISO keymap",
	DMENU_SET_VARIABLE,	 "keymap=danish.iso", 0, 0, dmenuVarCheck	},
      { "French ISO",		"French ISO keymap",
	DMENU_SET_VARIABLE,	 "keymap=fr.iso", 0, 0, dmenuVarCheck		},
      { "German CP850",		"German Code Page 850 keymap",
	DMENU_SET_VARIABLE,	 "keymap=german.cp850", 0, 0, dmenuVarCheck	},
      { "German ISO",		"German ISO keymap",
	DMENU_SET_VARIABLE,	 "keymap=german.iso", 0, 0, dmenuVarCheck	},
      { "Russian CP866",	"Russian Code Page 866 keymap",
	DMENU_SET_VARIABLE,	 "keymap=ru.cp866", 0, 0, dmenuVarCheck		},
      { "Russian KOI8",		"Russian koi8 keymap",
	DMENU_SET_VARIABLE,	 "keymap=ru.koi8-r", 0, 0, dmenuVarCheck	},
      { "Russian s-KOI8",	"Russian shifted koi8 keymap",
	DMENU_SET_VARIABLE,	 "keymap=ru.koi8-r.shift", 0, 0, dmenuVarCheck	},
      { "Swedish CP850",	"Swedish Code Page 850 keymap",
	DMENU_SET_VARIABLE,	 "keymap=swedish.cp850", 0, 0, dmenuVarCheck	},
      { "Swedish ISO",		"Swedish ISO keymap",
	DMENU_SET_VARIABLE,	 "keymap=swedish.iso", 0, 0, dmenuVarCheck	},
      { "U.K. CP850",		"United Kingdom Code Page 850 keymap",
	DMENU_SET_VARIABLE,	 "keymap=uk.cp850", 0, 0, dmenuVarCheck		},
      { "U.K. ISO",		"United Kingdom ISO keymap",
	DMENU_SET_VARIABLE,	 "keymap=uk.iso", 0, 0, dmenuVarCheck		},
      { "U.S. ISO",		"United States ISO keymap",
	DMENU_SET_VARIABLE,	 "keymap=us.iso", 0, 0, dmenuVarCheck		},
      { NULL } },
};

DMenu MenuSysconsKeyrate = {
    DMENU_RADIO_TYPE | DMENU_SELECTION_RETURNS,
    "System Console Keyboard Repeat Rate",
    "This menu allows you to set the speed at which keys repeat\n\
when held down.",
    "Choose a keyboard repeat rate",
    NULL,
    { { "Slow",			"Slow keyboard repeat rate",
	DMENU_SET_VARIABLE,	"keyrate=slow", 0, 0, dmenuVarCheck		},
      { "Normal",		"\"Normal\" keyboard repeat rate",
	DMENU_SET_VARIABLE,	"keyrate=normal", 0, 0, dmenuVarCheck		},
      { "Fast",			"Fast keyboard repeat rate",
	DMENU_SET_VARIABLE,	"keyrate=fast", 0, 0, dmenuVarCheck		},
      { "Default",		"Use default keyboard repeat rate",
	DMENU_SET_VARIABLE,	"keyrate=NO", 0, 0, dmenuVarCheck		},
      { NULL } },
};

DMenu MenuSysconsSaver = {
    DMENU_MULTIPLE_TYPE | DMENU_SELECTION_RETURNS,
    "System Console Screen Saver",
    "By default, the console driver will not attempt to do anything\n\
special with your screen when it's idle.  If you expect to leave your\n\
monitor switched on and idle for long periods of time then you should\n\
probably enable one of these screen savers to prevent phosphor burn-in.",
    "Choose a nifty-looking screen saver",
    NULL,
{ { "blank",		"Simply blank the screen",
	DMENU_SET_VARIABLE,	"saver=blank", 0, 0, dmenuVarCheck		},
  { "Green",		"\"Green\" power saving mode (if supported by monitor)",
	DMENU_SET_VARIABLE,	"saver=green", 0, 0, dmenuVarCheck		},
  { "Snake",		"Draw a FreeBSD \"snake\" on your screen",
	DMENU_SET_VARIABLE,	"saver=snake", 0, 0, dmenuVarCheck		},
  { "Star",		"A \"twinkling stars\" effect",
	DMENU_SET_VARIABLE,	"saver=star", 0, 0, dmenuVarCheck		},
  { "Timeout",		"Set the screen saver timeout interval",
	DMENU_CALL,		configSaverTimeout, (int)"blanktime", 0, dmenuVarCheck	},
  { NULL } },
};
