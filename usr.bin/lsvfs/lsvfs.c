/*
 * lsvfs - lsit loaded VFSes
 * Garrett A. Wollman, September 1994
 * This file is in the public domain.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <stdio.h>
#include <err.h>

#define FMT "%-32.32s %5d %5d %5d\n"
#define HDRFMT "%-32.32s %5.5s %5.5s %5.5s\n"
#define DASHES "-------------------------------- ----- ----- -----\n"

int
main(int argc, char **argv)
{
  int rv = 0;
  struct vfsconf *vfc;
  argc--, argv++;

  setvfsent(1);

  printf(HDRFMT, "Filesystem", "Index", "Refs", "Flags");
  fputs(DASHES, stdout);

  if(argc) {
    for(; argc; argc--, argv++) {
      vfc = getvfsbyname(*argv);
      if(vfc) {
        printf(FMT, vfc->vfc_name, vfc->vfc_index, vfc->vfc_refcount,
               vfc->vfc_flags);
      } else {
	warnx("VFS %s unknown or not loaded", *argv);
        rv++;
      }
    }
  } else {
    while(vfc = getvfsent()) {
      printf(FMT, vfc->vfc_name, vfc->vfc_index, vfc->vfc_refcount,
             vfc->vfc_flags);
    }
  }

  endvfsent();
  return rv;
}

