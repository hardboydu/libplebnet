/*-
 * Copyright (c) 1997, 1998
 *	Nan Yang Computer Services Limited.  All rights reserved.
 *
 *  This software is distributed under the so-called ``Berkeley
 *  License'':
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
 *	This product includes software developed by Nan Yang Computer
 *      Services Limited.
 * 4. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even if
 * advised of the possibility of such damage.
 *
 * $Id: vinumstate.h,v 1.1.1.1 1998/09/16 05:56:21 grog Exp $
 */

/* This file gets read by makestatetext to create text files
 * with the names of the states, so don't change the file
 * format */

enum volumestate {
    volume_unallocated,
    /* present but unused.  Must be 0 */

    volume_uninit,
    /* mentioned elsewhere but not defined */

    volume_down,

    /* The volume is up and functional, but not all plexes may be available */
    volume_up,
    volume_laststate = volume_up			    /* last value, for table dimensions */
};

enum plexstate {
    /* An empty entry, not a plex at all.   */
    plex_unallocated,

    /* The plex has been allocated, but there configuration
     * is not complete */
    plex_init,

    /* A plex which has gone completely down because of
     * I/O errors. */
    plex_faulty,

    /* A plex which has been taken down by the
     * administrator. */
    plex_down,

    /* A plex which is currently being brought up after
     * being not up.  This involves copying data from
     * another plex */
    plex_reviving,

    /* A plex which is being initialized */
    plex_initializing,

    /* *** The remaining states represent plexes which are
     * at least partially up.  Keep these separate so that
     * they can be checked more easily. */

    /* A plex entry which is at least partially up.  Not
     * all subdisks are available, and an inconsistency
     * has occurred.  If no other plex is uncorrupted,
     * the volume is no longer consistent. */
    plex_corrupt,

    plex_firstup = plex_corrupt,			    /* first "up" state */

    /* A plex entry which is at least partially up.  Not
     * all subdisks are available, but so far no
     * inconsistency has occurred (this will change with
     * the first write to the address space occupied by
     * a defective subdisk).  A RAID 5 plex with one subdisk
     * down will remain degraded even after a write */
    plex_degraded,

    /* A plex which is really up, but which has a reborn
     * subdisk which we don't completely trust, and
     * which we don't want to read if we can avoid it */
    plex_flaky,

    /* A plex entry which is completely up.  All subdisks
     * are up. */
    plex_up,

    plex_laststate = plex_up				    /* last value, for table dimensions */
};

/* subdisk states */
enum sdstate {
    /* An empty entry, not a subdisk at all. */
    sd_unallocated,

    /* A subdisk entry which has not been created
     * completely.  Some fields may be empty.
     */
    sd_uninit,

    /* A subdisk entry which has been created completely.
     * All fields are correct, but the disk hasn't
     * been updated.
     */
    sd_init,

    /* A subdisk entry which has been created completely and
     * which is currently being initialized */
    sd_initializing,

    /* A subdisk entry which has been created completely.
     * All fields are correct, and the disk has been
     * updated, but there is no data on the disk.
     */
    sd_empty,

    /* *** The following states represent invalid data */
    /* A subdisk entry which has been created completely.
     * All fields are correct, the disk has been updated,
     * and the data was valid, but since then the drive
     * has gone down, and as a result updates have been
     * missed.
     */
    sd_obsolete,

    /* A subdisk entry which has been created completely.
     * All fields are correct, the disk has been updated,
     * and the data was valid, but since then the drive
     * has gone down, updates have been lost, and then
     * the drive came up again.
     */
    sd_stale,

    /* *** The following states represent valid, inaccessible data */
    /* A subdisk entry which has been created completely.
     * All fields are correct, the disk has been updated,
     * and the data was valid, but since then the drive
     * has gone down.   No attempt has been made to write
     * to the subdisk since the crash.
     */
    sd_crashed,

    /* A subdisk entry which was up, which contained
     * valid data, and which was taken down by the
     * administrator.  The data is valid. */
    sd_down,

    /* *** The following states represent accessible subdisks
     * with valid data */

    /* A subdisk entry which has been created completely.
     * All fields are correct, the disk has been updated,
     * and the data was valid, but since then the drive
     * has gone down and up again.  No updates were lost,
     * but it is possible that the subdisk has been
     * damaged.  We won't read from this subdisk if we
     * have a choice.  If this is the only subdisk which
     * covers this address space in the plex, we set its
     * state to sd_up under these circumstances, so this
     * status implies that there is another subdisk to
     * fulfil the request.
     */
    sd_reborn,

    /* A subdisk entry which has been created completely.
     * All fields are correct, the disk has been updated,
     * and the data is valid.
     */
    sd_up,

    sd_laststate = sd_up				    /* last value, for table dimensions */
};

enum drivestate {
    drive_unallocated,
    /* present but unused.  Must be 0 */

    drive_uninit,
    /* just mentioned in some other config entry */

    drive_down,
    /* not accessible */

    drive_coming_up,
    /* in the process of being brought up */

    drive_up,
    /* up and running */

    drive_laststate = drive_up				    /* last value, for table dimensions */
};
