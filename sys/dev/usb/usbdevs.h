/*	$NetBSD: usbdevs.h,v 1.6 1998/10/05 02:31:13 mark Exp $	*/

/*
 * THIS FILE AUTOMATICALLY GENERATED.  DO NOT EDIT.
 *
 * generated from:
 *	NetBSD: usbdevs,v 1.5 1998/10/05 02:30:17 mark Exp 
 */

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Author: Lennart Augustsson <augustss@carlstedt.se>
 *         Carlstedt Research & Technology
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * List of known USB vendors
 */

#define	USB_VENDOR_NEC	0x0409		/* NEC */
#define	USB_VENDOR_KODAK	0x040a		/* Eastman Kodak */
#define	USB_VENDOR_NANAO	0x0440		/* Nanao */
#define	USB_VENDOR_UNIXTAR	0x0451		/* Unixtar */
#define	USB_VENDOR_GENIUS	0x0458		/* Genius */
#define	USB_VENDOR_CHERRY	0x046a		/* Cherry */
#define	USB_VENDOR_PHILIPS	0x0471		/* Philips */
#define	USB_VENDOR_CONNECTIX	0x0478		/* Connectix */
#define	USB_VENDOR_CYPRESS	0x04b4		/* Cypress Semicondutor */
#define	USB_VENDOR_EIZO	0x056d		/* EIZO */
#define	USB_VENDOR_BELKIN	0x05ab		/* Belkin */
#define	USB_VENDOR_EIZONANAO	0x05e7		/* EIZO Nanao */
#define	USB_VENDOR_CHIC	0x05fe		/* Chic Technology */
#define	USB_VENDOR_PLX	0x10b5		/* PLX */
#define	USB_VENDOR_INSIDEOUT	0x1608		/* Inside Out Networks */
#define	USB_VENDOR_INTEL	0x8086		/* Intel */

/*
 * List of known products.  Grouped by vendor.
 */

/* NEC products */
#define	USB_PRODUCT_NEC_HUB	0x55aa		/* hub */

/* Kodak products */
#define	USB_PRODUCT_KODAK_DC260	0x0110		/* Digital Science DC260 */

/* Nanao products */
#define	USB_PRODUCT_NANAO_HUB	0x0000		/* hub */
#define	USB_PRODUCT_NANAO_MONITOR	0x0001		/* monitor */

/* Unixtar products */
#define	USB_PRODUCT_UNIXTAR_UTUSB41	0x1446		/* UT-USB41 */

/* Genius products */
#define	USB_PRODUCT_GENIUS_NICHE	0x0001		/* Niche mouse */
#define	USB_PRODUCT_GENIUS_FLIGHT2000	0x1004		/* Flight 2000 joystick */

/* Cherry products */
#define	USB_PRODUCT_CHERRY_MY3000KBD	0x0001		/* My3000 keyboard */
#define	USB_PRODUCT_CHERRY_MY3000HUB	0x0003		/* My3000 hub */

/* Philips products */
#define	USB_PRODUCT_PHILIPS_DSS	0x0101		/* DSS 350 Digital Speaker System */
#define	USB_PRODUCT_PHILIPS_HUB	0x0201		/* hub */

/* Connectix products */
#define	USB_PRODUCT_CONNECTIX_QUICKCAM	0x0001		/* QuickCam */

/* Cypress Semiconduuctor products */
#define	USB_PRODUCT_CYPRESS_MOUSE	0x0001		/* mouse */

/* Belkin products */
#define	USB_PRODUCT_BELKIN_F5U002	0x0002		/* Parallel printer adapter */

/* EIZO Nanao products */
#define	USB_PRODUCT_EIZO_HUB	0x0000		/* hub */
#define	USB_PRODUCT_EIZO_MONITOR	0x0001		/* monitor */
#define	USB_PRODUCT_EIZONANAO_HUB	0x0000		/* hub */
#define	USB_PRODUCT_EIZONANAO_MONITOR	0x0001		/* monitor */

/* Chic Technology */
#define	USB_PRODUCT_CHIC_MOUSE1	0x0001		/* mouse */

/* PLX products */
#define	USB_PRODUCT_PLX_TESTBOARD	0x9060		/* test board */

/* Inside Out Networks products */
#define	USB_PRODUCT_INSIDEOUT_EDGEPORT4	0x0001		/* EdgePort/4 */

/* Intel products */
#define	USB_PRODUCT_INTEL_TESTBOARD	0x9890		/* 82930 test board */
