#
# Copyright (c) 1998 Robert Nordier
# All rights reserved.
#
# Redistribution and use in source and binary forms are freely
# permitted provided that the above copyright notice and this
# paragraph and the following disclaimer are duplicated in all
# such forms.
#
# This software is provided "AS IS" and without any express or
# implied warranties, including, without limitation, the implied
# warranties of merchantability and fitness for a particular
# purpose.
#

#	$Id: boot0.m4,v 1.1.1.1 1998/10/05 10:08:37 rnordier Exp $

define(_al,0x0)dnl
define(_cl,0x1)dnl
define(_dl,0x2)dnl
define(_bl,0x3)dnl
define(_ah,0x4)dnl
define(_ch,0x5)dnl
define(_dh,0x6)dnl
define(_bh,0x7)dnl

define(_ax,0x0)dnl
define(_cx,0x1)dnl
define(_dx,0x2)dnl
define(_bx,0x3)dnl
define(_sp,0x4)dnl
define(_bp,0x5)dnl
define(_si,0x6)dnl
define(_di,0x7)dnl

define(_es,0x0)dnl
define(_cs,0x1)dnl
define(_ss,0x2)dnl
define(_ds,0x3)dnl
define(_fs,0x4)dnl
define(_gs,0x5)dnl

define(_bx_si,0x0)dnl
define(_bx_di,0x1)dnl
define(_bp_si,0x2)dnl
define(_bp_di,0x3)dnl
define(_si_,0x4)dnl
define(_di_,0x5)dnl
define(_bp_,0x6)dnl
define(_bx_,0x7)dnl

define(o16,`.byte 0x66')dnl

define(addwia,`.byte 0x5; .word $1')dnl
define(btwrm,`.byte 0xf; .byte 0xa3; .byte 0x6 | ($1 << 0x3); .word $2')dnl
define(btswrm,`.byte 0xf; .byte 0xab; .byte 0x6 | ($1 << 0x3); .word $2')dnl
define(cmpwmr,`.byte 0x3b; .byte ($2 << 0x3) | 0x6; .word $1')dnl
define(cmpwi2,`.byte 0x81; .byte 0xb8 | $3; .word $2; .word $1')dnl
define(cmpwir,`.byte 0x81; .byte 0xf8 | $2; .word $1')dnl
define(movbr0,`.byte 0x88; .byte ($1 << 0x3) | $2')dnl
define(movbrm,`.byte 0x88; .byte 0x6 | ($1 << 0x3); .word $2')dnl
define(movbr1,`.byte 0x88; .byte 0x40 | ($1 << 0x3) | $3; .byte $2')dnl
define(movwr1,`.byte 0x89; .byte 0x40 | ($1 << 0x3) | $3; .byte $2')dnl
define(movb0r,`.byte 0x8a; .byte ($2 << 0x3) | $1')dnl
define(movbmr,`.byte 0x8a; .byte 0x6 | ($2 << 0x3); .word $1')dnl
define(movb1r,`.byte 0x8a; .byte 0x40 | ($3 << 0x3) | $2; .byte $1')dnl
define(movw1r,`.byte 0x8b; .byte 0x40 | ($3 << 0x3) | $2; .byte $1')dnl
define(movws1,`.byte 0x8c; .byte 0x40 | ($1 << 0x3) | $3; .byte $2')dnl
define(leaw1r,`.byte 0x8d; .byte 0x40 | ($3 << 0x3) | $2; .byte $1')dnl
define(movbma,`.byte 0xa0; .word $1')dnl
define(movbam,`.byte 0xa2; .word $1')dnl
define(movwir,`.byte 0xb8 | $2; .word $1')dnl
define(movbi0,`.byte 0xc6; .byte $2; .byte $1')dnl
define(callwi,`.byte 0xe8; .word $1 - . - 0x2')dnl
define(jmpnwi,`.byte 0xe9; .word $1 - . - 0x2')dnl
define(tstbim,`.byte 0xf6; .byte 0x6; .word $2; .byte $1')dnl
define(incb1,`.byte 0xfe; .byte 0x40 | $2; .byte $1')dnl
