/* Definitions for Intel 386 running system V, using gas.
   Copyright (C) 1992, 1996, 2000 Free Software Foundation, Inc.

This file is part of GNU CC.

GNU CC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU CC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU CC; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include "i386/gas.h"

/* Add stuff that normally comes from i386/sysv3.h */

/* longjmp may fail to restore the registers if called from the same
   function that called setjmp.  To compensate, the compiler avoids
   putting variables in registers in functions that use both setjmp
   and longjmp.  */

#define NON_SAVING_SETJMP \
  (current_function_calls_setjmp && current_function_calls_longjmp)

/* longjmp may fail to restore the stack pointer if the saved frame
   pointer is the same as the caller's frame pointer.  Requiring a frame
   pointer in any function that calls setjmp or longjmp avoids this
   problem, unless setjmp and longjmp are called from the same function.
   Since a frame pointer will be required in such a function, it is OK
   that the stack pointer is not restored.  */

#undef SUBTARGET_FRAME_POINTER_REQUIRED
#define SUBTARGET_FRAME_POINTER_REQUIRED \
  (current_function_calls_setjmp || current_function_calls_longjmp)

/* Modify ASM_OUTPUT_LOCAL slightly to test -msvr3-shlib, adapted to gas  */
#undef ASM_OUTPUT_LOCAL
#define ASM_OUTPUT_LOCAL(FILE, NAME, SIZE, ROUNDED)	\
  do {							\
    int align = exact_log2 (ROUNDED);			\
    if (align > 2) align = 2;				\
    if (TARGET_SVR3_SHLIB)				\
      {							\
	data_section ();				\
	ASM_OUTPUT_ALIGN ((FILE), align == -1 ? 2 : align); \
	ASM_OUTPUT_LABEL ((FILE), (NAME));		\
	fprintf ((FILE), "\t.set .,.+%u\n", (ROUNDED));	\
      }							\
    else						\
      {							\
	fputs (".lcomm ", (FILE));			\
	assemble_name ((FILE), (NAME));			\
	fprintf ((FILE), ",%u\n", (ROUNDED));		\
      }							\
  } while (0)

/* Add stuff that normally comes from i386/sysv3.h via svr3.h */

/* Define the actual types of some ANSI-mandated types.  These
   definitions should work for most SVR3 systems.  */

#undef SIZE_TYPE
#define SIZE_TYPE "unsigned int"

#undef PTRDIFF_TYPE
#define PTRDIFF_TYPE "int"

#undef WCHAR_TYPE
#define WCHAR_TYPE "long int"

#undef WCHAR_TYPE_SIZE
#define WCHAR_TYPE_SIZE BITS_PER_WORD

/* ??? This stuff is copied from config/svr3.h.  In the future,
   this file should be rewritten to include config/svr3.h
   and override what isn't right.  */

/* Support const sections and the ctors and dtors sections for g++.
   Note that there appears to be two different ways to support const
   sections at the moment.  You can either #define the symbol
   READONLY_DATA_SECTION (giving it some code which switches to the
   readonly data section) or else you can #define the symbols
   EXTRA_SECTIONS, EXTRA_SECTION_FUNCTIONS, SELECT_SECTION, and
   SELECT_RTX_SECTION.  We do both here just to be on the safe side.
   However, use of the const section is turned off by default
   unless the specific tm.h file turns it on by defining
   USE_CONST_SECTION as 1.  */

#define USE_CONST_SECTION	0

#define INIT_SECTION_ASM_OP     "\t.section\t.init"
#define FINI_SECTION_ASM_OP     "\t.section .fini,\"x\""
#define CONST_SECTION_ASM_OP	"\t.section\t.rodata, \"x\""
#define CTORS_SECTION_ASM_OP	INIT_SECTION_ASM_OP
#define DTORS_SECTION_ASM_OP    FINI_SECTION_ASM_OP

/* CTOR_LIST_BEGIN and CTOR_LIST_END are machine-dependent
   because they push on the stack.  */
/* This is copied from i386/sysv3.h.  */

#define CTOR_LIST_BEGIN				\
  asm (INIT_SECTION_ASM_OP);			\
  asm ("pushl $0")
#define CTOR_LIST_END CTOR_LIST_BEGIN

/* Constructor list on stack is in reverse order.  Go to the end of the
   list and go backwards to call constructors in the right order.  */
#define DO_GLOBAL_CTORS_BODY					\
do {								\
  func_ptr *p, *beg = alloca (0);				\
  for (p = beg; *p; p++)					\
    ;								\
  while (p != beg)						\
    (*--p) ();							\
} while (0)

/* Add extra sections .rodata, .init and .fini.  */

#undef EXTRA_SECTIONS
#define EXTRA_SECTIONS in_const, in_init, in_fini

#undef EXTRA_SECTION_FUNCTIONS
#define EXTRA_SECTION_FUNCTIONS					\
  CONST_SECTION_FUNCTION					\
  INIT_SECTION_FUNCTION						\
  FINI_SECTION_FUNCTION

#define INIT_SECTION_FUNCTION					\
void								\
init_section ()							\
{								\
  if (in_section != in_init)					\
    {								\
      fprintf (asm_out_file, "%s\n", INIT_SECTION_ASM_OP);	\
      in_section = in_init;					\
    }								\
}

#define FINI_SECTION_FUNCTION					\
void								\
fini_section ()							\
{								\
  if (in_section != in_fini)					\
    {								\
      fprintf (asm_out_file, "%s\n", FINI_SECTION_ASM_OP);	\
      in_section = in_fini;					\
    }								\
}

#define READONLY_DATA_SECTION() const_section ()

#define CONST_SECTION_FUNCTION						\
void									\
const_section ()							\
{									\
  if (!USE_CONST_SECTION)						\
    text_section();							\
  else if (in_section != in_const)					\
    {									\
      fprintf (asm_out_file, "%s\n", CONST_SECTION_ASM_OP);		\
      in_section = in_const;						\
    }									\
}

#define TARGET_ASM_CONSTRUCTOR  ix86_svr3_asm_out_constructor

/* A C statement or statements to switch to the appropriate
   section for output of DECL.  DECL is either a `VAR_DECL' node
   or a constant of some sort.  RELOC indicates whether forming
   the initial value of DECL requires link-time relocations.  */

#define SELECT_SECTION(DECL,RELOC,ALIGN)				\
{									\
  if (TREE_CODE (DECL) == STRING_CST)					\
    {									\
      if (! flag_writable_strings)					\
	const_section ();						\
      else								\
	data_section ();						\
    }									\
  else if (TREE_CODE (DECL) == VAR_DECL)				\
    {									\
      if ((0 && RELOC)	/* should be (flag_pic && RELOC) */		\
	  || !TREE_READONLY (DECL) || TREE_SIDE_EFFECTS (DECL)		\
	  || !DECL_INITIAL (DECL)					\
	  || (DECL_INITIAL (DECL) != error_mark_node 			\
	      && !TREE_CONSTANT (DECL_INITIAL (DECL))))			\
	data_section ();						\
      else								\
	const_section ();						\
    }									\
  else									\
    const_section ();							\
}

/* A C statement or statements to switch to the appropriate
   section for output of RTX in mode MODE.  RTX is some kind
   of constant in RTL.  The argument MODE is redundant except
   in the case of a `const_int' rtx.  Currently, these always
   go into the const section.  */

#define SELECT_RTX_SECTION(MODE,RTX,ALIGN) const_section()
