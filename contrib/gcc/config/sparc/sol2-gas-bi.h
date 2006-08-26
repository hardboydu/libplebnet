/* Definitions of target machine for GCC, for bi-arch SPARC
   running Solaris 2 using the GNU assembler.  */

#undef  AS_SPARC64_FLAG
#define AS_SPARC64_FLAG	"-TSO -64 -Av9"

/* Emit a DTP-relative reference to a TLS variable.  */
#ifdef HAVE_AS_TLS
#define ASM_OUTPUT_DWARF_DTPREL(FILE, SIZE, X) \
  sparc_output_dwarf_dtprel (FILE, SIZE, X)
#endif
