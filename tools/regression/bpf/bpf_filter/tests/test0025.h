/*-
 * Test 0025:	BPF_ALU|BPF_SUB|BPF_X
 *
 * $FreeBSD$
 */

/* BPF program */
struct bpf_insn pc[] = {
	BPF_STMT(BPF_LD|BPF_IMM, 0xdeadc0de),
	BPF_STMT(BPF_LDX|BPF_IMM, 0x20000801),
	BPF_STMT(BPF_ALU|BPF_SUB|BPF_X, 0),
	BPF_STMT(BPF_RET|BPF_A, 0),
};

/* Packet */
u_char	pkt[] = {
	0x00,
};

/* Packet length seen on wire */
u_int	wirelen =	sizeof(pkt);

/* Packet length passed on buffer */
u_int	buflen =	sizeof(pkt);

/* Invalid instruction */
int	invalid =	0;

/* Expected return value */
u_int	expect =	0xbeadb8dd;

/* Expeced signal */
int	expect_signal =	0;
