/*
 * Copyright (c) 2003
 *	Bill Paul <wpaul@windriver.com>.  All rights reserved.
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
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>

#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>

#include <sys/systm.h>
#include <machine/clock.h>
#include <machine/bus_memio.h>
#include <machine/bus_pio.h>
#include <machine/bus.h>

#include <sys/bus.h>
#include <sys/rman.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/hal_var.h>

#define FUNC void(*)(void)

__stdcall static void hal_stall_exec_cpu(uint32_t);
__stdcall static void hal_writeport_buf_ulong(uint32_t *,
	uint32_t *, uint32_t);
__stdcall static void hal_writeport_buf_ushort(uint16_t *,
	uint16_t *, uint32_t);
__stdcall static void hal_writeport_buf_uchar(uint8_t *,
	uint8_t *, uint32_t);
__stdcall static void hal_writeport_ulong(uint32_t *, uint32_t);
__stdcall static void hal_writeport_ushort(uint16_t *, uint16_t);
__stdcall static void hal_writeport_uchar(uint8_t *, uint8_t);
__stdcall static uint32_t hal_readport_ulong(uint32_t *);
__stdcall static uint16_t hal_readport_ushort(uint16_t *);
__stdcall static uint8_t hal_readport_uchar(uint8_t *);
__stdcall static void hal_readport_buf_ulong(uint32_t *,
	uint32_t *, uint32_t);
__stdcall static void hal_readport_buf_ushort(uint16_t *,
	uint16_t *, uint32_t);
__stdcall static void hal_readport_buf_uchar(uint8_t *,
	uint8_t *, uint32_t);
__stdcall static uint64_t hal_perfcount(uint64_t *);
__stdcall static void dummy (void);

extern struct mtx_pool *ndis_mtxpool;

__stdcall static void
hal_stall_exec_cpu(usecs)
	uint32_t		usecs;
{
	DELAY(usecs);
	return;
}

__stdcall static void
hal_writeport_ulong(port, val)
	uint32_t		*port;
	uint32_t		val;
{
	bus_space_write_4(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port, val);
	return;
}

__stdcall static void
hal_writeport_ushort(port, val)
	uint16_t		*port;
	uint16_t		val;
{
	bus_space_write_2(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port, val);
	return;
}

__stdcall static void
hal_writeport_uchar(port, val)
	uint8_t			*port;
	uint8_t			val;
{
	bus_space_write_1(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port, val);
	return;
}

__stdcall static void
hal_writeport_buf_ulong(port, val, cnt)
	uint32_t		*port;
	uint32_t		*val;
	uint32_t		cnt;
{
	bus_space_write_multi_4(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, val, cnt);
	return;
}

__stdcall static void
hal_writeport_buf_ushort(port, val, cnt)
	uint16_t		*port;
	uint16_t		*val;
	uint32_t		cnt;
{
	bus_space_write_multi_2(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, val, cnt);
	return;
}

__stdcall static void
hal_writeport_buf_uchar(port, val, cnt)
	uint8_t			*port;
	uint8_t			*val;
	uint32_t		cnt;
{
	bus_space_write_multi_1(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, val, cnt);
	return;
}

__stdcall static uint16_t
hal_readport_ushort(port)
	uint16_t		*port;
{
	return(bus_space_read_2(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

__stdcall static uint32_t
hal_readport_ulong(port)
	uint32_t		*port;
{
	return(bus_space_read_4(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

__stdcall static uint8_t
hal_readport_uchar(port)
	uint8_t			*port;
{
	return(bus_space_read_1(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

__stdcall static void
hal_readport_buf_ulong(port, val, cnt)
	uint32_t		*port;
	uint32_t		*val;
	uint32_t		cnt;
{
	bus_space_read_multi_4(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, val, cnt);
	return;
}

__stdcall static void
hal_readport_buf_ushort(port, val, cnt)
	uint16_t		*port;
	uint16_t		*val;
	uint32_t		cnt;
{
	bus_space_read_multi_2(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, val, cnt);
	return;
}

__stdcall static void
hal_readport_buf_uchar(port, val, cnt)
	uint8_t			*port;
	uint8_t			*val;
	uint32_t		cnt;
{
	bus_space_read_multi_1(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, val, cnt);
	return;
}

/*
 * The spinlock implementation in Windows differs from that of FreeBSD.
 * The basic operation of spinlocks involves two steps: 1) spin in a
 * tight loop while trying to acquire a lock, 2) after obtaining the
 * lock, disable preemption. (Note that on uniprocessor systems, you're
 * allowed to skip the first step and just lock out pre-emption, since
 * it's not possible for you to be in contention with another running
 * thread.) Later, you release the lock then re-enable preemption.
 * The difference between Windows and FreeBSD lies in how preemption
 * is disabled. In FreeBSD, it's done using critical_enter(), which on
 * the x86 arch translates to a cli instruction. This masks off all
 * interrupts, and effectively stops the scheduler from ever running
 * so _nothing_ can execute except the current thread. In Windows,
 * preemption is disabled by raising the processor IRQL to DISPATCH_LEVEL.
 * This stops other threads from running, but does _not_ block device
 * interrupts. This means ISRs can still run, and they can make other
 * threads runable, but those other threads won't be able to execute
 * until the current thread lowers the IRQL to something less than
 * DISPATCH_LEVEL.
 *
 * In FreeBSD, ISRs run in interrupt threads, so to duplicate the
 * Windows notion of IRQLs, we use the following rules:
 *
 * PASSIVE_LEVEL == normal kernel thread priority
 * DISPATCH_LEVEL == lowest interrupt thread priotity (PI_SOFT)
 * DEVICE_LEVEL == highest interrupt thread priority  (PI_REALTIME)
 * HIGH_LEVEL == interrupts disabled (critical_enter())
 *
 * Be aware that, at least on the x86 arch, the Windows spinlock
 * functions are divided up in peculiar ways. The actual spinlock
 * functions are KfAcquireSpinLock() and KfReleaseSpinLock(), and
 * they live in HAL.dll. Meanwhile, KeInitializeSpinLock(),
 * KefAcquireSpinLockAtDpcLevel() and KefReleaseSpinLockFromDpcLevel()
 * live in ntoskrnl.exe. Most Windows source code will call
 * KeAcquireSpinLock() and KeReleaseSpinLock(), but these are just
 * macros that call KfAcquireSpinLock() and KfReleaseSpinLock().
 * KefAcquireSpinLockAtDpcLevel() and KefReleaseSpinLockFromDpcLevel()
 * perform the lock aquisition/release functions without doing the
 * IRQL manipulation, and are used when one is already running at
 * DISPATCH_LEVEL. Make sense? Good.
 *
 * According to the Microsoft documentation, any thread that calls
 * KeAcquireSpinLock() must be running at IRQL <= DISPATCH_LEVEL. If
 * we detect someone trying to acquire a spinlock from DEVICE_LEVEL
 * or HIGH_LEVEL, we panic.
 */

__fastcall uint8_t
hal_lock(REGARGS1(kspin_lock *lock))
{
	uint8_t			oldirql;

	/* I am so going to hell for this. */
	if (hal_irql() > DISPATCH_LEVEL)
		panic("IRQL_NOT_LESS_THAN_OR_EQUAL");

	oldirql = FASTCALL1(hal_raise_irql, DISPATCH_LEVEL);
	FASTCALL1(ntoskrnl_lock_dpc, lock);

	return(oldirql);
}

__fastcall void
hal_unlock(REGARGS2(kspin_lock *lock, uint8_t newirql))
{
	FASTCALL1(ntoskrnl_unlock_dpc, lock);
	FASTCALL1(hal_lower_irql, newirql);

	return;
}

__stdcall uint8_t
hal_irql(void)
{
	if (AT_DISPATCH_LEVEL(curthread))
		return(DISPATCH_LEVEL);
	return(PASSIVE_LEVEL);
}

__stdcall static uint64_t
hal_perfcount(freq)
	uint64_t		*freq;
{
	if (freq != NULL)
		*freq = hz;

	return((uint64_t)ticks);
}

__fastcall uint8_t
hal_raise_irql(REGARGS1(uint8_t irql))
{
	uint8_t			oldirql;

	if (irql < hal_irql())
		panic("IRQL_NOT_LESS_THAN");

	if (hal_irql() == DISPATCH_LEVEL)
		return(DISPATCH_LEVEL);

	mtx_lock_spin(&sched_lock);
	oldirql = curthread->td_base_pri;
	sched_prio(curthread, PI_REALTIME);
	mtx_unlock_spin(&sched_lock);

	return(oldirql);
}

__fastcall void 
hal_lower_irql(REGARGS1(uint8_t oldirql))
{
	if (oldirql == DISPATCH_LEVEL)
		return;

	if (hal_irql() != DISPATCH_LEVEL)
		panic("IRQL_NOT_GREATER_THAN");

	mtx_lock_spin(&sched_lock);
	sched_prio(curthread, oldirql);
	mtx_unlock_spin(&sched_lock);

	return;
}

__stdcall
static void dummy()
{
	printf ("hal dummy called...\n");
	return;
}

image_patch_table hal_functbl[] = {
	{ "KeStallExecutionProcessor",	(FUNC)hal_stall_exec_cpu },
	{ "WRITE_PORT_ULONG",		(FUNC)hal_writeport_ulong },
	{ "WRITE_PORT_USHORT",		(FUNC)hal_writeport_ushort },
	{ "WRITE_PORT_UCHAR",		(FUNC)hal_writeport_uchar },
	{ "WRITE_PORT_BUFFER_ULONG",	(FUNC)hal_writeport_buf_ulong },
	{ "WRITE_PORT_BUFFER_USHORT",	(FUNC)hal_writeport_buf_ushort },
	{ "WRITE_PORT_BUFFER_UCHAR",	(FUNC)hal_writeport_buf_uchar },
	{ "READ_PORT_ULONG",		(FUNC)hal_readport_ulong },
	{ "READ_PORT_USHORT",		(FUNC)hal_readport_ushort },
	{ "READ_PORT_UCHAR",		(FUNC)hal_readport_uchar },
	{ "READ_PORT_BUFFER_ULONG",	(FUNC)hal_readport_buf_ulong },
	{ "READ_PORT_BUFFER_USHORT",	(FUNC)hal_readport_buf_ushort },
	{ "READ_PORT_BUFFER_UCHAR",	(FUNC)hal_readport_buf_uchar },
	{ "KfAcquireSpinLock",		(FUNC)hal_lock },
	{ "KfReleaseSpinLock",		(FUNC)hal_unlock },
	{ "KeGetCurrentIrql",		(FUNC)hal_irql },
	{ "KeQueryPerformanceCounter",	(FUNC)hal_perfcount },
	{ "KfLowerIrql",		(FUNC)hal_lower_irql },
	{ "KfRaiseIrql",		(FUNC)hal_raise_irql },

	/*
	 * This last entry is a catch-all for any function we haven't
	 * implemented yet. The PE import list patching routine will
	 * use it for any function that doesn't have an explicit match
	 * in this table.
	 */

	{ NULL, (FUNC)dummy },

	/* End of list. */

	{ NULL, NULL },
};
