/*
 * APM (Advanced Power Management) BIOS Device Driver
 *
 * Copyright (c) 1994 UKAI, Fumitoshi.
 * Copyright (c) 1994-1995 by HOSOKAWA, Tatsumi <hosokawa@mt.cs.keio.ac.jp>
 *
 * This software may be used, modified, copied, and distributed, in
 * both source and binary form provided that the above copyright and
 * these terms are retained. Under no circumstances is the author 
 * responsible for the proper functioning of this software, nor does 
 * the author assume any responsibility for damages incurred with its 
 * use.
 *
 * Sep, 1994	Implemented on FreeBSD 1.1.5.1R (Toshiba AVS001WD)
 *
 *	$Id: apm.c,v 1.10 1994/12/16 07:31:47 phk Exp $
 */

#include "apm.h"

#if NAPM > 0

#ifdef __FreeBSD__
#include <sys/param.h>
#include "conf.h"
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include "i386/isa/isa.h"
#include "i386/isa/isa_device.h"
#include <machine/apm_bios.h>
#include <machine/segments.h>
#include <machine/clock.h>
#include <vm/vm.h>
#include <sys/syslog.h>
#include "apm_setup.h"
#endif /* __FreeBSD__ */

#ifdef MACH_KERNEL
#include <mach/std_types.h>
#include <sys/types.h>
#include <sys/time.h>
#include <device/conf.h>
#include <device/errno.h>
#include <device/tty.h>
#include <device/io_req.h>
#include <kern/time_out.h>

#include <i386/ipl.h>
#include <i386/pio.h>
#include <i386/seg.h>
#include <i386/machspl.h>
#include <chips/busses.h>
#include <i386at/apm_bios.h>
#include <i386at/apm_setup.h>
#include <i386at/apm_segments.h>
#endif /* MACH_KERNEL */

/* static data */
struct apm_softc {
	int	initialized, active, halt_cpu;
	u_int	minorversion, majorversion;
	u_int	cs32_base, cs16_base, ds_base;
	u_int	cs_limit, ds_limit;
	u_int	cs_entry;
	u_int	intversion;
	int	idle_cpu, disabled, disengaged;
	struct apmhook sc_suspend;
	struct apmhook sc_resume;
}; 

static struct apm_softc apm_softc[NAPM];
static struct apm_softc *master_softc = NULL; 	/* XXX */
struct apmhook	*hook[NAPM_HOOK];		/* XXX */
#ifdef APM_SLOWSTART
int		apm_slowstart = 0;
int		apm_ss_cnt = 0;
static int	apm_slowstart_p = 0;
int		apm_slowstart_stat = 0;
#endif /* APM_SLOWSTART */

#ifdef MACH_KERNEL
extern struct fake_descriptor     gdt[GDTSZ];
extern void fix_desc(struct fake_descriptor *, int);
#endif /* MACH_KERNEL */

#define is_enabled(foo) ((foo) ? "enabled" : "disabled")

/* Map version number to integer (keeps ordering of version numbers) */
#define INTVERSION(major, minor)	((major)*100 + (minor))

#ifdef __FreeBSD__
static timeout_t apm_timeout;
#endif /* __FreeBSD__ */
#ifdef MACH_KERNEL
static void apm_timeout(void *);
#endif /* MACH_KERNEL */

/* setup APM GDT discriptors */
static void 
setup_apm_gdt(u_int code32_base, u_int code16_base, u_int data_base, u_int code_limit, u_int data_limit) 
{
#ifdef __FreeBSD__
	/* setup 32bit code segment */
	gdt_segs[GAPMCODE32_SEL].ssd_base  = code32_base;
	gdt_segs[GAPMCODE32_SEL].ssd_limit = code_limit;

	/* setup 16bit code segment */
	gdt_segs[GAPMCODE16_SEL].ssd_base  = code16_base;
	gdt_segs[GAPMCODE16_SEL].ssd_limit = code_limit;

	/* setup data segment */
	gdt_segs[GAPMDATA_SEL  ].ssd_base  = data_base;
	gdt_segs[GAPMDATA_SEL  ].ssd_limit = data_limit;

	/* reflect these changes on physical GDT */
	ssdtosd(gdt_segs + GAPMCODE32_SEL, &gdt[GAPMCODE32_SEL].sd);
	ssdtosd(gdt_segs + GAPMCODE16_SEL, &gdt[GAPMCODE16_SEL].sd);
	ssdtosd(gdt_segs + GAPMDATA_SEL  , &gdt[GAPMDATA_SEL  ].sd);
#endif /* __FreeBSD__ */
#ifdef MACH_KERNEL
	/* setup 32bit code segment */
	gdt[sel_idx(GAPMCODE32_SEL)].offset       = code32_base;
	gdt[sel_idx(GAPMCODE32_SEL)].lim_or_seg   = code_limit;
	gdt[sel_idx(GAPMCODE32_SEL)].size_or_wdct = SZ_32;
	gdt[sel_idx(GAPMCODE32_SEL)].access       = ACC_P | ACC_PL_K | ACC_CODE_R;

	/* setup 16bit code segment */
	gdt[sel_idx(GAPMCODE16_SEL)].offset       = code16_base;
	gdt[sel_idx(GAPMCODE16_SEL)].lim_or_seg   = code_limit;
	gdt[sel_idx(GAPMCODE16_SEL)].size_or_wdct = 0;
	gdt[sel_idx(GAPMCODE16_SEL)].access       = ACC_P | ACC_PL_K | ACC_CODE_R;

	/* setup data segment */
	gdt[sel_idx(GAPMDATA_SEL  )].offset       = data_base;
	gdt[sel_idx(GAPMDATA_SEL  )].lim_or_seg   = data_limit;
	gdt[sel_idx(GAPMDATA_SEL  )].size_or_wdct = 0;
	gdt[sel_idx(GAPMDATA_SEL  )].access       = ACC_P | ACC_PL_K | ACC_DATA_W;

	/* reflect these changes on physical GDT */
	fix_desc(gdt + sel_idx(GAPMCODE32_SEL), 1);
	fix_desc(gdt + sel_idx(GAPMCODE16_SEL), 1);
	fix_desc(gdt + sel_idx(GAPMDATA_SEL)  , 1);
#endif /* MACH_KERNEL */
}

/* 48bit far pointer */
struct addr48 {
	u_long		offset;
	u_short		segment;
} apm_addr;

int apm_errno;

inline
int
apm_int(u_long *eax, u_long *ebx, u_long *ecx)
{
	u_long cf;
	__asm ("pushl	%%ebp
		pushl	%%edx
		pushl	%%esi
		xorl	%3,%3
		movl	%3,%%esi
		lcall	_apm_addr
		jnc	1f
		incl	%3
	1:	
		popl	%%esi
		popl	%%edx
		popl	%%ebp"
		: "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=D" (cf)
		: "0" (*eax),  "1" (*ebx),  "2" (*ecx)
		);		
	apm_errno = ((*eax) >> 8) & 0xff;
	return cf;
}


/* enable/disable power management */
static int 
apm_enable_disable_pm(struct apm_softc *sc, int enable)
{
	u_long eax, ebx, ecx;

	eax = (APM_BIOS << 8) | APM_ENABLEDISABLEPM;

	if (sc->intversion >= INTVERSION(1, 1)) {
		ebx  = PMDV_ALLDEV;
	} else {
		ebx  = 0xffff;	/* APM version 1.0 only */
	}
	ecx  = enable;
	return apm_int(&eax, &ebx, &ecx);
}

/* Tell APM-BIOS that WE will do 1.1 and see what they say... */
static void
apm_driver_version(void)
{
	u_long eax, ebx, ecx, i;

#ifdef APM_DEBUG
	eax = (APM_BIOS<<8) | APM_INSTCHECK;
	ebx  = 0x0;
	ecx  = 0x0101;
	i = apm_int(&eax, &ebx, &ecx);
	printf("[%04lx %04lx %04lx %ld %02x]\n",
		eax, ebx, ecx, i, apm_errno);
#endif

	eax = (APM_BIOS << 8) | APM_DRVVERSION;
	ebx  = 0x0;
	ecx  = 0x0101;
	if(!apm_int(&eax, &ebx, &ecx)) 
		apm_version = eax & 0xffff;

#ifdef APM_DEBUG
	eax = (APM_BIOS << 8) | APM_INSTCHECK;
	ebx  = 0x0;
	ecx  = 0x0101;
	i = apm_int(&eax, &ebx, &ecx);
	printf("[%04lx %04lx %04lx %ld %02x]\n",
		eax, ebx, ecx, i, apm_errno);
#endif
}

/* engage/disengage power management (APM 1.1 or later) */
static int 
apm_engage_disengage_pm(struct apm_softc *sc, int engage)
{
	u_long eax, ebx, ecx, i;

	eax = (APM_BIOS << 8) | APM_ENGAGEDISENGAGEPM;
	ebx = PMDV_ALLDEV;
	ecx = engage;
	i = apm_int(&eax, &ebx, &ecx);
	return i;
}

/* get PM event */
static u_int 
apm_getevent(struct apm_softc *sc)
{
	u_long eax, ebx, ecx;

	eax = (APM_BIOS << 8) | APM_GETPMEVENT;
	
	ebx = 0;
	ecx = 0;
	if (apm_int(&eax, &ebx, &ecx))
		return PMEV_NOEVENT;

	return ebx & 0xffff;
}

/* suspend entire system */
static int 
apm_suspend_system(struct apm_softc *sc)
{
	u_long eax, ebx, ecx;
	
	eax = (APM_BIOS << 8) | APM_SETPWSTATE;
	ebx = PMDV_ALLDEV;
	ecx = PMST_SUSPEND;

	__asm("cli");
	if (apm_int(&eax, &ebx, &ecx)) {
		__asm("sti");
		printf("Entire system suspend failure: errcode = %ld\n", 
			0xff & (eax >> 8));
		return 1;
	}
	__asm("sti");
	return 0;
}

/* Display control */
/*
 * Experimental implementation: My laptop machine can't handle this function
 * If your laptop can control the display via APM, please inform me.
 *                            HOSOKAWA, Tatsumi <hosokawa@mt.cs.keio.ac.jp>
 */
int
apm_display_off(void)
{
	u_long eax, ebx, ecx;
	
	eax = (APM_BIOS << 8) | APM_SETPWSTATE;
	ebx = PMDV_2NDSTORAGE0;
	ecx = PMST_STANDBY;
	if (apm_int(&eax, &ebx, &ecx)) {
		printf("Display off failure: errcode = %ld\n", 
			0xff & (eax >> 8));
		return 1;
	}

	return 0;
}

/* APM Battery low handler */
static void 
apm_battery_low(struct apm_softc *sc)
{
	printf("\007\007 * * * BATTERY IS LOW * * * \007\007");
}

/* APM hook manager */
static struct apmhook *
apm_add_hook(struct apmhook **list, struct apmhook *ah)
{
	int s;
	struct apmhook *p, *prev;

#if 0
	printf("Add hook \"%s\"\n", ah->ah_name);
#endif

	s = splhigh();
	if (ah == NULL) {
		panic("illegal apm_hook!");
	}
	prev = NULL;
	for (p = *list; p != NULL; prev = p, p = p->ah_next) {
		if (p->ah_order > ah->ah_order) {
			break;
		}
	}

	if (prev == NULL) {
		ah->ah_next = *list;
		*list = ah;
	} else {
		ah->ah_next = prev->ah_next;
		prev->ah_next = ah;
	}
	splx(s);
	return ah;
}

static void 
apm_del_hook(struct apmhook **list, struct apmhook *ah)
{
	int s;
	struct apmhook *p, *prev;

	s = splhigh();
	prev = NULL;
	for (p = *list; p != NULL; prev = p, p = p->ah_next) {
		if (p == ah) {
			goto deleteit;
		}
	}
	panic("Tried to delete unregistered apm_hook.");
	goto nosuchnode;
deleteit:
	if (prev != NULL) {
		prev->ah_next = p->ah_next;
	} else {
		*list = p->ah_next;
	}
nosuchnode:
	splx(s);
}


/* APM driver calls some functions automatically */
static void     
apm_execute_hook(struct apmhook *list)
{
	struct apmhook *p;

	for (p = list; p != NULL; p = p->ah_next) {
#if 0
		printf("Execute APM hook \"%s.\"\n", p->ah_name);
#endif
		if ((*(p->ah_fun))(p->ah_arg)) {
			printf("Warning: APM hook \"%s\" failed", p->ah_name);
		}       
	}       
}


/* establish an apm hook */
struct apmhook *
apm_hook_establish(int apmh, struct apmhook *ah)
{
	if (apmh < 0 || apmh >= NAPM_HOOK)
		return NULL;

	return apm_add_hook(&hook[apmh], ah);
}

/* disestablish an apm hook */
void
apm_hook_disestablish(int apmh, struct apmhook *ah)
{
	if (apmh < 0 || apmh >= NAPM_HOOK)
		return;

	apm_del_hook(&hook[apmh], ah);
}


static struct timeval suspend_time;
static struct timeval diff_time;

static int 
apm_default_resume(struct apm_softc *sc)
{
#ifdef __FreeBSD__
	int pl;
	u_int second, minute, hour;
	struct timeval resume_time, tmp_time;

	/* modified for adjkerntz */
	pl = splsoftclock();
	inittodr(0);			/* adjust time to RTC */
	microtime(&resume_time);
	tmp_time = time;		/* because 'time' is volatile */
	timevaladd(&tmp_time, &diff_time);
	time = tmp_time;
	splx(pl);
	second = resume_time.tv_sec - suspend_time.tv_sec;
	hour = second / 3600;
	second %= 3600;
	minute = second / 60;
	second %= 60;
	log(LOG_NOTICE, "resumed from suspended mode (slept %02d:%02d:%02d)\n",
		hour, minute, second);
#endif /* __FreeBSD__ */
	return 0;
}

static int 
apm_default_suspend(void)
{
#ifdef __FreeBSD__
	int	pl;

	pl = splsoftclock();
	microtime(&diff_time);
	inittodr(0);
	microtime(&suspend_time);
	timevalsub(&diff_time, &suspend_time);
	splx(pl);
#if 0
	printf("diff_time = %d:%d\n", diff_time.tv_sec, diff_time.tv_usec);
#endif
#endif /* __FreeBSD__ */
	return 0;
}

static void apm_processevent(struct apm_softc *);

/*
 * Public interface to the suspend/resume:
 *
 * Execute suspend and resume hook before and after sleep, respectively.
 *
 */

void 
apm_suspend(void)
{
	struct apm_softc *sc;

	sc = master_softc;      /* XXX */
	if (!sc)
		return;

	if (sc->initialized) {
		apm_execute_hook(hook[APM_HOOK_SUSPEND]);
		apm_suspend_system(sc);
		apm_processevent(sc);
	}
}

void
apm_resume(void)
{
	struct apm_softc *sc;

	sc = master_softc;      /* XXX */
	if (!sc)
		return;

	if (sc->initialized) {
		apm_execute_hook(hook[APM_HOOK_RESUME]);
	}
}


/* get APM information */
static int
apm_get_info(struct apm_softc *sc, apm_info_t aip)
{
	u_long eax, ebx, ecx;

	eax = (APM_BIOS << 8) | APM_GETPWSTATUS;
	ebx = PMDV_ALLDEV;
	ecx = 0;

	if (apm_int(&eax, &ebx, &ecx))
		return 1;

	aip->ai_acline    = (ebx >> 8) & 0xff;
	aip->ai_batt_stat = ebx & 0xff;
	aip->ai_batt_life = ecx & 0xff;
	aip->ai_major     = (u_int)sc->majorversion;
	aip->ai_minor     = (u_int)sc->minorversion;
	return 0;
}


/* inform APM BIOS that CPU is idle */
void 
apm_cpu_idle(void)
{
	struct apm_softc *sc = master_softc;    /* XXX */

	if (sc->idle_cpu) {
		if (sc->active) {
			__asm ("movw $0x5305, %ax; lcall _apm_addr");
		}
	}
	/*
	 * Some APM implementation halts CPU in BIOS, whenever 
	 * "CPU-idle" function are invoked, but swtch() of
	 * FreeBSD halts CPU, therefore, CPU is halted twice
	 * in the sched loop. It makes the interrupt latency
	 * terribly long and be able to cause a serious problem
	 * in interrupt processing. We prevent it by removing
	 * "hlt" operation from swtch() and managed it under
	 * APM driver.
	 */
	/*
	 * UKAI Note: on NetBSD, idle() called from cpu_switch()
	 * doesn't halt CPU, so halt_cpu may not need on NetBSD/i386
	 * or only "sti" operation would be needed.
	 */

	if (!sc->active || sc->halt_cpu) {
		__asm("sti ; hlt");	/* wait for interrupt */
	}
}

/* inform APM BIOS that CPU is busy */
void 
apm_cpu_busy(void)
{
	struct apm_softc *sc = master_softc;	/* XXX */

	if (sc->idle_cpu && sc->active) {
		__asm("movw $0x5306, %ax; lcall _apm_addr");
	}
}


/*
 * APM timeout routine:
 *
 * This routine is automatically called by timer once per second.
 */

static void 
apm_timeout(void *arg)
{
	struct apm_softc *sc = arg;

	apm_processevent(sc);
	timeout(apm_timeout, (void *)sc, hz - 1 );  /* More than 1 Hz */
}

/* enable APM BIOS */
static void 
apm_event_enable(struct apm_softc *sc)
{
#ifdef APM_DEBUG
	printf("called apm_event_enable()\n");
#endif
	if (sc->initialized) {
		sc->active = 1;
		apm_timeout(sc);
	}
}

/* disable APM BIOS */
static void 
apm_event_disable(struct apm_softc *sc)
{
#ifdef APM_DEBUG
	printf("called apm_event_disable()\n");
#endif
	if (sc->initialized) {
		untimeout(apm_timeout, NULL);
		sc->active = 0;
	}
}

/* halt CPU in scheduling loop */
static void 
apm_halt_cpu(struct apm_softc *sc)
{
	if (sc->initialized) {
		sc->halt_cpu = 1;
	}
#ifdef APM_SLOWSTART
	apm_slowstart = 0;
#endif /* APM_SLOWSTART */
}

/* don't halt CPU in scheduling loop */
static void 
apm_not_halt_cpu(struct apm_softc *sc)
{
	if (sc->initialized) {
		sc->halt_cpu = 0;
	}
#ifdef APM_SLOWSTART
	apm_slowstart = apm_slowstart_p;
#endif /* APM_SLOWSTART */
}

/* device driver definitions */
#ifdef __FreeBSD__
int apmprobe (struct isa_device *);
int apmattach(struct isa_device *);
struct isa_driver apmdriver = {
	apmprobe, apmattach, "apm" };
#endif /* __FreeBSD__ */

#ifdef MACH_KERNEL
int apmprobe(vm_offset_t, struct bus_ctlr *);
void apmattach(struct bus_device *);
static struct bus_device *apminfo[NAPM];
static vm_offset_t apmstd[NAPM] = { 0 };
struct bus_driver apmdriver = {
	apmprobe, 0, apmattach, 0, apmstd, "apm", apminfo, 0, 0, 0};
#endif /* MACH_KERNEL */


/*
 * probe APM (dummy):
 *
 * APM probing routine is placed on locore.s and apm_init.S because
 * this process forces the CPU to turn to real mode or V86 mode.
 * Current version uses real mode, but on future version, we want
 * to use V86 mode in APM initialization.
 */

int 
#ifdef __FreeBSD__
	apmprobe(struct isa_device *dvp)
#endif /* __FreeBSD__ */
#ifdef MACH_KERNEL
	apmprobe(vm_offset_t port, struct bus_ctlr *devc)
#endif /* MACH_KERNEL */
{
#ifdef __FreeBSD__
	int     unit = dvp->id_unit;
#endif /* __FreeBSD__ */
#ifdef MACH_KERNEL
	int     unit = devc->unit;
#endif /* MACH_KERNEL */
	struct apm_softc *sc = &apm_softc[unit];

	switch (apm_version) {
	case APMINI_CANTFIND:
		/* silent */
		return 0;
	case APMINI_NOT32BIT:
		printf("apm%d: 32bit connection is not supported.\n", unit);
		return 0;
	case APMINI_CONNECTERR:
		printf("apm%d: 32-bit connection error.\n", unit);
		return 0;
	}

	return -1;
}


/* Process APM event */
static void
apm_processevent(struct apm_softc *sc)
{
	int apm_event;

#ifdef APM_DEBUG
#  define OPMEV_DEBUGMESSAGE(symbol) case symbol: \
	printf("Original APM Event: " #symbol "\n");
#else
#  define OPMEV_DEBUGMESSAGE(symbol) case symbol:
#endif
	while (1) {
		apm_event = apm_getevent(sc);
		if (apm_event == PMEV_NOEVENT) 
			break;
		switch (apm_event) {
		    OPMEV_DEBUGMESSAGE(PMEV_STANDBYREQ);
			apm_suspend();
			break;
		    OPMEV_DEBUGMESSAGE(PMEV_SUSPENDREQ);
			apm_suspend();
			break;
		    OPMEV_DEBUGMESSAGE(PMEV_USERSUSPENDREQ);
			apm_suspend();
			break;
		    OPMEV_DEBUGMESSAGE(PMEV_CRITSUSPEND);
			apm_suspend();
			break;
		    OPMEV_DEBUGMESSAGE(PMEV_NORMRESUME);
			apm_resume();
			break;
		    OPMEV_DEBUGMESSAGE(PMEV_CRITRESUME);
			apm_resume();
			break;
		    OPMEV_DEBUGMESSAGE(PMEV_STANDBYRESUME);
			apm_resume();
			break;
		    OPMEV_DEBUGMESSAGE(PMEV_BATTERYLOW);
			apm_battery_low(sc);
			apm_suspend();
			break;

		    OPMEV_DEBUGMESSAGE(PMEV_POWERSTATECHANGE);
			break;

		    OPMEV_DEBUGMESSAGE(PMEV_UPDATETIME);
			inittodr(0);	/* adjust time to RTC */
			break;

		    default:
			printf("Unknown Original APM Event 0x%x\n", apm_event);
			    break;
		}
	}
}

/*
 * Attach APM:
 *
 * Initialize APM driver (APM BIOS itself has been initialized in locore.s)
 *
 * Now, unless I'm mad, (not quite ruled out yet), the APM-1.1 spec is bogus:
 * 
 * Appendix C says under the header "APM 1.0/APM 1.1 Modal BIOS Behavior"
 * that "When an APM Driver connects with an APM 1.1 BIOS, the APM 1.1 BIOS
 * will default to an APM 1.0 connection.  After an APM Driver calls the APM
 * Driver Version function, specifying that it supports APM 1.1, and [sic!]
 * APM BIOS will change its behavior to an APM 1.1 connection.  If the APM
 * BIOS is an APM 1.0 BIOS, the APM Driver Version function call will fail,
 * and the connection will remain an APM 1.0 connection."
 *
 * OK so I can establish a 1.0 connection, and then tell that I'm a 1.1
 * and maybe then the BIOS will tell that it too is a 1.1.
 * Fine.
 * Now how will I ever get the segment-limits for instance ?  There is no 
 * way I can see that I can get a 1.1 response back from an "APM Protected 
 * Mode 32-bit Interface Connect" function ???
 * 
 * Who made this,  Intel and Microsoft ?  -- How did you guess !
 *
 * /phk
 */

#ifdef __FreeBSD__
int 
apmattach(struct isa_device *dvp)
#endif /* __FreeBSD__ */
#ifdef MACH_KERNEL
void 
apmattach(struct bus_device *dvp)
#endif /* MACH_KERNEL */
{
#ifdef __FreeBSD__
	int	unit = dvp->id_unit;
#define APM_KERNBASE	KERNBASE
#endif /* __FreeBSD__ */
#ifdef MACH_KERNEL
	int	unit = dvp->unit;
#define APM_KERNBASE	VM_MIN_KERNEL_ADDRESS
#endif /* MACH_KERNEL */
	struct apm_softc	*sc = &apm_softc[unit];
	int	i;

	master_softc = sc;	/* XXX */
	sc->initialized = 0;
	sc->active = 0;
	sc->halt_cpu = 1;

	/* setup APM parameters */
	sc->cs16_base = (apm_cs32_base << 4) + APM_KERNBASE;
	sc->cs32_base = (apm_cs16_base << 4) + APM_KERNBASE;
	sc->ds_base = (apm_ds_base << 4) + APM_KERNBASE;
	sc->cs_limit = apm_cs_limit;
	sc->ds_limit = apm_ds_limit;
	sc->cs_entry = apm_cs_entry;

	sc->idle_cpu = ((apm_flags & APM_CPUIDLE_SLOW) != 0);
	sc->disabled = ((apm_flags & APM_DISABLED) != 0);
	sc->disengaged = ((apm_flags & APM_DISENGAGED) != 0);

#ifdef APM_SLOWSTART
	if (sc->idle_cpu) {
		apm_slowstart = apm_slowstart_p = 1;
	}
#endif 

	/* print bootstrap messages */
#ifdef APM_DEBUG
	printf(" found APM BIOS version %04x\n",  apm_version);
	printf("apm%d: Code32 0x%08x, Code16 0x%08x, Data 0x%08x\n",
		unit, sc->cs32_base, sc->cs16_base, sc->ds_base);
	printf("apm%d: Code entry 0x%08x, Idling CPU %s, Management %s\n",
		unit, sc->cs_entry, is_enabled(sc->idle_cpu), 
		is_enabled(!sc->disabled));
	printf("apm%d: CS_limit=%x, DS_limit=%x\n",
		unit, sc->cs_limit, sc->ds_limit);
#endif /* APM_DEBUG */

	sc->cs_limit = 0xffff;
	sc->ds_limit = 0xffff;

	/* setup GDT */
	setup_apm_gdt(sc->cs32_base, sc->cs16_base, sc->ds_base, 
			sc->cs_limit, sc->ds_limit);

	/* setup entry point 48bit pointer */
#ifdef __FreeBSD__
	apm_addr.segment = GSEL(GAPMCODE32_SEL, SEL_KPL);
#endif /* __FreeBSD__ */
#ifdef MACH_KERNEL
	apm_addr.segment = GAPMCODE32_SEL;
#endif /* MACH_KERNEL */
	apm_addr.offset  = sc->cs_entry;

	/* Try to kick bios into 1.1 mode */
	apm_driver_version();
	sc->minorversion = ((apm_version & 0x00f0) >>  4) * 10 +
			((apm_version & 0x000f) >> 0);
	sc->majorversion = ((apm_version & 0xf000) >> 12) * 10 + 
			((apm_version & 0x0f00) >> 8);

	sc->intversion = INTVERSION(sc->majorversion, sc->minorversion);

	if (sc->intversion >= INTVERSION(1, 1)) {
		printf("apm%d: Engaged control %s\n",
			unit, is_enabled(!sc->disengaged));
	}

	printf(" found APM BIOS version %d.%d\n", 
		sc->majorversion, sc->minorversion);
	printf("apm%d: Idling CPU %s\n", unit, is_enabled(sc->idle_cpu));

	/* enable power management */
	if (sc->disabled) {
		if (apm_enable_disable_pm(sc, 1)) {
			printf("Warning: APM enable function failed! [%x]\n", 
				apm_errno);
		}
	}

	/* engage power managment (APM 1.1 or later) */
	if (sc->intversion >= INTVERSION(1, 1) && sc->disengaged) {
		if (apm_engage_disengage_pm(sc, 1)) {
			printf("Warning: APM engage function failed [%x]\n", 
				apm_errno);
		}
	}

        /* default suspend hook */
        sc->sc_suspend.ah_fun = apm_default_suspend;
        sc->sc_suspend.ah_arg = sc;
        sc->sc_suspend.ah_name = "default suspend";
        sc->sc_suspend.ah_order = APM_MAX_ORDER;

        /* default resume hook */
        sc->sc_resume.ah_fun = apm_default_resume;
        sc->sc_resume.ah_arg = sc;
        sc->sc_resume.ah_name = "default resume";
        sc->sc_resume.ah_order = APM_MIN_ORDER;

        apm_hook_establish(APM_HOOK_SUSPEND, &sc->sc_suspend);
        apm_hook_establish(APM_HOOK_RESUME , &sc->sc_resume);

	apm_event_enable(sc);

	sc->initialized = 1;

#ifdef __FreeBSD__
	return 0;
#endif /* __FreeBSD__ */
}

#ifdef __FreeBSD__
int 
apmopen(dev_t dev, int flag, int fmt, struct proc *p) 
{
	struct apm_softc *sc = &apm_softc[minor(dev)];

	if (minor(dev) >= NAPM) {
		return (ENXIO);
	}
	if (!sc->initialized) {
		return ENXIO;
	}
	return 0;
}

int 
apmclose(dev_t dev, int flag, int fmt, struct proc *p)
{
	return 0;
}

int 
apmioctl(dev_t dev, int cmd, caddr_t addr, int flag, struct proc *p)
{
	struct apm_softc *sc = &apm_softc[minor(dev)];
	int error = 0;
	int pl;

#ifdef APM_DEBUG
	printf("APM ioctl: minor = %d, cmd = 0x%x\n", minor(dev), cmd);
#endif

	if (minor(dev) >= NAPM) {
		return ENXIO;
	}
	if (!sc->initialized) {
		return ENXIO;
	}
	switch (cmd) {
	case APMIO_SUSPEND:
		apm_suspend();
		break;
	case APMIO_GETINFO:
		if (apm_get_info(sc, (apm_info_t)addr)) {
			error = ENXIO;
		}
		break;
	case APMIO_ENABLE:
		apm_event_enable(sc);
		break;
	case APMIO_DISABLE:
		apm_event_disable(sc);
		break;
	case APMIO_HALTCPU:
		apm_halt_cpu(sc);
		break;
	case APMIO_NOTHALTCPU:
		apm_not_halt_cpu(sc);
		break;
	case APMIO_DISPLAYOFF:
		if (apm_display_off()) {
			error = ENXIO;
		}
		break;
	default:
		error = EINVAL;
		break;
	}
	return error;
}
#endif /* __FreeBSD__ */

#ifdef MACH_KERNEL
io_return_t apmopen(dev_t dev, int flag, io_req_t ior)
{
	int result;

	result = ENXIO;
	return result;
}

io_return_t apmclose(dev_t dev, int flag)
{
	return 0;
}

io_return_t apmgetstat(dev_t dev, int flavor, int *data, u_int *count)
{
}

io_return_t apmsetstat(dev_t dev, int flavor, int *data, u_int count)
{
}
#endif /* MACH_KERNEL */

#endif /* NAPM > 0 */
