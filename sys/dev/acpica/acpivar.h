/*-
 * Copyright (c) 2000 Mitsuru IWASAKI <iwasaki@jp.freebsd.org>
 * Copyright (c) 2000 Michael Smith <msmith@freebsd.org>
 * Copyright (c) 2000 BSDi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD$
 */

#include "bus_if.h"
#include <sys/eventhandler.h>
#include <sys/sysctl.h>
#if __FreeBSD_version >= 500000
#include <sys/lock.h>
#include <sys/mutex.h>
#endif

#include <machine/bus.h>
#include <machine/resource.h>

#if __FreeBSD_version < 500000
typedef vm_offset_t vm_paddr_t;
#endif

struct acpi_softc {
    device_t		acpi_dev;
    dev_t		acpi_dev_t;

    struct resource	*acpi_irq;
    int			acpi_irq_rid;
    void		*acpi_irq_handle;

    int			acpi_enabled;
    int			acpi_sstate;
    int			acpi_sleep_disabled;

    struct sysctl_ctx_list acpi_sysctl_ctx;
    struct sysctl_oid	*acpi_sysctl_tree;
    int			acpi_power_button_sx;
    int			acpi_sleep_button_sx;
    int			acpi_lid_switch_sx;

    int			acpi_standby_sx;
    int			acpi_suspend_sx;

    int			acpi_sleep_delay;
    int			acpi_s4bios;
    int			acpi_disable_on_poweroff;
    int			acpi_verbose;

    bus_dma_tag_t	acpi_waketag;
    bus_dmamap_t	acpi_wakemap;
    vm_offset_t		acpi_wakeaddr;
    vm_paddr_t		acpi_wakephys;

    struct sysctl_ctx_list	 acpi_battery_sysctl_ctx;
    struct sysctl_oid		*acpi_battery_sysctl_tree;
};

struct acpi_device {
    /* ACPI ivars */
    ACPI_HANDLE			ad_handle;
    int				ad_magic;
    void			*ad_private;

    /* Resources */
    struct resource_list	ad_rl;
};

struct acpi_prw_data {
    ACPI_HANDLE		gpe_handle;
    int			gpe_bit;
    int			lowest_wake;
    void		*power_res;
};

/* Flags for each device defined in the AML namespace. */
#define ACPI_FLAG_WAKE_CAPABLE	0x1
#define ACPI_FLAG_WAKE_ENABLED	0x2

#if __FreeBSD_version < 500000
/*
 * In 4.x, ACPI is protected by splhigh().
 */
# define ACPI_LOCK			s = splhigh()
# define ACPI_UNLOCK			splx(s)
# define ACPI_ASSERTLOCK
# define ACPI_MSLEEP(a, b, c, d, e)	tsleep(a, c, d, e)
# define ACPI_LOCK_DECL			int s
# define kthread_create(a, b, c, d, e, f)	kthread_create(a, b, c, f)
# define tc_init(a)			init_timecounter(a)
#else
# define ACPI_LOCK
# define ACPI_UNLOCK
# define ACPI_ASSERTLOCK
# define ACPI_LOCK_DECL
#endif

/*
 * ACPI CA does not define layers for non-ACPI CA drivers.
 * We define some here within the range provided.
 */
#define	ACPI_AC_ADAPTER		0x00010000
#define	ACPI_BATTERY		0x00020000
#define	ACPI_BUS		0x00040000
#define	ACPI_BUTTON		0x00080000
#define	ACPI_EC			0x00100000
#define	ACPI_FAN		0x00200000
#define	ACPI_POWERRES		0x00400000
#define	ACPI_PROCESSOR		0x00800000
#define	ACPI_THERMAL		0x01000000
#define	ACPI_TIMER		0x02000000
#define	ACPI_ASUS		0x04000000

/*
 * Constants for different interrupt models used with acpi_SetIntrModel().
 */
#define	ACPI_INTR_PIC		0
#define	ACPI_INTR_APIC		1
#define	ACPI_INTR_SAPIC		2

/*
 * Note that the low ivar values are reserved to provide
 * interface compatibility with ISA drivers which can also
 * attach to ACPI.
 */
#define ACPI_IVAR_HANDLE	0x100
#define ACPI_IVAR_MAGIC		0x101
#define ACPI_IVAR_PRIVATE	0x102

/*
 * Accessor functions for our ivars.  Default value for BUS_READ_IVAR is
 * (type) 0.  The <sys/bus.h> accessor functions don't check return values.
 */
#define __ACPI_BUS_ACCESSOR(varp, var, ivarp, ivar, type)	\
								\
static __inline type varp ## _get_ ## var(device_t dev)		\
{								\
    uintptr_t v = 0;						\
    BUS_READ_IVAR(device_get_parent(dev), dev,			\
	ivarp ## _IVAR_ ## ivar, &v);				\
    return ((type) v);						\
}								\
								\
static __inline void varp ## _set_ ## var(device_t dev, type t)	\
{								\
    uintptr_t v = (uintptr_t) t;				\
    BUS_WRITE_IVAR(device_get_parent(dev), dev,			\
	ivarp ## _IVAR_ ## ivar, v);				\
}

__ACPI_BUS_ACCESSOR(acpi, handle, ACPI, HANDLE, ACPI_HANDLE)
__ACPI_BUS_ACCESSOR(acpi, magic, ACPI, MAGIC, int)
__ACPI_BUS_ACCESSOR(acpi, private, ACPI, PRIVATE, void *)

void acpi_fake_objhandler(ACPI_HANDLE h, UINT32 fn, void *data);
static __inline device_t
acpi_get_device(ACPI_HANDLE handle)
{
    void *dev = NULL;
    AcpiGetData(handle, acpi_fake_objhandler, &dev);
    return ((device_t)dev);
}

static __inline ACPI_OBJECT_TYPE
acpi_get_type(device_t dev)
{
    ACPI_HANDLE		h;
    ACPI_OBJECT_TYPE	t;

    if ((h = acpi_get_handle(dev)) == NULL)
	return (ACPI_TYPE_NOT_FOUND);
    if (AcpiGetType(h, &t) != AE_OK)
	return (ACPI_TYPE_NOT_FOUND);
    return (t);
}

#ifdef ACPI_DEBUGGER
void		acpi_EnterDebugger(void);
#endif

#ifdef ACPI_DEBUG
#include <sys/cons.h>
#define STEP(x)		do {printf x, printf("\n"); cngetc();} while (0)
#else
#define STEP(x)
#endif

#define ACPI_VPRINT(dev, acpi_sc, x...) do {			\
    if (acpi_get_verbose(acpi_sc))				\
	device_printf(dev, x);					\
} while (0)

#define ACPI_DEVINFO_PRESENT(x)	(((x) & 0x9) == 9)
BOOLEAN		acpi_DeviceIsPresent(device_t dev);
BOOLEAN		acpi_BatteryIsPresent(device_t dev);
BOOLEAN		acpi_MatchHid(ACPI_HANDLE h, char *hid);
ACPI_STATUS	acpi_GetHandleInScope(ACPI_HANDLE parent, char *path,
		    ACPI_HANDLE *result);
uint32_t	acpi_TimerDelta(uint32_t end, uint32_t start);
ACPI_BUFFER	*acpi_AllocBuffer(int size);
ACPI_STATUS	acpi_ConvertBufferToInteger(ACPI_BUFFER *bufp,
		    UINT32 *number);
ACPI_STATUS	acpi_GetInteger(ACPI_HANDLE handle, char *path,
		    UINT32 *number);
ACPI_STATUS	acpi_SetInteger(ACPI_HANDLE handle, char *path,
		    UINT32 number);
ACPI_STATUS	acpi_ForeachPackageObject(ACPI_OBJECT *obj, 
		    void (*func)(ACPI_OBJECT *comp, void *arg), void *arg);
ACPI_STATUS	acpi_FindIndexedResource(ACPI_BUFFER *buf, int index,
		    ACPI_RESOURCE **resp);
ACPI_STATUS	acpi_AppendBufferResource(ACPI_BUFFER *buf,
		    ACPI_RESOURCE *res);
ACPI_STATUS	acpi_OverrideInterruptLevel(UINT32 InterruptNumber);
ACPI_STATUS	acpi_SetIntrModel(int model);
ACPI_STATUS	acpi_SetSleepState(struct acpi_softc *sc, int state);
int		acpi_wake_init(device_t dev, int type);
int		acpi_wake_set_enable(device_t dev, int enable);
int		acpi_wake_sleep_prep(device_t dev, int sstate);
int		acpi_wake_run_prep(device_t dev);
ACPI_STATUS	acpi_Startup(void);
ACPI_STATUS	acpi_Enable(struct acpi_softc *sc);
ACPI_STATUS	acpi_Disable(struct acpi_softc *sc);
void		acpi_UserNotify(const char *subsystem, ACPI_HANDLE h,
		    uint8_t notify);
struct resource *acpi_bus_alloc_gas(device_t dev, int *rid,
		    ACPI_GENERIC_ADDRESS *gas);

struct acpi_parse_resource_set {
    void	(*set_init)(device_t dev, void *arg, void **context);
    void	(*set_done)(device_t dev, void *context);
    void	(*set_ioport)(device_t dev, void *context, uint32_t base,
		    uint32_t length);
    void	(*set_iorange)(device_t dev, void *context, uint32_t low,
		    uint32_t high, uint32_t length, uint32_t align);
    void	(*set_memory)(device_t dev, void *context, uint32_t base,
		    uint32_t length);
    void	(*set_memoryrange)(device_t dev, void *context, uint32_t low,
		    uint32_t high, uint32_t length, uint32_t align);
    void	(*set_irq)(device_t dev, void *context, u_int32_t *irq,
		    int count, int trig, int pol);
    void	(*set_drq)(device_t dev, void *context, u_int32_t *drq,
		    int count);
    void	(*set_start_dependant)(device_t dev, void *context,
		    int preference);
    void	(*set_end_dependant)(device_t dev, void *context);
};

extern struct	acpi_parse_resource_set acpi_res_parse_set;
ACPI_STATUS	acpi_parse_resources(device_t dev, ACPI_HANDLE handle,
		    struct acpi_parse_resource_set *set, void *arg);
extern struct	rman acpi_rman_io, acpi_rman_mem;
struct resource_list_entry *acpi_sysres_find(int type, u_long addr);

/* ACPI event handling */
UINT32		acpi_event_power_button_sleep(void *context);
UINT32		acpi_event_power_button_wake(void *context);
UINT32		acpi_event_sleep_button_sleep(void *context);
UINT32		acpi_event_sleep_button_wake(void *context);

#define ACPI_EVENT_PRI_FIRST      0
#define ACPI_EVENT_PRI_DEFAULT    10000
#define ACPI_EVENT_PRI_LAST       20000

typedef void (*acpi_event_handler_t)(void *, int);

EVENTHANDLER_DECLARE(acpi_sleep_event, acpi_event_handler_t);
EVENTHANDLER_DECLARE(acpi_wakeup_event, acpi_event_handler_t);

/* Device power control. */
ACPI_STATUS	acpi_pwr_switch_consumer(ACPI_HANDLE consumer, int state);

/* Misc. */
static __inline struct acpi_softc *
acpi_device_get_parent_softc(device_t child)
{
    device_t	parent;

    parent = device_get_parent(child);
    if (parent == NULL)
	return (NULL);
    return (device_get_softc(parent));
}

static __inline int
acpi_get_verbose(struct acpi_softc *sc)
{
    if (sc)
	return (sc->acpi_verbose);
    return (0);
}

char		*acpi_name(ACPI_HANDLE handle);
int		acpi_avoid(ACPI_HANDLE handle);
int		acpi_disabled(char *subsys);
int		acpi_machdep_init(device_t dev);
void		acpi_install_wakeup_handler(struct acpi_softc *sc);
int		acpi_sleep_machdep(struct acpi_softc *sc, int state);

/* Battery Abstraction. */
struct acpi_battinfo;
struct acpi_battdesc;

int		acpi_battery_register(int, int);
int		acpi_battery_get_battinfo(int, struct acpi_battinfo *);
int		acpi_battery_get_units(void);
int		acpi_battery_get_info_expire(void);
int		acpi_battery_get_battdesc(int, struct acpi_battdesc *);

int		acpi_cmbat_get_battinfo(int, struct acpi_battinfo *);

/* Embedded controller. */
void		acpi_ec_ecdt_probe(device_t);

/* AC adapter interface. */
int		acpi_acad_get_acline(int *);

/* Package manipulation convenience functions. */
#define ACPI_PKG_VALID(pkg, size)				\
    ((pkg) != NULL && (pkg)->Type == ACPI_TYPE_PACKAGE &&	\
     (pkg)->Package.Count >= (size))
int		acpi_PkgInt(ACPI_OBJECT *res, int idx, ACPI_INTEGER *dst);
int		acpi_PkgInt32(ACPI_OBJECT *res, int idx, uint32_t *dst);
int		acpi_PkgStr(ACPI_OBJECT *res, int idx, void *dst, size_t size);
int		acpi_PkgGas(device_t dev, ACPI_OBJECT *res, int idx, int *rid,
			    struct resource **dst);
ACPI_HANDLE	acpi_GetReference(ACPI_HANDLE scope, ACPI_OBJECT *obj);

#if __FreeBSD_version >= 500000
#ifndef ACPI_MAX_THREADS
#define ACPI_MAX_THREADS	3
#endif
#if ACPI_MAX_THREADS > 0
#define ACPI_USE_THREADS
#endif
#endif

#ifdef ACPI_USE_THREADS
/* ACPI task kernel thread initialization. */
int		acpi_task_thread_init(void);
#endif
