/*-
 * Copyright (c) 2004-2005 Nate Lawson (SDG)
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/sbuf.h>

#include "cpufreq_if.h"

/*
 * Common CPU frequency glue code.  Drivers for specific hardware can
 * attach this interface to allow users to get/set the CPU frequency.
 */

/*
 * Number of levels we can handle.  Levels are synthesized from settings
 * so for N settings there may be N^2 levels.
 */
#define CF_MAX_LEVELS	32

struct cpufreq_softc {
	struct cf_level			curr_level;
	int				priority;
	int				all_count;
	struct cf_level_lst		all_levels;
	device_t			dev;
	struct sysctl_ctx_list		sysctl_ctx;
};

struct cf_setting_array {
	struct cf_setting		sets[MAX_SETTINGS];
	int				count;
	TAILQ_ENTRY(cf_setting_array)	link;
};

TAILQ_HEAD(cf_setting_lst, cf_setting_array);

static int	cpufreq_attach(device_t dev);
static int	cpufreq_detach(device_t dev);
static void	cpufreq_evaluate(void *arg);
static int	cf_set_method(device_t dev, const struct cf_level *level,
		    int priority);
static int	cf_get_method(device_t dev, struct cf_level *level);
static int	cf_levels_method(device_t dev, struct cf_level *levels,
		    int *count);
static int	cpufreq_insert_abs(struct cpufreq_softc *sc,
		    struct cf_setting *sets, int count);
static int	cpufreq_expand_set(struct cpufreq_softc *sc,
		    struct cf_setting_array *set_arr);
static struct cf_level *cpufreq_dup_set(struct cpufreq_softc *sc,
		    struct cf_level *dup, struct cf_setting *set);
static int	cpufreq_curr_sysctl(SYSCTL_HANDLER_ARGS);
static int	cpufreq_levels_sysctl(SYSCTL_HANDLER_ARGS);

static device_method_t cpufreq_methods[] = {
	DEVMETHOD(device_probe,		bus_generic_probe),
	DEVMETHOD(device_attach,	cpufreq_attach),
	DEVMETHOD(device_detach,	cpufreq_detach),

        DEVMETHOD(cpufreq_set,		cf_set_method),
        DEVMETHOD(cpufreq_get,		cf_get_method),
        DEVMETHOD(cpufreq_levels,	cf_levels_method),
	{0, 0}
};
static driver_t cpufreq_driver = {
	"cpufreq", cpufreq_methods, sizeof(struct cpufreq_softc)
};
static devclass_t cpufreq_dc;
DRIVER_MODULE(cpufreq, cpu, cpufreq_driver, cpufreq_dc, 0, 0);

static eventhandler_tag cf_ev_tag;

static int
cpufreq_attach(device_t dev)
{
	struct cpufreq_softc *sc;
	device_t parent;
	int numdevs;

	sc = device_get_softc(dev);
	parent = device_get_parent(dev);
	sc->dev = dev;
	sysctl_ctx_init(&sc->sysctl_ctx);
	TAILQ_INIT(&sc->all_levels);
	sc->curr_level.total_set.freq = CPUFREQ_VAL_UNKNOWN;

	/*
	 * Only initialize one set of sysctls for all CPUs.  In the future,
	 * if multiple CPUs can have different settings, we can move these
	 * sysctls to be under every CPU instead of just the first one.
	 */
	numdevs = devclass_get_count(cpufreq_dc);
	if (numdevs > 1)
		return (0);

	SYSCTL_ADD_PROC(&sc->sysctl_ctx,
	    SYSCTL_CHILDREN(device_get_sysctl_tree(parent)),
	    OID_AUTO, "freq", CTLTYPE_INT | CTLFLAG_RW, sc, 0,
	    cpufreq_curr_sysctl, "I", "Current CPU frequency");
	SYSCTL_ADD_PROC(&sc->sysctl_ctx,
	    SYSCTL_CHILDREN(device_get_sysctl_tree(parent)),
	    OID_AUTO, "freq_levels", CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    cpufreq_levels_sysctl, "A", "CPU frequency levels");
	cf_ev_tag = EVENTHANDLER_REGISTER(cpufreq_changed, cpufreq_evaluate,
	    NULL, EVENTHANDLER_PRI_ANY);

	return (0);
}

static int
cpufreq_detach(device_t dev)
{
	struct cpufreq_softc *sc;
	int numdevs;

	sc = device_get_softc(dev);
	sysctl_ctx_free(&sc->sysctl_ctx);

	/* Only clean up these resources when the last device is detaching. */
	numdevs = devclass_get_count(cpufreq_dc);
	if (numdevs == 1)
		EVENTHANDLER_DEREGISTER(cpufreq_changed, cf_ev_tag);

	return (0);
}

static void
cpufreq_evaluate(void *arg)
{
	/* TODO: Re-evaluate when notified of changes to drivers. */
}

static int
cf_set_method(device_t dev, const struct cf_level *level, int priority)
{
	struct cpufreq_softc *sc;
	const struct cf_setting *set;
	int error, i;

	sc = device_get_softc(dev);

	/* If already at this level, just return. */
	if (CPUFREQ_CMP(sc->curr_level.total_set.freq, level->total_set.freq))
		return (0);

	/* First, set the absolute frequency via its driver. */
	set = &level->abs_set;
	if (set->dev) {
		if (!device_is_attached(set->dev)) {
			error = ENXIO;
			goto out;
		}
		error = CPUFREQ_DRV_SET(set->dev, set);
		if (error) {
			goto out;
		}
	}

	/* Next, set any/all relative frequencies via their drivers. */
	for (i = 0; i < level->rel_count; i++) {
		set = &level->rel_set[i];
		if (!device_is_attached(set->dev)) {
			error = ENXIO;
			goto out;
		}
		error = CPUFREQ_DRV_SET(set->dev, set);
		if (error) {
			/* XXX Back out any successful setting? */
			goto out;
		}
	}

	/* Record the current level. */
	sc->curr_level = *level;
	sc->priority = priority;
	error = 0;

out:
	if (error)
		device_printf(set->dev, "set freq failed, err %d\n", error);
	return (error);
}

static int
cf_get_method(device_t dev, struct cf_level *level)
{
	struct cpufreq_softc *sc;
	struct cf_level *levels;
	struct cf_setting *curr_set, set;
	struct pcpu *pc;
	device_t *devs;
	int count, error, i, numdevs;
	uint64_t rate;

	sc = device_get_softc(dev);
	curr_set = &sc->curr_level.total_set;
	levels = NULL;

	/* If we already know the current frequency, we're done. */
	if (curr_set->freq != CPUFREQ_VAL_UNKNOWN)
		goto out;

	/*
	 * We need to figure out the current level.  Loop through every
	 * driver, getting the current setting.  Then, attempt to get a best
	 * match of settings against each level.
	 */
	count = CF_MAX_LEVELS;
	levels = malloc(count * sizeof(*levels), M_TEMP, M_NOWAIT);
	if (levels == NULL)
		return (ENOMEM);
	error = CPUFREQ_LEVELS(sc->dev, levels, &count);
	if (error)
		goto out;
	error = device_get_children(device_get_parent(dev), &devs, &numdevs);
	if (error)
		goto out;
	for (i = 0; i < numdevs && curr_set->freq == CPUFREQ_VAL_UNKNOWN; i++) {
		if (!device_is_attached(devs[i]))
			continue;
		error = CPUFREQ_DRV_GET(devs[i], &set);
		if (error)
			continue;
		for (i = 0; i < count; i++) {
			if (CPUFREQ_CMP(set.freq, levels[i].total_set.freq)) {
				sc->curr_level = levels[i];
				break;
			}
		}
	}
	free(devs, M_TEMP);
	if (curr_set->freq != CPUFREQ_VAL_UNKNOWN)
		goto out;

	/*
	 * We couldn't find an exact match, so attempt to estimate and then
	 * match against a level.
	 */
	pc = cpu_get_pcpu(dev);
	if (pc == NULL) {
		error = ENXIO;
		goto out;
	}
	cpu_est_clockrate(pc->pc_cpuid, &rate);
	rate /= 1000000;
	for (i = 0; i < count; i++) {
		if (CPUFREQ_CMP(rate, levels[i].total_set.freq)) {
			sc->curr_level = levels[i];
			break;
		}
	}

out:
	if (levels)
		free(levels, M_TEMP);
	*level = sc->curr_level;
	return (0);
}

static int
cf_levels_method(device_t dev, struct cf_level *levels, int *count)
{
	struct cf_setting_array *set_arr;
	struct cf_setting_lst rel_sets;
	struct cpufreq_softc *sc;
	struct cf_level *lev;
	struct cf_setting *sets;
	struct pcpu *pc;
	device_t *devs;
	int error, i, numdevs, set_count, type;
	uint64_t rate;

	if (levels == NULL || count == NULL)
		return (EINVAL);

	TAILQ_INIT(&rel_sets);
	sc = device_get_softc(dev);
	error = device_get_children(device_get_parent(dev), &devs, &numdevs);
	if (error)
		return (error);
	sets = malloc(MAX_SETTINGS * sizeof(*sets), M_TEMP, M_NOWAIT);
	if (sets == NULL) {
		free(devs, M_TEMP);
		return (ENOMEM);
	}

	/* Get settings from all cpufreq drivers. */
	for (i = 0; i < numdevs; i++) {
		if (!device_is_attached(devs[i]))
			continue;
		set_count = MAX_SETTINGS;
		error = CPUFREQ_DRV_SETTINGS(devs[i], sets, &set_count, &type);
		if (error || set_count == 0)
			continue;

		switch (type) {
		case CPUFREQ_TYPE_ABSOLUTE:
			error = cpufreq_insert_abs(sc, sets, set_count);
			break;
		case CPUFREQ_TYPE_RELATIVE:
			set_arr = malloc(sizeof(*set_arr), M_TEMP, M_NOWAIT);
			if (set_arr == NULL) {
				error = ENOMEM;
				goto out;
			}
			bcopy(sets, set_arr->sets, set_count * sizeof(*sets));
			set_arr->count = set_count;
			TAILQ_INSERT_TAIL(&rel_sets, set_arr, link);
			break;
		default:
			error = EINVAL;
			break;
		}
		if (error)
			goto out;
	}

	/* If there are no absolute levels, create a fake one at 100%. */
	if (TAILQ_EMPTY(&sc->all_levels)) {
		bzero(&sets[0], sizeof(*sets));
		pc = cpu_get_pcpu(dev);
		if (pc == NULL) {
			error = ENXIO;
			goto out;
		}
		cpu_est_clockrate(pc->pc_cpuid, &rate);
		sets[0].freq = rate / 1000000;
		error = cpufreq_insert_abs(sc, sets, 1);
		if (error)
			goto out;
	}

	/* Create a combined list of absolute + relative levels. */
	TAILQ_FOREACH(set_arr, &rel_sets, link)
		cpufreq_expand_set(sc, set_arr);

	/* If the caller doesn't have enough space, return the actual count. */
	if (sc->all_count > *count) {
		*count = sc->all_count;
		error = E2BIG;
		goto out;
	}

	/* Finally, output the list of levels. */
	i = 0;
	TAILQ_FOREACH(lev, &sc->all_levels, link) {
		levels[i] = *lev;
		i++;
	}
	*count = sc->all_count;
	error = 0;

out:
	/* Clear all levels since we regenerate them each time. */
	while ((lev = TAILQ_FIRST(&sc->all_levels)) != NULL) {
		TAILQ_REMOVE(&sc->all_levels, lev, link);
		free(lev, M_TEMP);
	}
	while ((set_arr = TAILQ_FIRST(&rel_sets)) != NULL) {
		TAILQ_REMOVE(&rel_sets, set_arr, link);
		free(set_arr, M_TEMP);
	}
	sc->all_count = 0;
	free(devs, M_TEMP);
	free(sets, M_TEMP);
	return (error);
}

/*
 * Create levels for an array of absolute settings and insert them in
 * sorted order in the specified list.
 */
static int
cpufreq_insert_abs(struct cpufreq_softc *sc, struct cf_setting *sets,
    int count)
{
	struct cf_level_lst *list;
	struct cf_level *level, *search;
	int i;

	list = &sc->all_levels;
	for (i = 0; i < count; i++) {
		level = malloc(sizeof(*level), M_TEMP, M_NOWAIT | M_ZERO);
		if (level == NULL)
			return (ENOMEM);
		level->abs_set = sets[i];
		level->total_set = sets[i];
		level->total_set.dev = NULL;
		sc->all_count++;

		if (TAILQ_EMPTY(list)) {
			TAILQ_INSERT_HEAD(list, level, link);
			continue;
		}

		TAILQ_FOREACH_REVERSE(search, list, cf_level_lst, link) {
			if (sets[i].freq <= search->total_set.freq) {
				TAILQ_INSERT_AFTER(list, search, level, link);
				break;
			}
		}
	}
	return (0);
}

/*
 * Expand a group of relative settings, creating derived levels from them.
 */
static int
cpufreq_expand_set(struct cpufreq_softc *sc, struct cf_setting_array *set_arr)
{
	struct cf_level *fill, *search;
	struct cf_setting *set;
	int i;

	TAILQ_FOREACH(search, &sc->all_levels, link) {
		/* Skip this level if we've already modified it. */
		for (i = 0; i < search->rel_count; i++) {
			if (search->rel_set[i].dev == set_arr->sets[0].dev)
				break;
		}
		if (i != search->rel_count)
			continue;

		/* Add each setting to the level, duplicating if necessary. */
		for (i = 0; i < set_arr->count; i++) {
			set = &set_arr->sets[i];

			/*
			 * If this setting is less than 100%, split the level
			 * into two and add this setting to the new level.
			 */
			fill = search;
			if (set->freq < 10000)
				fill = cpufreq_dup_set(sc, search, set);

			/*
			 * The new level was a duplicate of an existing level
			 * so we freed it.  Go to the next setting.
			 */
			if (fill == NULL)
				continue;

			/* Add this setting to the existing or new level. */
			KASSERT(fill->rel_count < MAX_SETTINGS,
			    ("cpufreq: too many relative drivers (%d)",
			    MAX_SETTINGS));
			fill->rel_set[fill->rel_count] = *set;
			fill->rel_count++;
		}
	}

	return (0);
}

static struct cf_level *
cpufreq_dup_set(struct cpufreq_softc *sc, struct cf_level *dup,
    struct cf_setting *set)
{
	struct cf_level_lst *list;
	struct cf_level *fill, *itr;
	struct cf_setting *fill_set, *itr_set;
	int i;

	/*
	 * Create a new level, copy it from the old one, and update the
	 * total frequency and power by the percentage specified in the
	 * relative setting.
	 */
	fill = malloc(sizeof(*fill), M_TEMP, M_NOWAIT);
	if (fill == NULL)
		return (NULL);
	*fill = *dup;
	fill_set = &fill->total_set;
	fill_set->freq =
	    ((uint64_t)fill_set->freq * set->freq) / 10000;
	if (fill_set->power != CPUFREQ_VAL_UNKNOWN) {
		fill_set->power = ((uint64_t)fill_set->power * set->freq)
		    / 10000;
	}
	if (set->lat != CPUFREQ_VAL_UNKNOWN) {
		if (fill_set->lat != CPUFREQ_VAL_UNKNOWN)
			fill_set->lat += set->lat;
		else
			fill_set->lat = set->lat;
	}

	/*
	 * If we copied an old level that we already modified (say, at 100%),
	 * we need to remove that setting before adding this one.  Since we
	 * process each setting array in order, we know any settings for this
	 * driver will be found at the end.
	 */
	for (i = fill->rel_count; i != 0; i--) {
		if (fill->rel_set[i - 1].dev != set->dev)
			break;
		fill->rel_count--;
	}

	/*
	 * Insert the new level in sorted order.  If we find a duplicate,
	 * free the new level.  We can do this since any existing level will
	 * be guaranteed to have the same or less settings and thus consume
	 * less power.  For example, a level with one absolute setting of
	 * 800 Mhz uses less power than one composed of an absolute setting
	 * of 1600 Mhz and a relative setting at 50%.
	 */
	list = &sc->all_levels;
	if (TAILQ_EMPTY(list)) {
		TAILQ_INSERT_HEAD(list, fill, link);
	} else {
		TAILQ_FOREACH_REVERSE(itr, list, cf_level_lst, link) {
			itr_set = &itr->total_set;
			if (CPUFREQ_CMP(fill_set->freq, itr_set->freq)) {
				free(fill, M_TEMP);
				fill = NULL;
				break;
			} else if (fill_set->freq < itr_set->freq) {
				TAILQ_INSERT_AFTER(list, itr, fill, link);
				sc->all_count++;
				break;
			}
		}
	}

	return (fill);
}

static int
cpufreq_curr_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct cpufreq_softc *sc;
	struct cf_level *levels;
	int count, error, freq, i;

	sc = oidp->oid_arg1;
	count = CF_MAX_LEVELS;
	levels = malloc(count * sizeof(*levels), M_TEMP, M_NOWAIT);
	if (levels == NULL)
		return (ENOMEM);

	error = CPUFREQ_GET(sc->dev, &levels[0]);
	if (error)
		goto out;
	freq = levels[0].total_set.freq;
	error = sysctl_handle_int(oidp, &freq, 0, req);
	if (error != 0 || req->newptr == NULL)
		goto out;

	error = CPUFREQ_LEVELS(sc->dev, levels, &count);
	if (error)
		goto out;
	for (i = 0; i < count; i++) {
		if (CPUFREQ_CMP(levels[i].total_set.freq, freq)) {
			error = CPUFREQ_SET(sc->dev, &levels[i],
			    CPUFREQ_PRIO_USER);
			break;
		}
	}
	if (i == count)
		error = EINVAL;

out:
	if (levels)
		free(levels, M_TEMP);
	return (error);
}

static int
cpufreq_levels_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct cpufreq_softc *sc;
	struct cf_level *levels;
	struct cf_setting *set;
	struct sbuf sb;
	int count, error, i;

	sc = oidp->oid_arg1;
	sbuf_new(&sb, NULL, 128, SBUF_AUTOEXTEND);

	/* Get settings from the device and generate the output string. */
	count = CF_MAX_LEVELS;
	levels = malloc(count * sizeof(*levels), M_TEMP, M_NOWAIT);
	if (levels == NULL)
		return (ENOMEM);
	error = CPUFREQ_LEVELS(sc->dev, levels, &count);
	if (error)
		goto out;
	if (count) {
		for (i = 0; i < count; i++) {
			set = &levels[i].total_set;
			sbuf_printf(&sb, "%d/%d ", set->freq, set->power);
		}
	} else
		sbuf_cpy(&sb, "0");
	sbuf_trim(&sb);
	sbuf_finish(&sb);
	error = sysctl_handle_string(oidp, sbuf_data(&sb), sbuf_len(&sb), req);

out:
	free(levels, M_TEMP);
	sbuf_delete(&sb);
	return (error);
}

int
cpufreq_register(device_t dev)
{
	device_t cf_dev, cpu_dev;

	/*
	 * Only add one cpufreq device (on cpu0) for all control.  Once
	 * independent multi-cpu control appears, we can assign one cpufreq
	 * device per cpu.
	 */
	cf_dev = devclass_get_device(cpufreq_dc, 0);
	if (cf_dev)
		return (0);

	/* Add the child device and sysctls. */
	cpu_dev = devclass_get_device(devclass_find("cpu"), 0);
	cf_dev = BUS_ADD_CHILD(cpu_dev, 0, "cpufreq", 0);
	if (cf_dev == NULL)
		return (ENOMEM);
	device_quiet(cf_dev);

	return (device_probe_and_attach(cf_dev));
}

int
cpufreq_unregister(device_t dev)
{
	device_t cf_dev, *devs;
	int cfcount, count, devcount, error, i, type;
	struct cf_setting set;

	/*
	 * If this is the last cpufreq child device, remove the control
	 * device as well.  We identify cpufreq children by calling a method
	 * they support.
	 */
	error = device_get_children(device_get_parent(dev), &devs, &devcount);
	if (error)
		return (error);
	cf_dev = devclass_get_device(cpufreq_dc, 0);
	KASSERT(cf_dev != NULL, ("unregister with no cpufreq dev"));
	cfcount = 0;
	for (i = 0; i < devcount; i++) {
		if (!device_is_attached(devs[i]))
			continue;
		count = 1;
		if (CPUFREQ_DRV_SETTINGS(devs[i], &set, &count, &type) == 0)
			cfcount++;
	}
	if (cfcount <= 1) {
		device_delete_child(device_get_parent(cf_dev), cf_dev);
	}
	free(devs, M_TEMP);

	return (0);
}
