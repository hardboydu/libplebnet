/*
 * $FreeBSD$
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/param.h>

#ifndef _PATH_LIBMAP_CONF
#define	_PATH_LIBMAP_CONF	"/etc/libmap.conf"
#endif

TAILQ_HEAD(lm_list, lm);
struct lm {
	char *f;
	char *t;

	TAILQ_ENTRY(lm)	lm_link;
};

TAILQ_HEAD(lmp_list, lmp) lmp_head = TAILQ_HEAD_INITIALIZER(lmp_head);
struct lmp {
	char *p;
	struct lm_list lml;
	TAILQ_ENTRY(lmp) lmp_link;
};

static void		lm_add		(char *, char *, char *);
static void		lm_free		(struct lm_list *);
static char *		lml_find	(struct lm_list *, const char *);
static struct lm_list *	lmp_find	(const char *);
static struct lm_list *	lmp_init	(char *);

void
lm_init (void)
{
	FILE	*fp;
	char	*cp;
	char	*f, *t, *p;
	char	prog[MAXPATHLEN];
	char	line[MAXPATHLEN + 2];

	TAILQ_INIT(&lmp_head);

	if ((fp = fopen(_PATH_LIBMAP_CONF, "r")) == NULL)
		return;

	p = NULL;
	while ((cp = fgets(line, MAXPATHLEN + 1, fp)) != NULL) {
		t = f = NULL;
		/* Skip over leading space */
		while (!isalpha(*cp) &&
		       *cp != '#' && *cp != '\0' && *cp != '[') cp++;
		/* Found a comment or EOL */
		if (*cp == '#' || *cp == '\0')
			continue;
		/* Found a costraint selector */
		if (*cp == '[') {
			cp++;
			/* Skip leading space */
			while (isspace(*cp) &&
			       *cp != '#' && *cp != '\0' && *cp != ']') cp++;
			/* Found comment, EOL or end of selector */
			if  (*cp == '#' || *cp == '\0' || *cp == ']')
				continue;
			p = cp;
			/* Skip to end of word */
			while (!isspace(*cp) &&
			       *cp != '#' && *cp != '\0' && *cp != ']') cp++;
			*cp++ = '\0';
			bzero(prog, MAXPATHLEN);
			strncpy(prog, p, strlen(p));
			p = prog;
			continue;
		}
		f = cp;
		while (!isspace(*cp) && *cp != '#' && *cp != '\0') cp++;
		*cp++ = '\0';
		while (isspace(*cp) && *cp != '#' && *cp != '\0') cp++;
		t = cp;
		while (!isspace(*cp) && *cp != '#' && *cp != '\0') cp++;
		*cp++ = '\0';

		lm_add(p, strdup(f), strdup(t));
		bzero(line, sizeof(line));
	}
	(void)fclose(fp);
	return;
}

static void
lm_free (struct lm_list *lml)
{
	struct lm *lm;

	while (!TAILQ_EMPTY(lml)) {
		lm = TAILQ_FIRST(lml);
		TAILQ_REMOVE(lml, lm, lm_link);
		free(lm->f);
		free(lm->t);
		free(lm);
	}
	return;
}

void
lm_fini (void)
{
	struct lmp *lmp;

	while (!TAILQ_EMPTY(&lmp_head)) {
		lmp = TAILQ_FIRST(&lmp_head);
		TAILQ_REMOVE(&lmp_head, lmp, lmp_link);
		free(lmp->p);
		lm_free(&lmp->lml);
		free(lmp);
	}
	return;
}

static void
lm_add (char *p, char *f, char *t)
{
	struct lm_list *lml;
	struct lm *lm;

	if (p == NULL)
		p = "$DEFAULT$";

#if 0
	printf("%s(\"%s\", \"%s\", \"%s\")\n", __func__, p, f, t);
#endif

	if ((lml = lmp_find(p)) == NULL)
		lml = lmp_init(strdup(p));

	lm = malloc(sizeof(struct lm));
	lm->f = f;
	lm->t = t;
	TAILQ_INSERT_HEAD(lml, lm, lm_link);
}

char *
lm_find (const char *p, const char *f)
{
	struct lm_list *lml;
	char *t;

	if (p != NULL && (lml = lmp_find(p)) != NULL) {
		t = lml_find(lml, f);
		if (t != NULL)
			return (t);
	}
	lml = lmp_find("$DEFAULT$");
	if (lml != NULL)
		return (lml_find(lml, f));
	else
		return (NULL);
}

static char *
lml_find (struct lm_list *lmh, const char *f)
{
	struct lm *lm;

	TAILQ_FOREACH(lm, lmh, lm_link)
		if ((strncmp(f, lm->f, strlen(lm->f)) == 0) &&
		    (strlen(f) == strlen(lm->f)))
			return (lm->t);
	return NULL;
}

static struct lm_list *
lmp_find (const char *n)
{
	struct lmp *lmp;

	TAILQ_FOREACH(lmp, &lmp_head, lmp_link)
		if ((strncmp(n, lmp->p, strlen(lmp->p)) == 0) &&
		    (strlen(n) == strlen(lmp->p)))
			return (&lmp->lml);
	return (NULL);
}

static struct lm_list *
lmp_init (char *n)
{
	struct lmp *lmp;

	lmp = malloc(sizeof(struct lmp));
	lmp->p = n;
	TAILQ_INIT(&lmp->lml);
	TAILQ_INSERT_HEAD(&lmp_head, lmp, lmp_link);

	return (&lmp->lml);
}
