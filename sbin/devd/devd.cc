/*-
 * Copyright (c) 2002-2003 M. Warner Losh.
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

/*
 * DEVD control daemon.
 */

// TODO list:
//	o devd.conf and devd man pages need a lot of help:
//	  - devd.conf needs to lose the warning about zone files.
//	  - devd.conf needs more details on the supported statements.

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <regex.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "devd.h"

#define CF "/etc/devd.conf"
#define SYSCTL "hw.bus.devctl_disable"

using namespace std;

extern FILE *yyin;
extern int lineno;

static const char nomatch = '?';
static const char attach = '+';
static const char detach = '-';

int Dflag;
int dflag;
int nflag;
int romeo_must_die = 0;

static void event_loop(void);
static void usage(void);

template <class T> void
delete_and_clear(vector<T *> &v)
{
	typename vector<T *>::const_iterator i;

	for (i = v.begin(); i != v.end(); i++)
		delete *i;
	v.clear();
}

class config;

class var_list
{
public:
	var_list() {}
	virtual ~var_list() {}
	void set_variable(const string &var, const string &val);
	const string &get_variable(const string &var) const;
	bool is_set(const string &var) const;
	static const string bogus;
	static const string nothing;
private:
	map<string, string> _vars;
};

class eps
{
public:
	eps() {}
	virtual ~eps() {}
	virtual bool do_match(config &) = 0;
	virtual bool do_action(config &) = 0;
};

class match : public eps
{
public:
	match(config &, const char *var, const char *re);
	virtual ~match();
	virtual bool do_match(config &);
	virtual bool do_action(config &) { return true; }
private:
	string _var;
	string _re;
	regex_t _regex;
};

class action : public eps
{
public:
	action(const char *cmd);
	virtual ~action();
	virtual bool do_match(config &) { return true; }
	virtual bool do_action(config &);
private:
	string _cmd;
};

class event_proc
{
public:
	event_proc();
	virtual ~event_proc();
	int get_priority() const { return (_prio); }
	void set_priority(int prio) { _prio = prio; }
	void add(eps *);
	bool matches(config &);
	bool run(config &);
private:
	int _prio;
	vector<eps *> _epsvec;
};

class config
{
public:
	config() : _pidfile("") { push_var_table(); }
	virtual ~config() { reset(); }
	void add_attach(int, event_proc *);
	void add_detach(int, event_proc *);
	void add_directory(const char *);
	void add_nomatch(int, event_proc *);
	void set_pidfile(const char *);
	void reset();
	void parse();
	void drop_pidfile();
	void push_var_table();
	void pop_var_table();
	void set_variable(const char *var, const char *val);
	const string &get_variable(const string &var);
	const string expand_string(const string &var);
	char *set_vars(char *);
	void find_and_execute(char);
protected:
	void sort_vector(vector<event_proc *> &);
	void parse_one_file(const char *fn);
	void parse_files_in_dir(const char *dirname);
	void expand_one(const char *&src, char *&dst, char *eod);
	bool is_id_char(char);
	bool chop_var(char *&buffer, char *&lhs, char *&rhs);
private:
	vector<string> _dir_list;
	string _pidfile;
	vector<var_list *> _var_list_table;
	vector<event_proc *> _attach_list;
	vector<event_proc *> _detach_list;
	vector<event_proc *> _nomatch_list;
};

config cfg;

event_proc::event_proc() : _prio(-1)
{
	// nothing
}

event_proc::~event_proc()
{
	vector<eps *>::const_iterator i;

	for (i = _epsvec.begin(); i != _epsvec.end(); i++)
		delete *i;
	_epsvec.clear();
}

void
event_proc::add(eps *eps)
{
	_epsvec.push_back(eps);
}

bool
event_proc::matches(config &c)
{
	vector<eps *>::const_iterator i;

	for (i = _epsvec.begin(); i != _epsvec.end(); i++)
		if (!(*i)->do_match(c))
			return (false);
	return (true);
}

bool
event_proc::run(config &c)
{
	vector<eps *>::const_iterator i;
		
	for (i = _epsvec.begin(); i != _epsvec.end(); i++)
		if (!(*i)->do_action(c))
			return (false);
	return (true);
}

action::action(const char *cmd)
	: _cmd(cmd) 
{
	// nothing
}

action::~action()
{
	// nothing
}

bool
action::do_action(config &c)
{
	string s = c.expand_string(_cmd);
	if (Dflag)
		fprintf(stderr, "Executing '%s'\n", s.c_str());
	::system(s.c_str());
	return (true);
}

match::match(config &c, const char *var, const char *re)
	: _var(var)
{
	string pattern = re;
	_re = "^";
	_re.append(c.expand_string(string(re)));
	_re.append("$");
	regcomp(&_regex, _re.c_str(), REG_EXTENDED | REG_NOSUB);
}

match::~match()
{
	regfree(&_regex);
}

bool
match::do_match(config &c)
{
	string value = c.get_variable(_var);
	bool retval;

	if (Dflag)
		fprintf(stderr, "Testing %s=%s against %s\n", _var.c_str(),
		    value.c_str(), _re.c_str());

	retval = (regexec(&_regex, value.c_str(), 0, NULL, 0) == 0);
	return retval;
}

const string var_list::bogus = "_$_$_$_$_B_O_G_U_S_$_$_$_$_";
const string var_list::nothing = "";

const string &
var_list::get_variable(const string &var) const
{
	map<string, string>::const_iterator i;

	i = _vars.find(var);
	if (i == _vars.end())
		return (var_list::bogus);
	return (i->second);
}

bool
var_list::is_set(const string &var) const
{
	return (_vars.find(var) != _vars.end());
}

void
var_list::set_variable(const string &var, const string &val)
{
	if (Dflag)
		fprintf(stderr, "%s=%s\n", var.c_str(), val.c_str());
	_vars[var] = val;
}

void
config::reset(void)
{
	_dir_list.clear();
	delete_and_clear(_var_list_table);
	delete_and_clear(_attach_list);
	delete_and_clear(_detach_list);
	delete_and_clear(_nomatch_list);
}

void
config::parse_one_file(const char *fn)
{
	if (Dflag)
		printf("Parsing %s\n", fn);
	yyin = fopen(fn, "r");
	if (yyin == NULL)
		err(1, "Cannot open config file %s", fn);
	if (yyparse() != 0)
		errx(1, "Cannot parse %s at line %d", fn, lineno);
	fclose(yyin);
}

void
config::parse_files_in_dir(const char *dirname)
{
	DIR *dirp;
	struct dirent *dp;
	char path[PATH_MAX];

	if (Dflag)
		printf("Parsing files in %s\n", dirname);
	dirp = opendir(dirname);
	if (dirp == NULL)
		return;
	readdir(dirp);		/* Skip . */
	readdir(dirp);		/* Skip .. */
	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name + dp->d_namlen - 5, ".conf") == 0) {
			snprintf(path, sizeof(path), "%s/%s",
			    dirname, dp->d_name);
			parse_one_file(path);
		}
	}
}

class epv_greater {
public:
	int operator()(event_proc *const&l1, event_proc *const&l2)
	{
		return (l1->get_priority() > l2->get_priority());
	}
};

void
config::sort_vector(vector<event_proc *> &v)
{
	sort(v.begin(), v.end(), epv_greater());
}

void
config::parse(void)
{
	vector<string>::const_iterator i;

	parse_one_file(CF);
	for (i = _dir_list.begin(); i != _dir_list.end(); i++)
		parse_files_in_dir((*i).c_str());
	sort_vector(_attach_list);
	sort_vector(_detach_list);
	sort_vector(_nomatch_list);
}

void
config::drop_pidfile()
{
	FILE *fp;
	
	if (_pidfile == "")
		return;
	fp = fopen(_pidfile.c_str(), "w");
	if (fp == NULL)
		return;
	fprintf(fp, "%d\n", getpid());
	fclose(fp);
}

void
config::add_attach(int prio, event_proc *p)
{
	p->set_priority(prio);
	_attach_list.push_back(p);
}

void
config::add_detach(int prio, event_proc *p)
{
	p->set_priority(prio);
	_detach_list.push_back(p);
}

void
config::add_directory(const char *dir)
{
	_dir_list.push_back(string(dir));
}

void
config::add_nomatch(int prio, event_proc *p)
{
	p->set_priority(prio);
	_nomatch_list.push_back(p);
}

void
config::set_pidfile(const char *fn)
{
	_pidfile = string(fn);
}

void
config::push_var_table()
{
	var_list *vl;
	
	vl = new var_list();
	_var_list_table.push_back(vl);
	if (Dflag)
		fprintf(stderr, "Pushing table\n");
}

void
config::pop_var_table()
{
	delete _var_list_table.back();
	_var_list_table.pop_back();
	if (Dflag)
		fprintf(stderr, "Popping table\n");
}

void
config::set_variable(const char *var, const char *val)
{
	_var_list_table.back()->set_variable(var, val);
}

const string &
config::get_variable(const string &var)
{
	vector<var_list *>::reverse_iterator i;

	for (i = _var_list_table.rbegin(); i != _var_list_table.rend(); i++) {
		if ((*i)->is_set(var))
			return ((*i)->get_variable(var));
	}
	return (var_list::nothing);
}

bool
config::is_id_char(char ch)
{
	return (ch != '\0' && (isalpha(ch) || isdigit(ch) || ch == '_' || 
	    ch == '-'));
}

// XXX
// imp should learn how to make effective use of the string class.
void
config::expand_one(const char *&src, char *&dst, char *)
{
	int count;
	const char *var;
	char buffer[1024];
	string varstr;

	src++;
	// $$ -> $
	if (*src == '$') {
		*dst++ = *src++;
		return;
	}
		
	// $(foo) -> $(foo)
	// Not sure if I want to support this or not, so for now we just pass
	// it through.
	if (*src == '(') {
		*dst++ = '$';
		count = 1;
		while (count > 0) {
			if (*src == ')')
				count--;
			else if (*src == '(')
				count++;
			*dst++ = *src++;
		}
		return;
	}
	
	// ${^A-Za-z] -> $\1
	if (!isalpha(*src)) {
		*dst++ = '$';
		*dst++ = *src++;
		return;
	}

	// $var -> replace with value
	var = src++;
	while (is_id_char(*src))
		src++;
	memcpy(buffer, var, src - var);
	buffer[src - var] = '\0';
	varstr = get_variable(buffer);
	strcpy(dst, varstr.c_str());
	dst += strlen(dst);
}

const string
config::expand_string(const string &s)
{
	const char *src;
	char *dst;
	char buffer[1024];

	src = s.c_str();
	dst = buffer;
	while (*src) {
		if (*src == '$')
			expand_one(src, dst, buffer + sizeof(buffer));
		else
			*dst++ = *src++;
	}
	*dst++ = '\0';

	return (buffer);
}

bool
config::chop_var(char *&buffer, char *&lhs, char *&rhs)
{
	char *walker;
	
	if (*buffer == '\0')
		return (false);
	walker = lhs = buffer;
	while (is_id_char(*walker))
		walker++;
	if (*walker != '=')
		return (false);
	walker++;		// skip =
	if (*walker == '"') {
		walker++;	// skip "
		rhs = walker;
		while (*walker && *walker != '"')
			walker++;
		if (*walker != '"')
			return (false);
		rhs[-2] = '\0';
		*walker++ = '\0';
	} else {
		rhs = walker;
		while (*walker && !isspace(*walker))
			walker++;
		if (*walker != '\0')
			*walker++ = '\0';
		rhs[-1] = '\0';
	}
	while (isspace(*walker))
		walker++;
	buffer = walker;
	return (true);
}


char *
config::set_vars(char *buffer)
{
	char *lhs;
	char *rhs;

	while (1) {
		if (!chop_var(buffer, lhs, rhs))
			break;
		set_variable(lhs, rhs);
	}
	return (buffer);
}

void
config::find_and_execute(char type)
{
	vector<event_proc *> *l;
	vector<event_proc *>::const_iterator i;
	char *s;

	switch (type) {
	default:
		return;
	case nomatch:
		l = &_nomatch_list;
		s = "nomatch";
		break;
	case attach:
		l = &_attach_list;
		s = "attach";
		break;
	case detach:
		l = &_detach_list;
		s = "detach";
		break;
	}
	if (Dflag)
		fprintf(stderr, "Processing %s event\n", s);
	for (i = l->begin(); i != l->end(); i++) {
		if ((*i)->matches(*this)) {
			(*i)->run(*this);
			break;
		}
	}

}


static void
process_event(char *buffer)
{
	char type;
	char *sp;

	sp = buffer + 1;
	if (Dflag)
		fprintf(stderr, "Processing event '%s'\n", buffer);
	type = *buffer++;
	cfg.push_var_table();
	// No match doesn't have a device, and the format is a little
	// different, so handle it separately.
	if (type != nomatch) {
		sp = strchr(sp, ' ');
		if (sp == NULL)
			return;	/* Can't happen? */
		*sp++ = '\0';
		cfg.set_variable("device-name", buffer);
		if (strncmp(sp, "at ", 3) == 0)
			sp += 3;
		sp = cfg.set_vars(sp);
		if (strncmp(sp, "on ", 3) == 0)
			cfg.set_variable("bus", sp + 3);
	} else {
		//?vars at location on bus
		sp = cfg.set_vars(sp);
		if (strncmp(sp, "at ", 3) == 0)
			sp += 3;
		sp = cfg.set_vars(sp);
		if (strncmp(sp, "on ", 3) == 0)
			cfg.set_variable("bus", sp + 3);
	}
	
	cfg.find_and_execute(type);
	cfg.pop_var_table();
}

static void
event_loop(void)
{
	int rv;
	int fd;
	char buffer[DEVCTL_MAXBUF];
	int once = 0;
	timeval tv;
	fd_set fds;

	fd = open(PATH_DEVCTL, O_RDONLY);
	if (fd == -1)
		err(1, "Can't open devctl");
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
		err(1, "Can't set close-on-exec flag");
	while (1) {
		if (romeo_must_die)
			break;
		if (!once && !dflag && !nflag) {
			// Check to see if we have any events pending.
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			FD_ZERO(&fds);
			FD_SET(fd, &fds);
			rv = select(fd + 1, &fds, &fds, &fds, &tv);
			// No events -> we've processed all pending events
			// == 2 is a kernel bug, but we hang if we don't
			// make allowances for a while.
			if (rv == 0 || rv == 2) {
				if (Dflag)
					fprintf(stderr, "Calling daemon\n");
				daemon(0, 0);
				once++;
			}
		}
		rv = read(fd, buffer, sizeof(buffer) - 1);
		if (rv > 0) {
			buffer[rv] = '\0';
			while (buffer[--rv] == '\n')
				buffer[rv] = '\0';
			process_event(buffer);
		} else if (rv < 0) {
			if (errno != EINTR)
				break;
		} else {
			/* EOF */
			break;
		}
	}
	close(fd);
}

/*
 * functions that the parser uses.
 */
void
add_attach(int prio, event_proc *p)
{
	cfg.add_attach(prio, p);
}

void
add_detach(int prio, event_proc *p)
{
	cfg.add_detach(prio, p);
}

void
add_directory(const char *dir)
{
	cfg.add_directory(dir);
	free(const_cast<char *>(dir));
}

void
add_nomatch(int prio, event_proc *p)
{
	cfg.add_nomatch(prio, p);
}

event_proc *
add_to_event_proc(event_proc *ep, eps *eps)
{
	if (ep == NULL)
		ep = new event_proc();
	ep->add(eps);
	return (ep);
}

eps *
new_action(const char *cmd)
{
	eps *e = new action(cmd);
	free(const_cast<char *>(cmd));
	return (e);
}

eps *
new_match(const char *var, const char *re)
{
	eps *e = new match(cfg, var, re);
	free(const_cast<char *>(var));
	free(const_cast<char *>(re));
	return (e);
}

void
set_pidfile(const char *name)
{
	cfg.set_pidfile(name);
	free(const_cast<char *>(name));
}

void
set_variable(const char *var, const char *val)
{
	cfg.set_variable(var, val);
	free(const_cast<char *>(var));
	free(const_cast<char *>(val));
}



static void
gensighand(int)
{
	romeo_must_die++;
	_exit(0);
}

static void
usage()
{
	fprintf(stderr, "usage: %s [-d]\n", getprogname());
	exit(1);
}

static void
check_devd_enabled()
{
	int val = 0;
	size_t len;

	len = sizeof(val);
	if (sysctlbyname(SYSCTL, &val, &len, NULL, NULL) != 0)
		errx(1, "devctl sysctl missing from kernel!");
	if (val) {
		warnx("Setting " SYSCTL " to 0");
		val = 0;
		sysctlbyname(SYSCTL, NULL, NULL, &val, sizeof(val));
	}
}

/*
 * main
 */
int
main(int argc, char **argv)
{
	int ch;

	check_devd_enabled();
	while ((ch = getopt(argc, argv, "Ddn")) != -1) {
		switch (ch) {
		case 'D':
			Dflag++;
			break;
		case 'd':
			dflag++;
			break;
		case 'n':
			nflag++;
			break;
		default:
			usage();
		}
	}

	cfg.parse();
	if (!dflag && nflag)
		daemon(0, 0);
	cfg.drop_pidfile();
	signal(SIGHUP, gensighand);
	signal(SIGINT, gensighand);
	signal(SIGTERM, gensighand);
	event_loop();
	return (0);
}
