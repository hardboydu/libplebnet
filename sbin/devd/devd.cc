/*-
 * Copyright (c) 2002 M. Warner Losh.
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
//	o rewrite the main loop:
//	  - expand variables
//	  - find best match
//	  - execute it.
//	o need to insert the event_proc structures in order of priority.  
//        bigger numbers mean higher priority.
//	o devd.conf and devd man pages need a lot of help:
//	  - devd.conf needs to lose the warning about zone files.
//	  - devd.conf needs more details on the supported statements.
//	  - devd.conf needs an example or two.

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>

#include "devd.h"

#define CF "/etc/devd.conf"

using namespace std;

extern FILE *yyin;
extern int lineno;

int dflag;
int romeo_must_die = 0;

static void event_loop(void);
static void usage(void);

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
	match(const char *var, const char *re);
	virtual ~match();
	virtual bool do_match(config &);
	virtual bool do_action(config &) { return true; }
private:
	string _var;
	string _re;
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
	int get_priority() { return (_prio); }
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
	const string &expand_string(const string &var);
protected:
	void parse_one_file(const char *fn);
	void parse_files_in_dir(const char *dirname);
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
action::do_action(config &)
{
	// this is lame because we don't expand variables.
	// xxx
	::system(_cmd.c_str());
	return (true);
}

match::match(const char *var, const char *re)
	: _var(var), _re(re)
{
	// nothing
}

match::~match()
{
	// nothing
}

bool
match::do_match(config &)
{
	// XXX
	return false;
}

const string var_list::bogus = "_$_$_$_$_B_O_G_U_S_$_$_$_$_";
const string var_list::nothing = "";

const string &
var_list::get_variable(const string &var) const
{
	map<string, string>::const_iterator i;

	i = _vars.find(var);
	if (i == _vars.end())
		return var_list::bogus;
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
	_vars[var] = val;
}

void
config::reset(void)
{
	_dir_list.clear();
	_var_list_table.clear();
	// XXX need to cleanup _{attach,detach,nomatch}_list
}

void
config::parse_one_file(const char *fn)
{
	if (dflag)
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

	if (dflag)
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

void
config::parse(void)
{
	vector<string>::const_iterator i;

	parse_one_file(CF);
	for (i = _dir_list.begin(); i != _dir_list.end(); i++)
		parse_files_in_dir((*i).c_str());
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
}

void
config::pop_var_table()
{
	delete _var_list_table.back();
	_var_list_table.pop_back();
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
			return (var);
	}
	return (var_list::nothing);
}

const string &
config::expand_string(const string &)
{
	return var_list::bogus;
}


static void
process_event(const char *buffer)
{
	char type;
	char cmd[1024];
	char *sp;

	// XXX should involve config
	// XXX and set some variables
	// XXX run the list and so forth

	// Ignore unknown devices for now.
	if (*buffer == '?')
		return;
	type = *buffer++;
	sp = strchr(buffer, ' ');
	if (sp == NULL)
		return;	/* Can't happen? */
	*sp = '\0';
	snprintf(cmd, sizeof(cmd), "/etc/devd-generic %s %s", buffer,
	    type == '+' ? "start" : "stop");
	if (dflag)
		printf("Trying '%s'\n", cmd);
	system(cmd);
}

static void
event_loop(void)
{
	int rv;
	int fd;
	char buffer[DEVCTL_MAXBUF];

	fd = open(PATH_DEVCTL, O_RDONLY);
	if (fd == -1)
		err(1, "Can't open devctl");
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
		err(1, "Can't set close-on-exec flag");
	while (1) {
		if (romeo_must_die)
			break;
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
	eps *e = new match(var, re);
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
	fprintf(stderr, "usage: %s [-d]", getprogname());
	exit(1);
}

/*
 * main
 */
int
main(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			dflag++;
			break;
		default:
			usage();
		}
	}

	cfg.parse();
	if (!dflag)
		daemon(0, 0);
	cfg.drop_pidfile();
	signal(SIGHUP, gensighand);
	signal(SIGINT, gensighand);
	signal(SIGTERM, gensighand);
	event_loop();
	return (0);
}
