/*
 * Linux-PAM session chroot()er
 * account, session, authentication
 *
 * $Id: pam_chroot.h,v 1.1 2007/10/02 05:55:19 schmolli Exp $
 */

#ifndef _PAM_CHROOT_H
#define _PAM_CHROOT_H

#include <regex.h>
#include <sys/types.h>

#define  PAM_SM_AUTH
#define  PAM_SM_ACCOUNT
#define  PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

/* default location of the pam_chroot config file */
#define CONFIG  "/etc/security/chroot.conf"

/* max length (bytes) of line in config file */
#define LINELEN         1024
/* max length (bytes) of a GID string representation */
#define MAX_GID_LEN     6
/* maximum number of groups we handle */
#define MAX_GROUPS      64

/* defines for flags */
#define _PAM_OPTS_NOOPTS        0x0000
#define _PAM_OPTS_DEBUG         0x0001
#define _PAM_OPTS_SILENT        0x0002
#define _PAM_OPTS_NOTFOUNDFAILS 0x0004
#define _PAM_OPTS_NO_CHROOT     0x0008
#define _PAM_OPTS_USE_REGEX     0x0010
#define _PAM_OPTS_USE_EXT_REGEX 0x0030 /* includes _PAM_OPTS_USE_REGEX */
#define _PAM_OPTS_USE_GROUPS    0x0040
#define _PAM_OPTS_SECCHECKS     0x0080

/* defines for (internal) return values */
#define _PAM_CHROOT_INTERNALERR         -2
#define _PAM_CHROOT_SYSERR              -1
#define _PAM_CHROOT_OK                  0
#define _PAM_CHROOT_USERNOTFOUND        1
#define _PAM_CHROOT_INCOMPLETE          2


typedef struct _pam_opts {
  int16_t flags;        /* combined option flags */
  char* chroot_dir;     /* where to chroot to */
  char* conf;           /* name of pam_chroot config file */
  char* module;         /* module currently being processed */
} _opts;

/* initialize opts to a standard known state */
int _pam_opts_init(_opts* opts);

/* configure opts per the passed flags and cmd line args */
int _pam_opts_config(_opts* opts, int flags, int argc, const char** argv);

/* free the allocated memory of a struct _pam_opts */
int _pam_opts_free(_opts* opts);

/* if the system doesn't have getgrouplist(), then I have to do it myself */
#ifndef HAVE_GETGROUPLIST
#define _PAM_GETUGROUPS _pam_getugroups
/* *user is the user to collect info on
 * gid is a gid to include in the grplist
 * *grps is the array of gid_t to return the grplist in (if not NULL)
 * *ngrps is the max number of gid_t to return in grplist AND where to 
 *   store the actual number of gid_t returned
 *
 * return -1 if *ngrps is too small
 */
int _pam_getugroups(const char *user, gid_t gid, gid_t *grps, int *ngrps);
#else
#define _PAM_GETUGROUPS getgrouplist
#endif

/* generate a list of group names from a list of gids */
char** _pam_get_groups(const char* user, _opts* opts);

/* helper function to free group list */
void _pam_free_groups(char **groups);

/* verify that the arguement path is root owned and not writable by
 * group or other
 * return 0 if ok, 1 if not, -1 on system error */
int _pam_check_path_perms(char *path, _opts* opts);

/* expand chroot path */
/* path - string to expand
 * user - username, for %u expansion
 * grp - group, for %g expansion
 * match - name entry that was matched
 * matchptr - array of regmatch_t containing matched substrings (assume
 *   at least 10 items in array)
 */
char* _pam_expand_chroot_dir(const char* path, const char* user,
                             const char* grp, const char* match,
                             regmatch_t* matchptr, _opts* opts);

/* parse the chroot.conf to find chroot_dir */
int _pam_get_chrootdir(const char* user, _opts* opts);

/* This is the workhorse function.  All of the pam_sm_* functions should
 *  initialize a _pam_opts struct with the command line args and flags,
 *  then pass it to this function */
int _pam_do_chroot(pam_handle_t *pamh, _opts *opts);

#endif
