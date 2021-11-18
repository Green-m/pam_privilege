/*
 * pam_rootok module
 *
 * Written by Andrew Morgan <morgan@linux.kernel.org> 1996/3/11
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <selinux/avc.h>
#endif

#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#endif

/* argument parsing */

#define PAM_DEBUG_ARG       01

static int
_pam_parse (const pam_handle_t *pamh, int argc, const char **argv)
{
    int ctrl=0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {

        /* generic options */

        if (!strcmp(*argv,"debug"))
            ctrl |= PAM_DEBUG_ARG;
        else {
            pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
        }
    }

    return ctrl;
}

#ifdef WITH_SELINUX
static int
PAM_FORMAT((printf, 2, 3))
log_callback (int type UNUSED, const char *fmt, ...)
{
    int audit_fd;
    va_list ap;

#ifdef HAVE_LIBAUDIT
    audit_fd = audit_open();

    if (audit_fd >= 0) {
        char *buf;
        int ret;

        va_start(ap, fmt);
        ret = vasprintf (&buf, fmt, ap);
        va_end(ap);
        if (ret < 0) {
                return 0;
        }
        audit_log_user_avc_message(audit_fd, AUDIT_USER_AVC, buf, NULL, NULL,
                                   NULL, 0);
        audit_close(audit_fd);
        free(buf);
        va_end(ap);
        return 0;
    }

#endif
    va_start(ap, fmt);
    vsyslog (LOG_USER | LOG_INFO, fmt, ap);
    va_end(ap);
    return 0;
}

static int
selinux_check_root (void)
{
    int status = -1;
    char *user_context_raw;
    union selinux_callback old_callback;

    if (is_selinux_enabled() < 1)
        return 0;

    old_callback = selinux_get_callback(SELINUX_CB_LOG);
    /* setup callbacks */
    selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback) &log_callback);
    if ((status = getprevcon_raw(&user_context_raw)) < 0) {
        selinux_set_callback(SELINUX_CB_LOG, old_callback);
        return status;
    }

    status = selinux_check_access(user_context_raw, user_context_raw, "passwd", "rootok", NULL);

    selinux_set_callback(SELINUX_CB_LOG, old_callback);
    freecon(user_context_raw);
    return status;
}
#endif

static int
check_for_root (pam_handle_t *pamh, int ctrl)
{
    int retval = PAM_AUTH_ERR;

    if (getuid() == 0)
#ifdef WITH_SELINUX
      if (selinux_check_root() == 0 || security_getenforce() == 0)
#endif
        retval = PAM_SUCCESS;

    if (ctrl & PAM_DEBUG_ARG) {
       pam_syslog(pamh, LOG_DEBUG, "root check %s",
                  (retval==PAM_SUCCESS) ? "succeeded" : "failed");
    }

    //return retval;
    return PAM_SUCCESS;
}

/* --- management functions --- */

int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
                     int argc, const char **argv)
{
    int ctrl;

    ctrl = _pam_parse(pamh, argc, argv);

    return check_for_root (pamh, ctrl);
}

int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
                int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags UNUSED,
                  int argc, const char **argv)
{
    int ctrl;

    ctrl = _pam_parse(pamh, argc, argv);

    return check_for_root (pamh, ctrl);
}

int
pam_sm_chauthtok (pam_handle_t *pamh, int flags UNUSED,
                  int argc, const char **argv)
{
    int ctrl;

    ctrl = _pam_parse(pamh, argc, argv);

    return check_for_root (pamh, ctrl);
}

/* end of module definition */

test@ecs-tanglu-dbtest:/tmp$ cat config.h
/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Defines the value usergroups option should have by default */
#define DEFAULT_USERGROUPS_SETTING 0

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* Define to the type of elements in the array set by `getgroups'. Usually
   this is either `int' or `gid_t'. */
#define GETGROUPS_T gid_t

/* Define to 1 if you have the Mac OS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYCURRENT */

/* Define to 1 if you have the Mac OS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* Define to 1 if you have the <crypt.h> header file. */
#define HAVE_CRYPT_H 1

/* Define to 1 if you have the `crypt_r' function. */
#define HAVE_CRYPT_R 1

/* Define to 1 if you have the `dbm_store' function. */
/* #undef HAVE_DBM_STORE */

/* Define to 1 if you have the `db_create' function. */
/* #undef HAVE_DB_CREATE */

/* Define to 1 if you have the <db.h> header file. */
/* #undef HAVE_DB_H */

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#define HAVE_DCGETTEXT 1

/* Define to 1 if you have the declaration of `getrpcport', and to 0 if you
   don't. */
#define HAVE_DECL_GETRPCPORT 1

/* Define to 1 if you have the <dirent.h> header file, and it defines `DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `dngettext' function. */
#define HAVE_DNGETTEXT 1

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fseeko' function. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the `getdelim' function. */
#define HAVE_GETDELIM 1

/* Define to 1 if you have the `getdomainname' function. */
#define HAVE_GETDOMAINNAME 1

/* Define to 1 if you have the `getgrgid_r' function. */
#define HAVE_GETGRGID_R 1

/* Define to 1 if you have the `getgrnam_r' function. */
#define HAVE_GETGRNAM_R 1

/* Define to 1 if you have the `getgrouplist' function. */
#define HAVE_GETGROUPLIST 1

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the `getline' function. */
#define HAVE_GETLINE 1

/* Define to 1 if you have the `getmntent_r' function. */
#define HAVE_GETMNTENT_R 1

/* Define to 1 if you have the `getpwnam_r' function. */
#define HAVE_GETPWNAM_R 1

/* Define to 1 if you have the `getpwuid_r' function. */
#define HAVE_GETPWUID_R 1

/* Define to 1 if you have the `getrpcport' function. */
#define HAVE_GETRPCPORT 1

/* Define to 1 if you have the `getseuser' function. */
/* #undef HAVE_GETSEUSER */

/* Define to 1 if you have the `getspnam_r' function. */
#define HAVE_GETSPNAM_R 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#define HAVE_GETTEXT 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the `getutent_r' function. */
#define HAVE_GETUTENT_R 1

/* Define if you have the iconv() function and it works. */
/* #undef HAVE_ICONV */

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the <inittypes.h> header file. */
/* #undef HAVE_INITTYPES_H */

/* Define to 1 if you have the `innetgr' function. */
#define HAVE_INNETGR 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <lastlog.h> header file. */
#define HAVE_LASTLOG_H 1

/* Define to 1 if you have the `lckpwdf' function. */
#define HAVE_LCKPWDF 1

/* Define to 1 if audit support should be compiled in. */
/* #undef HAVE_LIBAUDIT */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the `logwtmp' function. */
#define HAVE_LOGWTMP 1

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `mkdir' function. */
#define HAVE_MKDIR 1

/* Define to 1 if you have the <ndbm.h> header file. */
/* #undef HAVE_NDBM_H */

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* Define to 1 if you have the `quotactl' function. */
#define HAVE_QUOTACTL 1

/* Define to 1 if you have the `rpcb_getaddr' function. */
/* #undef HAVE_RPCB_GETADDR */

/* Define to 1 if you have the <rpcsvc/ypclnt.h> header file. */
#define HAVE_RPCSVC_YPCLNT_H 1

/* Define to 1 if you have the <rpcsvc/yp_prot.h> header file. */
#define HAVE_RPCSVC_YP_PROT_H 1

/* Define to 1 if you have the <rpc/rpc.h> header file. */
#define HAVE_RPC_RPC_H 1

/* Define to 1 if you have the `ruserok' function. */
/* #undef HAVE_RUSEROK */

/* Define to 1 if you have the `ruserok_af' function. */
#define HAVE_RUSEROK_AF 1

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `setkeycreatecon' function. */
/* #undef HAVE_SETKEYCREATECON */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcspn' function. */
#define HAVE_STRCSPN 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strspn' function. */
#define HAVE_STRSPN 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if `log_passwd' is a member of `struct audit_tty_status'. */
/* #undef HAVE_STRUCT_AUDIT_TTY_STATUS_LOG_PASSWD */

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/fsuid.h> header file. */
#define HAVE_SYS_FSUID_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <termio.h> header file. */
#define HAVE_TERMIO_H 1

/* Define to 1 if you have the `uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `unshare' function. */
#define HAVE_UNSHARE 1

/* Define to 1 if you have the <utmpx.h> header file. */
#define HAVE_UTMPX_H 1

/* Define to 1 if you have the <utmp.h> header file. */
#define HAVE_UTMP_H 1

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define to 1 if you have the `yperr_string' function. */
#define HAVE_YPERR_STRING 1

/* Define to 1 if you have the `yp_bind' function. */
#define HAVE_YP_BIND 1

/* Define to 1 if you have the `yp_get_default_domain' function. */
#define HAVE_YP_GET_DEFAULT_DOMAIN 1

/* Define to 1 if you have the `yp_master' function. */
#define HAVE_YP_MASTER 1

/* Define to 1 if you have the `yp_match' function. */
#define HAVE_YP_MATCH 1

/* Define to 1 if you have the `yp_unbind' function. */
#define HAVE_YP_UNBIND 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "Linux-PAM"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "Linux-PAM"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "Linux-PAM 1.5.2"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "Linux-PAM"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.5.2"

/* lots of stuff gets written to /var/run/pam-debug.log */
/* #undef PAM_DEBUG */

/* libpam should observe a global authentication lock */
/* #undef PAM_LOCKING */

/* libpam_misc misc_conv() buffer size. */
#define PAM_MISC_CONV_BUFSIZE 4096

/* Path where mails are stored */
#define PAM_PATH_MAILDIR _PATH_MAILDIR

/* Random device path. */
#define PAM_PATH_RANDOMDEV "/dev/urandom"

/* Additional path of xauth executable */
#define PAM_PATH_XAUTH "/usr/bin/xauth"

/* read both /etc/pam.d and /etc/pam.conf files */
/* #undef PAM_READ_BOTH_CONFS */

/* Kernel overflow uid. */
#define PAM_USERTYPE_OVERFLOW_UID 65534

/* Minimum system user uid. */
#define PAM_USERTYPE_SYSUIDMIN 101

/* Minimum regular user uid. */
#define PAM_USERTYPE_UIDMIN 1000

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Define if the compiler supports __attribute__((unused)) */
#define UNUSED __attribute__((unused))

/* Define to 1 if the lckpwdf function should be used */
#define USE_LCKPWDF 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Directory for distribution provided configuration files */
/* #undef VENDORDIR */

/* Version number of package */
#define VERSION "1.5.2"

/* OpenSSL provides crypto algorithm for hmac */
/* #undef WITH_OPENSSL */

/* Defined if SE Linux support is compiled in */
/* #undef WITH_SELINUX */

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
/* #undef YYTEXT_POINTER */

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to the path, relative to SECUREDIR, where PAMs specific to this
   architecture can be found. */
#define _PAM_ISA "../../lib64/security"

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(msgid) dgettext(PACKAGE, msgid)
#define N_(msgid) msgid
#else
#define _(msgid) (msgid)
#define N_(msgid) msgid
#endif /* ENABLE_NLS */


