#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "suexec.h"

// Some macros for easier handling of the signal list
#define MAX(a,b) (a >= b ? a : b)
#define MIN(a,b) (a < b ? a : b)
#define SIGNAL() signal_list[MIN(signal_counter, SIGNAL_LIST_LENGTH)]

static const int signal_list[SIGNAL_LIST_LENGTH] = {SIGNAL_LIST};
volatile int signal_counter = 0;


volatile pid_t child = 0;

void killchild(int sig);

/*
 * Usage: ./suexec <timeout> <argv...>
 */
int main(int argc, char *argv[]) {

	long int val = 0;
	unsigned int timeout;
	char *endptr;
	char *cmd, *actual_uname, *actual_gname;
	uid_t uid;
	gid_t gid;
	struct passwd *pw;
	struct group *gr;

	struct sigaction act;
	int status;

	/*
	 * If there are a proper number of arguments, set
	 * all of them to variables.  Otherwise, error out.
	 */

	if (argc < 3) {
		fprintf(stderr, "too few arguments\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Intensive parsing of timeout value.
	 * Makes sure that only a valid integer is accepted.
	 */

	errno = 0;
	val = strtol(argv[1], &endptr, 10);

	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
			|| (errno != 0 && val == 0)) {
		fprintf(stderr, "invalid timeout value: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((endptr == argv[1]) || (*endptr != '\0')) {
		fprintf(stderr, "invalid timeout value\n");
		exit(EXIT_FAILURE);
	}

	if ((val > INT_MAX) || (val <= 0)) {
		fprintf(stderr, "invalid timeout value\n");
		exit(EXIT_FAILURE);
	}

	timeout = (unsigned int) val;

	cmd = argv[2];

	/*
	 * Check existence/validity of the UID of the user
	 * running this program.  Error out if invalid.
	 */
	uid = getuid();
	if ((pw = getpwuid(uid)) == NULL) {
		fprintf(stderr, "getpwuid(%d) failed: %s\n", uid,
				pw == NULL ?
						"The given name or uid was not found" :
						strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Check to see if the user running this program
	 * is the user allowed to do so as defined in
	 * suexec.h.  If not the allowed user, error out.
	 */
	if (strcmp(SOURCE_USER, pw->pw_name)) {
		fprintf(stderr, "user mismatch: %s instead of %s\n", pw->pw_name,
				SOURCE_USER);
		exit(EXIT_FAILURE);
	}

	/*
	 * Error out if the target username is invalid.
	 */
	if (strspn(TARGET_USER, "1234567890") != strlen(TARGET_USER)) {
		if ((pw = getpwnam(TARGET_USER)) == NULL) {
			fprintf(stderr, "getpwnam(%s) failed: %s\n", TARGET_USER,
					pw == NULL ?
							"The given name or uid was not found" :
							strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		if ((pw = getpwuid(atoi(TARGET_USER))) == NULL) {
			fprintf(stderr, "getpwuid(%s) failed: %s\n", TARGET_USER,
					pw == NULL ?
							"The given name or uid was not found" :
							strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	uid = pw->pw_uid;
	if ((actual_uname = strdup(pw->pw_name)) == NULL) {
		fprintf(stderr, "strdup(%s) failed: %s\n", pw->pw_name,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Error out if the target group name is invalid.
	 */
	if (strspn(TARGET_GROUP, "1234567890") != strlen(TARGET_GROUP)) {
		if ((gr = getgrnam(TARGET_GROUP)) == NULL) {
			fprintf(stderr, "getgrname(%s) failed: %s\n", TARGET_GROUP,
					gr == NULL ?
							"The given name or gid was not found" :
							strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		if ((gr = getgrgid(atoi(TARGET_GROUP))) == NULL) {
			fprintf(stderr, "getgrgid(%s) failed: %s\n", TARGET_GROUP,
					gr == NULL ?
							"The given name or gid was not found" :
							strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	gid = gr->gr_gid;
	if ((actual_gname = strdup(gr->gr_name)) == NULL) {
		fprintf(stderr, "strdup(%s) failed: %s\n", gr->gr_name,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Initialize the group access list for the target user,
	 * and setgid() to the target group. If unsuccessful, error out.
	 */
	if (setgid(gid) != 0) {
		fprintf(stderr, "setgid(%d) failed: %s\n", gid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (initgroups(actual_uname, gid) != 0) {
		fprintf(stderr, "initgroups(%s, %d) failed: %s\n", actual_uname, gid,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * setuid() to the target user.  Error out on fail.
	 */
	if (setuid(uid) != 0) {
		fprintf(stderr, "setuid(%d) failed: %s\n", uid, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Set the alarm and handler before forking and execv-ing.
	 */
	act.sa_handler = killchild;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART; // Don't interrupt the waitpid call

	if (sigaction(SIGALRM, &act, NULL) != 0) {
		fprintf(stderr, "sigaction(SIGALRM, ..., ...) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	alarm(timeout);

	switch (child = fork()) {
		case -1: // Error
			fprintf(stderr, "fork() failed: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
			break;
		case 0: // Child
			execv(cmd, &argv[2]);
			fprintf(stderr, "execv(%s, ...) failed: %s\n", cmd, strerror(errno));
			exit(EXIT_FAILURE);
			break;
		default: // Father
			// TODO: Examine this loop - it shouldn't be needed
			while (child != waitpid(child, &status, 0)) { fprintf(stderr, "."); };
			if (WIFEXITED(status)) {
				// Child exited on its own - great
				exit(WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				// Child was signaled and killed
				// Mimic exit status of shell
				exit(127 + WTERMSIG(status));
			} else {
				// Erm, what am I doing here?
				fprintf(stderr, "unreachable code reached: %s:%d\n", __FILE__, __LINE__);
				exit(EXIT_FAILURE);
			}
			break;
	}
	fprintf(stderr, "unreachable code reached: %s:%d\n", __FILE__, __LINE__);
	exit(EXIT_FAILURE);
}

void killchild(int sig) {
	struct itimerval alarm;
	if (sig == SIGALRM) {
		if (child > 0) {
			if (kill(child, SIGNAL()) != 0) {
				if (errno == ESRCH) {
					// Okay, child is already gone
					return;
				} else {
					fprintf(stderr, "kill(%d, %d) failed: %s\n", child, SIGNAL(), strerror(errno));
				}
			}
			signal_counter++;
			// Re-engage alarm
			// alarm(TIMEOUT);
			alarm.it_interval.tv_sec = 0;
			alarm.it_interval.tv_usec = 0;
			alarm.it_value.tv_sec = 0;
			alarm.it_value.tv_usec = TIMEOUT;
			setitimer(ITIMER_REAL, &alarm, NULL);
			return;
		} else {
			// No child pid? Hmkay...
			fprintf(stderr, "-");
			return;
		}
	} else {
		// No way, this handler should only be registered for SIGALRM
		fprintf(stderr, "unreachable code reached: %s:%d\n", __FILE__, __LINE__);
		return;
	}
}
