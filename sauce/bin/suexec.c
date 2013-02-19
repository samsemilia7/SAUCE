/*
 General purpose port of the Apache HTTPD suexec program

 Heavily inspired by httpd-2.4.3/support/suexec.c

 Differences:
 - Stripped out all Apache-related code like logging
 - No environ cleaning
 - No cmd path sanity checks
 - No cwd path sanity checks and conversions
 - No permission checks on cmd and cwd
 - No umask sanity checks
 - No hashbang emulation support

 To use the suexec functionality within SAUCE, you need to
 perform some manual tasks which are described below.
 This isn't to punish you for something, but to make sure
 you are able to understand the security implications
 of using this binary with setuid.

 First, compile the suexec wrapper:
 $ gcc -Wall -o suexec suexec.c

 Now let root own the binary:
 # chown root suexec
 And set the setuid bit:
 # chmod u+s suexec

 See if it works by running it:
 $ ./suexec `id -u` `id -g` `which id`
 should give you the same output as a plain
 $ id

 */

/*
 #
 ## SAUCE - System for AUtomated Code Evaluation
 ## Copyright (C) 2013 Moritz Schlarb
 ##
 ## This program is free software: you can redistribute it and/or modify
 ## it under the terms of the GNU Affero General Public License as published by
 ## the Free Software Foundation, either version 3 of the License, or
 ## any later version.
 ##
 ## This program is distributed in the hope that it will be useful,
 ## but WITHOUT ANY WARRANTY; without even the implied warranty of
 ## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ## GNU Affero General Public License for more details.
 ##
 ## You should have received a copy of the GNU Affero General Public License
 ## along with this program.  If not, see <http://www.gnu.org/licenses/>.
 #
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <pwd.h>
#include <grp.h>

#include "suexec.h"


int main(int argc, char *argv[]) {

	int exitcode = EXIT_FAILURE;

	char *target_uname, *target_gname;
	char *actual_uname, *actual_gname;

	char *cmd;

	struct passwd *pw;
	struct group *gr;

	uid_t uid;
	gid_t gid;

/*
	struct stat fstat;
	if (stat(argv[0], &fstat) != 0) {
		fprintf(stderr, "stat(%s) failed: %s\n", argv[0], strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (!(fstat.st_mode & S_ISUID)) {
		fprintf(stderr, "%s is not setuid\n", argv[0]);
		exit(EXIT_FAILURE);
	}
*/

	if (argc < 4) {
		fprintf(stderr, "too few arguments\n");
		exit(EXIT_FAILURE);
	}

	target_uname = argv[1];
	target_gname = argv[2];
	cmd = argv[3];

	if (strspn(target_uname, "1234567890") != strlen(target_uname)) {
		// Textual uid
		if ((pw = getpwnam(target_uname)) == NULL) {
			fprintf(stderr, "getpwnam(%s) failed: %s\n", target_uname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		// Numerical uid
		if ((pw = getpwuid(atoi(target_uname))) == NULL) {
			fprintf(stderr, "getpwuid(%s) failed: %s\n", target_uname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	uid = pw->pw_uid;
	actual_uname = strdup(pw->pw_name);

	if (strspn(target_gname, "1234567890") != strlen(target_gname)) {
		// Textual gid
		if ((gr = getgrnam(target_gname)) == NULL) {
			fprintf(stderr, "getgrname(%s) failed: %s\n", target_gname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		// Numerical gid
		if ((gr = getgrgid(atoi(target_gname))) == NULL) {
			fprintf(stderr, "getgrid(%s) failed: %s\n", target_gname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	gid = gr->gr_gid;
	actual_gname = strdup(gr->gr_name);

	fprintf(stderr, "uid: (%s/%s) gid: (%s/%s)\n",
			target_uname, actual_uname,
			target_gname, actual_gname);

	if ((uid == 0) || (uid < UID_MIN)) {
		fprintf(stderr, "forbidden uid: %d\n", uid);
		exit(EXIT_FAILURE);
	}
	if ((gid == 0) || (gid < GID_MIN)) {
		fprintf(stderr, "forbidden gid: %d\n", gid);
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "uid: %5d, euid: %5d, gid: %5d, egid: %5d\n",
			getuid(), geteuid(), getgid(), getegid());

	if ((setgid(gid)) != 0) {
		fprintf(stderr, "setgid(%d) failed: %s\n", gid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	// Without initgroups, we would still have the group permissions of the old user
	if (initgroups(actual_uname, gid) != 0) {
		fprintf(stderr, "initgroups(%s, %d) failed: %s\n", actual_uname, gid, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((setuid(uid)) != 0) {
		fprintf(stderr, "setuid(%d) failed: %s\n", uid, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "uid: %5d, euid: %5d, gid: %5d, egid: %5d\n",
			getuid(), geteuid(), getgid(), getegid());

	exitcode = execv(cmd, &argv[3]);
	fprintf(stderr, "execv(%s) failed: %s\n", cmd, strerror(errno));

	exit(exitcode);
}
