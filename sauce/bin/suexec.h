#ifndef SUEXEC_H
#define SUEXEC_H

// All user and group definitions may be per name or per numerical id

// Set this to the user that is allowed to run suexec
// (e.g. the web application user)
#define SOURCE_USER

// Set this to the user and group which suexec will drop
// privileges to.
// To ensure that the temporary directory created by the web application
// is read- and writable for the target user, you must set permissions and
// ownership accordingly within the web application
#define TARGET_USER
#define TARGET_GROUP

// Set this to the amount of time in microseconds
// to wait between the various signals
#define TIMEOUT 100000

// Set the number of signals in the list below
#define SIGNAL_LIST_LENGTH 3
// Set the signals to send in ascending order (no quotes!)
#define SIGNAL_LIST SIGALRM, SIGTERM, SIGKILL

#endif /* SUEXEC_H */
