#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#include "sig_handlers.h"
#include "log.h"

int n_dirs = 0;
int n_files = 0;
int sigint_received = 0;

void sigint_handler(int signo){
	/* Received SIGINT */
	if(signo == SIGINT){
		sigint_received = 1;
		write_in_log("SIGNAL INT");
	}
}


void sigusr_handler(int signo) {
	/* Received SIGUSR1 */
	if (signo == SIGUSR1) {
		n_dirs++;
		printf("New directory: %d/%d directories/files at this time.\n", n_dirs, n_files);
	}
	/* Received SIGUSR2 */
	else if (signo == SIGUSR2) {
		n_files++;
		printf("New file: %d/%d directories/files at this time.\n", n_dirs, n_files);
	}
}

void sigusr_handler_child(int signo) {
	/* Child received SIGUSR1 */
	if (signo == SIGUSR1)
		kill(getppid(), SIGUSR1);
	/* Child received SIGUSR2 */
	else if (signo == SIGUSR2)
		kill(getppid(), SIGUSR2);
}