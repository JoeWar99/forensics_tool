#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#include "sig_handlers.h"

int n_dirs = 0;
int n_files = 0;

void sigusr_handler(int signo) {
	if (signo == SIGUSR1) {
		n_dirs++;
		printf("New directory: %d/%d directories/files at this time.\n", n_dirs, n_files);
	}
	else if (signo == SIGUSR2) {
		n_files++;
		printf("New file: %d/%d directories/files at this time.\n", n_dirs, n_files);
	}
}

void sigusr_handler_child(int signo) {
	if (signo == SIGUSR1)
		kill(getppid(), SIGUSR1);
	else if (signo == SIGUSR2)
		kill(getppid(), SIGUSR2);
}