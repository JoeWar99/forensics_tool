#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#include "sig_handlers.h"
#include "forensic.h"
#include "parse.h"
#include "log.h"
 
char *cmd2strg(char *firstWord, int argc, char *argv[])
{
	size_t totalSize = 0;
	for (int i = 0; i < argc; i++)
		totalSize += strlen(argv[i]);

	char *ret = NULL;
	size_t mallocSize = totalSize + argc;
	if (firstWord != NULL)
		mallocSize += strlen(firstWord) + 1;

	if ((ret = malloc(mallocSize)) == NULL)
	{
		perror("cmd2str");
		return NULL;
	}
	memset(ret, '\0', 1);
	if (firstWord != NULL)
	{
		strcat(ret, firstWord);
		strcat(ret, " ");
	}

	strcat(ret, argv[0]);
	for (int i = 1; i < argc; i++)
	{
		strcat(ret, " ");
		strcat(ret, argv[i]);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	if (argc < 2 || argc > 8)
	{
		printf("Usage: ./forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>\n");
		exit(1);
	}

	int ret;

	/* 0 | r | h | md5 | sha1 | sha256 | o | v */
	char flags = 0;

	/* File or directory specified */
	char *start_point = argv[argc - 1];

	struct stat stat_buf;

	/* Test start_point exsitence */
	if (lstat(start_point, &stat_buf) == -1)
	{
		perror(start_point);
		exit(1);
	}

	/* Output file (NULL if -o not set) */
	char *out_file = NULL;

	/* Log file name (NULL if -v not set) */
	char *log_file = NULL;

	/* argc - 2: without ./forensic + <file|dir> */
	flags = parse_cmd(argc - 2, &argv[1], &out_file);

	if (flags & FLAGS_ERROR)
	{
		printf("Usage: ./forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>\n");
		exit(2);
	}

	struct sigaction action2;
	action2.sa_handler = sigint_handler;
	sigemptyset(&action2.sa_mask);
	action2.sa_flags = SA_RESTART;
	sigaction(SIGINT, &action2, NULL);

	/* Install signal handlers if -o flag active */
	if (flags & FLAGS_O)
	{
		struct sigaction action;
		action.sa_handler = sigusr_handler;
		sigemptyset(&action.sa_mask);
		action.sa_flags = 0;
		sigaction(SIGUSR1, &action, NULL);
		sigaction(SIGUSR2, &action, NULL);
	}

	/* Get log file name from environment variable */
	if (flags & FLAGS_V)
		if ((ret = initialize_log()) != 0)
		{
			fprintf(stderr, "Error initializing log: %d\n", ret);
			return -1;
		}

	if (log_file != NULL)
		printf("%s\n", log_file);

	char *cmd = cmd2strg("COMMAND", argc, argv);
	write_in_log(cmd);
	free(cmd);

	/* If its a file display its info */
	if (S_ISREG(stat_buf.st_mode))
	{
		if (flags & FLAGS_O){
			write_in_log("SIGNAL USR2");
			raise(SIGUSR2);
		}
		file_forensic(flags, start_point, stat_buf, out_file);
	}

	/* If its a directory go inside it */
	else if (S_ISDIR(stat_buf.st_mode))
	{
		/* Remove slash at the end */
		if (start_point[strlen(start_point) - 1] == '/' && strlen(start_point) != 1)
			memset(start_point + strlen(start_point) - 1, '\0', 1);

		if (flags & FLAGS_O){
			write_in_log("SIGNAL USR1");
			raise(SIGUSR1);
		}

		dir_forensic(flags, start_point, out_file);
	}
	/* Close log file */
	if (flags & FLAGS_V)
		if ((ret = close_log()) != 0)
		{
			fprintf(stderr, "Error closing log: %d\n", ret);
			return -1;
		}

	if (out_file != NULL)
	{
		free(out_file);
	}

	return 0;
}