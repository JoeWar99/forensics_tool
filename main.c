#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <wait.h>
#include "forensic.h"
#include "parse.h"
#include "log.h"
#include "sig_handlers.h"

int dir_forensic(char flag, char *start_point, char *outfile) {

	DIR * dirp;
	struct dirent *direntp;
	struct stat stat_buf;
	char name[260];

	/* Open directory */
	if ((dirp = opendir(start_point)) == NULL){
		perror("start_point");
		exit(1);
	}

	/* Read the specified directory */
	while((direntp = readdir(dirp)) != NULL) {

		/* Skip . and .. directories */
		if (!strcmp(direntp->d_name, "..") || !strcmp(direntp->d_name, ".")) continue;

		/* Assemble new file/directory name */
		sprintf(name,"%s/%s",start_point,direntp->d_name);

		/* Retrieve information */
		if (lstat(name, &stat_buf)==-1)
		{
			perror("lstat ERROR");
			exit(3);
		}

		/* If its a file print its information */
		if (S_ISREG(stat_buf.st_mode)) {
			if (flag & FLAGS_O) raise(SIGUSR2);
			file_forensic(flag, name, stat_buf, outfile);
		}

		/* If its a directory and recursive bit is on, read subdirectories */
		else if (S_ISDIR(stat_buf.st_mode) && flag & FLAGS_R) {

			/* Create a child */
			pid_t pid = fork();

			/* Fork error */
			if (pid == -1) {
				perror("fork");
				exit(1);
			}
			if (pid == 0) {

				/* Override parent signal handlers */
				if (flag & FLAGS_O) {
					struct sigaction action;
					action.sa_handler = sigusr_handler_child;
					sigemptyset(&action.sa_mask);
					action.sa_flags = 0;
					sigaction(SIGUSR1, &action, NULL);
					sigaction(SIGUSR2, &action, NULL);
				}

				/* Generate SIGUSR1 signal */
				if (flag & FLAGS_O) raise(SIGUSR1);

				/* Look recursively through the folder */
				dir_forensic(flag, name, outfile);

				/* Kill child */
				exit(0);
			}
			else{
				wait(NULL);
			}
		}
	}
	/* Close opened directory */
 	closedir(dirp);

	return 0;
}

char * cmd2strg(char* firstWord, int argc, char * argv[]) {
    size_t totalSize = 0;
    for (int i = 0; i < argc; i++)
       totalSize += strlen(argv[i]);
    
    char * ret = NULL;
	size_t mallocSize = totalSize + argc;
	if(firstWord != NULL)
		mallocSize += strlen(firstWord) + 1;

    if ((ret = malloc(mallocSize)) == NULL) {
        perror("cmd2str");
		return NULL;
    }
	if(firstWord != NULL){
		strcat(ret, firstWord);
		strcat(ret, " ");
	}

	strcat(ret, argv[0]);
    for (int i = 1; i < argc; i++) {
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

	/* Install signal handlers if -o flag active */
	if (flags & FLAGS_O) {
		struct sigaction action;
		action.sa_handler = sigusr_handler;
		sigemptyset(&action.sa_mask);
		action.sa_flags = 0;
		sigaction(SIGUSR1, &action, NULL);
		sigaction(SIGUSR2, &action, NULL);
	}

	// TODO: LOGFILE
	/* Get log file name from environment variable */
	if (flags & FLAGS_V)
		if((ret = initialize_log()) != 0){
			fprintf(stderr, "Error initializing log: %d\n", ret);
			return -1;
		}

	if (log_file != NULL)
		printf("%s\n", log_file);

	
	write_in_log(cmd2strg("COMMAND", argc, argv));

	/* If its a file display its info */
	if (S_ISREG(stat_buf.st_mode)) {
		if (flags & FLAGS_O) raise(SIGUSR2);
		file_forensic(flags, start_point, stat_buf, out_file);
	}

	/* If its a directory go inside it */
	else if (S_ISDIR(stat_buf.st_mode)) {
		/* Remove slash at the end */
		if (start_point[strlen(start_point)-1] == '/')
			memset(start_point+strlen(start_point)-1, '\0', 1);
			
		if (flags & FLAGS_O) raise(SIGUSR1);

		dir_forensic(flags, start_point, out_file);
		}


	if (flags & FLAGS_V)
		if((ret = close_log()) != 0){
			fprintf(stderr, "Error closing log: %d\n", ret);
			return -1;
		}


	return 0;
}