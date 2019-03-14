#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>

#include "forensic.h"
#include "parse.h"


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
		if (S_ISREG(stat_buf.st_mode)) file_forensic(flag, name, stat_buf, outfile);

		/* If its a directory and recursive bit is on, read subdirectories */
		else if (S_ISDIR(stat_buf.st_mode) && flag & FLAGS_R) {

			/* Create a child */
			pid_t pid = fork();

			/* Fork error */
			if (pid == -1) {
				perror("fork");
				exit(1);
			}
			/* Look recursively through the folder */
			if (pid == 0) {
				dir_forensic(flag, name, outfile);
				exit(0);
			}
		}
	}
	/* Close opened directory */
 	closedir(dirp);

	return 0;
}

int main(int argc, char *argv[])
{

	if (argc < 2 || argc > 8)
	{
		printf("Usage: ./forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>\n");
		exit(1);
	}

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

	// TODO: LOGFILE
	/* Get log file name from environment variable */
	if (flags & FLAGS_V)
		log_file = getenv("LOGFILENAME");

	//printf("0x%x\n", flags);
	if (out_file != NULL)
		printf("%s\n", out_file);
	if (log_file != NULL)
		printf("%s\n", log_file);
	//printf("%s\n", start_point);

	/* If its a file display its info */
	if (S_ISREG(stat_buf.st_mode))
		file_forensic(flags, start_point, stat_buf, out_file);

	/* If its a directory go inside it */
	else if (S_ISDIR(stat_buf.st_mode))
		dir_forensic(flags, start_point, out_file);

	return 0;
}