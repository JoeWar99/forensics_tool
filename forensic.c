#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "parse.h"

int main(int argc, char * argv[]) {

    if (argc < 2 || argc > 8) {
        printf("Usage: ./forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>\n");
        exit(1);
    }

    /* 0 | r | h | md5 | sha1 | sha256 | o | v */
    char flags = 0;

    /* File or directory specified */
    char * start_point = argv[argc-1];
	struct stat stat_buf;

	/* Test start_point exsitence */
	if(lstat(start_point, &stat_buf) == -1){
			perror(start_point);
			exit(1);
	}

    /* Output file (NULL if -o not set) */
    char * out_file = NULL;

    /* Log file name (NULL if -v not set) */
    char * log_file = NULL;

	/* argc - 2: without ./forensic + <file|dir> */
	flags = parse_cmd(argc - 2, &argv[1], &out_file);

	if(flags & FLAGS_ERROR){
		printf("Usage: ./forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>\n");
        exit(2);
	}

	// TODO: LOGFILE
	/* Get log file name from environment variable */
	if(flags & FLAGS_V)
		log_file = getenv("LOGFILENAME");
    
	if (S_ISREG(stat_buf.st_mode))
		printf("regular\n");
	else if (S_ISDIR(stat_buf.st_mode))
		printf("directory\n");
	else
		printf("other\n");

    printf("0x%x\n", flags);
    if (out_file != NULL) printf("%s\n", out_file);
    if (log_file != NULL) printf("%s\n", log_file);
    // printf("%s\n", start_point);

    return 0;
}