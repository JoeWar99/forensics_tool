#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
//#include "forensic.h"
#include <unistd.h>
#include "parse.h"
#include <wait.h>
#include <time.h>
#include <fcntl.h>

int file_forensic(char flag, char *start_point, struct stat stat_buf, char *outfile)
{
	// TODO: analisar ficheiro
	// file_name,file_type,file_size,file_access,file_created_date,file_modification_date,md5,sha1,sha256
	// Ex: hello.txt,ASCII text,100,rw,2018-01-04T16:30:19,2018-01-04T16:34:13,
	//		4ff75ff116aad93549013ef70f41e59c,d2d29b8b66e3ef44f3412224de6624edd09cdb0c,7605bf
	//		c397c3d78b15a8719ddbfa28e751b81c6127c61a9c171e3db60dd9d046

	pid_t pid;
	struct tm ts;
	char buf[80];
	char buffer[100];
	int n;
	char buffer1[100];
	int filedes;
	
	
	if(flag & FLAGS_O){
		filedes = open(outfile, O_RDWR | O_CREAT, 0644);
		dup2(filedes, STDOUT_FILENO);

	}
	pid = fork();
	if (pid == 0)
	{
		execlp("file", "file", start_point, NULL);
		exit(0);
	}
	else
	{
		wait(NULL);
	}

	n = sprintf(buffer1, "%ld,", stat_buf.st_size);
	write(STDOUT_FILENO, buffer1, n);
	n =sprintf(buffer, "%u,", stat_buf.st_mode);

	// PERMISSOES  , DEPOIS TEMOS QUE UTILIZAR PROVAVELMENTE O WRITE() PARA ISTO
	printf( (S_ISDIR(stat_buf.st_mode)) ? "d" : "-");
    printf( (stat_buf.st_mode & S_IRUSR) ? "r" : "-");
    printf( (stat_buf.st_mode & S_IWUSR) ? "w" : "-");
    printf( (stat_buf.st_mode & S_IXUSR) ? "x" : "-");
    printf( (stat_buf.st_mode & S_IRGRP) ? "r" : "-");
    printf( (stat_buf.st_mode & S_IWGRP) ? "w" : "-");
    printf( (stat_buf.st_mode & S_IXGRP) ? "x" : "-");
    printf( (stat_buf.st_mode & S_IROTH) ? "r" : "-");
    printf( (stat_buf.st_mode & S_IWOTH) ? "w" : "-");
    printf( (stat_buf.st_mode & S_IXOTH) ? "x" : "-");
    printf(",\n");


	ts = *localtime(&stat_buf.st_ctime);
	strftime(buf, sizeof(buf), " %Y-%m-%dT%H:%M:%S,", &ts);
	write(STDOUT_FILENO, buf, strlen(buf));

	ts = *localtime(&stat_buf.st_mtime);
	strftime(buf, sizeof(buf), " %Y-%m-%dT%H:%M:%S,", &ts);
	write(STDOUT_FILENO, buf, strlen(buf));

	if (flag & FLAGS_SHA1)
	{
		pid = fork();
		if (pid == 0)
		{
			if (execlp("sha1sum", "sha1sum", start_point, NULL) == -1)
			{
				printf("Erro ao executar exelp\n");
				exit(1);
			}
			exit(0);
		}
		else
		{
			wait(NULL);
		}
		write(STDOUT_FILENO, ",", 1);
	}
	if (flag & FLAGS_SHA256)
	{
		pid = fork();
		if (pid == 0)
		{
			if (execlp("sha256sum", "sha256sum", start_point, NULL) == -1)
			{
				printf("Erro ao executar exelp\n");
				exit(1);
			}
			exit(0);
		}
		else
		{
			wait(NULL);
		}
		write(STDOUT_FILENO, ",", 1);
	}


	if (flag & FLAGS_MD5)
	{
		pid = fork();
		if (pid == 0)
		{
			if (execlp("md5sum", "md5sum", start_point, NULL) == -1)
			{
				printf("Erro ao executar exelp\n");
				exit(1);
			}
			exit(0);
		}
		else
		{
			wait(NULL);
		}
		write(STDOUT_FILENO, ",", 1);
	}
	if(flag & FLAGS_O){
		close(filedes);
	}
	exit(0);
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

	if (S_ISREG(stat_buf.st_mode))
		printf("regular\n");
	else if (S_ISDIR(stat_buf.st_mode))
		printf("directory\n");
	else
		printf("other\n");

	//printf("0x%x\n", flags);
	if (out_file != NULL)
		printf("%s\n", out_file);
	if (log_file != NULL)
		printf("%s\n", log_file);
	//printf("%s\n", start_point);
	file_forensic(flags, start_point, stat_buf, out_file);

	return 0;
}