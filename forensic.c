#include "forensic.h"
#include "parse.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <wait.h>


int file_forensic(char flag, char *start_point, struct stat stat_buf, char *outfile)
{
	// file_name,file_type,file_size,file_access,file_created_date,file_modification_date,md5,sha1,sha256
	// Ex: hello.txt,ASCII text,100,rw,2018-01-04T16:30:19,2018-01-04T16:34:13,
	//		4ff75ff116aad93549013ef70f41e59c,d2d29b8b66e3ef44f3412224de6624edd09cdb0c,7605bf
	//		c397c3d78b15a8719ddbfa28e751b81c6127c61a9c171e3db60dd9d046

	struct tm ts;
	char buf[BUFFER_SIZE];
	char * full_cmd = (char *) malloc( 1 + strlen(start_point) + strlen("sha256sum "));
	int n;
	FILE *fp;
	int filedes;
	
	
	if(flag & FLAGS_O){
		filedes = open(outfile, O_WRONLY | O_APPEND | O_CREAT, 0644);
		dup2(filedes, STDOUT_FILENO);

	}

	strcpy(full_cmd, "file ");
	strcat(full_cmd, start_point);

    if ((fp = popen(full_cmd, "r")) == NULL) {
        printf("Error opening file pipe!\n");
        return -1;
    }
	// TODO: not working properly in scripts
    while (fgets(buf, BUFFER_SIZE, fp) != NULL) {
        char * next = strtok(buf, ":");
		write(STDOUT_FILENO, next, strlen(next));
		write(STDOUT_FILENO, ",", 1);
		next = strtok(NULL, ",");
		while(next != NULL){
			if('\n' == next[strlen(next) - 1])
				write(STDOUT_FILENO, ++next, strlen(next)-1);
			else
				write(STDOUT_FILENO, ++next, strlen(next));
			write(STDOUT_FILENO, ",", 1);
			next = strtok(NULL, ",");
		}
    }

    if(pclose(fp))  {
        printf("Command not found or exited with error status\n");
        return -1;
    }

	n = sprintf(buf, "%ld,", stat_buf.st_size);
	write(STDOUT_FILENO, buf, n);

	// PERMISSOES  , DEPOIS TEMOS QUE UTILIZAR PROVAVELMENTE O WRITE() PARA ISTO
	// printf( (S_ISDIR(stat_buf.st_mode)) ? "d" : "-");
    // printf( (stat_buf.st_mode & S_IRUSR) ? "r" : "-");
    // printf( (stat_buf.st_mode & S_IWUSR) ? "w" : "-");
    // printf( (stat_buf.st_mode & S_IXUSR) ? "x" : "-");
    // printf( (stat_buf.st_mode & S_IRGRP) ? "r" : "-");
    // printf( (stat_buf.st_mode & S_IWGRP) ? "w" : "-");
    // printf( (stat_buf.st_mode & S_IXGRP) ? "x" : "-");
    // printf( (stat_buf.st_mode & S_IROTH) ? "r" : "-");
    // printf( (stat_buf.st_mode & S_IWOTH) ? "w" : "-");
    // printf( (stat_buf.st_mode & S_IXOTH) ? "x" : "-");

    printf( (stat_buf.st_mode & S_IRUSR) ? "r" : "");
    printf( (stat_buf.st_mode & S_IWUSR) ? "w" : "");
    printf( (stat_buf.st_mode & S_IXUSR) ? "x" : "");
    printf(","); 
	fflush(stdout);

	// TODO: Both dates are the same
	ts = *localtime(&stat_buf.st_ctime);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S,", &ts);
	write(STDOUT_FILENO, buf, strlen(buf));

	ts = *localtime(&stat_buf.st_mtime);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &ts);
	write(STDOUT_FILENO, buf, strlen(buf));

	if (flag & FLAGS_SHA1)
	{
		strcpy(full_cmd, "sha1sum ");
		strcat(full_cmd, start_point);

		if ((fp = popen(full_cmd, "r")) == NULL) {
			printf("Error opening sha1sum pipe!\n");
			return -1;
		}

		while (fgets(buf, BUFFER_SIZE, fp) != NULL) {
			char * next = strtok(buf, " ");
			write(STDOUT_FILENO, ",", 1);
			write(STDOUT_FILENO, next, strlen(next));
		}

		if(pclose(fp))  {
			printf("Command not found or exited with error status\n");
			return -1;
		}
	}
	if (flag & FLAGS_SHA256)
	{
		strcpy(full_cmd, "sha256sum ");
		strcat(full_cmd, start_point);

		if ((fp = popen(full_cmd, "r")) == NULL) {
			printf("Error opening sha256sum pipe!\n");
			return -1;
		}

		while (fgets(buf, BUFFER_SIZE, fp) != NULL) {
			char * next = strtok(buf, " ");
			write(STDOUT_FILENO, ",", 1);
			write(STDOUT_FILENO, next, strlen(next));
		}

		if(pclose(fp))  {
			printf("Command not found or exited with error status\n");
			return -1;
		}
	}


	if (flag & FLAGS_MD5)
	{
		strcpy(full_cmd, "md5sum ");
		strcat(full_cmd, start_point);

		if ((fp = popen(full_cmd, "r")) == NULL) {
			printf("Error opening md5sum pipe!\n");
			return -1;
		}

		while (fgets(buf, BUFFER_SIZE, fp) != NULL) {
			char * next = strtok(buf, " ");
			write(STDOUT_FILENO, ",", 1);
			write(STDOUT_FILENO, next, strlen(next));
		}

		if(pclose(fp))  {
			printf("Command not found or exited with error status\n");
			return -1;
		}
	}

	write(STDOUT_FILENO, "\n", 1);

	if(flag & FLAGS_O){
		close(filedes);
	}

	return 0;
}
