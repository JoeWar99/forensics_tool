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

// TODO free memory after using concat
void concat(char* str1, char* str2, int n) {
	const size_t len1 = strlen(str1);
    const size_t len2 = n < strlen(str2) ? n : strlen(str2);
    str1 = (char*) realloc(str1, len1 + len2 + 1); // +1 for the null-terminator

	/* Check for errors */
	if (str1 == NULL) {
		perror("realloc");
		exit(1);
	}

	/* Concatenate str2 */
    memcpy(str1 + len1, str2, len2);
	str1[len1+len2] = '\0';

	// TODO
	// Ele aqui fica bem, mas depois na funcao principal nao fica
	printf("%s\n", str1);
}

/*
void append_string(char* str1, char* str2) { 
	printf(">1 %s\n", str1);
	//char * prev = str1;
	str1 = concat(str1, str2, strlen(str2)); 
	//free(prev);
	printf(">2 %s\n", str1);
}
void append_string_n(char* str1, char* str2, int n) { 
	str1 = concat(str1, str2, n); 
}
*/
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
	char * ret_string = (char *) malloc(1);
	
	
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
	write(STDOUT_FILENO, ret_string, strlen(ret_string));

	int started = 0;
	char * next;
    while (fgets(buf, BUFFER_SIZE, fp) != NULL) {
		if (!started) {
			next = strtok(buf, ":");
			concat(ret_string, next, strlen(next));
			concat(ret_string, ",", 1);
			//write(STDOUT_FILENO, next, strlen(next));
			//write(STDOUT_FILENO, ",", 1);
			next = strtok(NULL, ",");
			started = 1;
		}
		else
			next = strtok(buf, ",");

		printf(">1 %s\n", ret_string);
		while(next != NULL){
			if('\n' == next[strlen(next) - 1]) {
				printf(">4 %s\n", ret_string);
				concat(ret_string, next+1, strlen(next+1)-1);
				printf(">5 %s\n", ret_string);
				//write(STDOUT_FILENO, next+1, strlen(next)-2);
			}
			else {
				concat(ret_string, next+1, strlen(next+1));
				printf(">2 %s\n", ret_string);
				//write(STDOUT_FILENO, next+1, strlen(next));
				// TODO above should be strlen(next) - 1 ????
			}
			concat(ret_string, ",", 1);
			printf(">3 %s\n", ret_string);
			//write(STDOUT_FILENO, ",", 1);
			next = strtok(NULL, ",");
		}
    }

    if(pclose(fp))  {
        printf("Command not found or exited with error status\n");
        return -1;
    }

	n = sprintf(buf, "%ld,", stat_buf.st_size);
	concat(ret_string, buf, n);
	//write(STDOUT_FILENO, buf, n);

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

/*
    printf( (stat_buf.st_mode & S_IRUSR) ? "r" : "");
    printf( (stat_buf.st_mode & S_IWUSR) ? "w" : "");
    printf( (stat_buf.st_mode & S_IXUSR) ? "x" : "");
    printf(","); */
	fflush(stdout);

	// TODO: Both dates are the same
	ts = *localtime(&stat_buf.st_ctime);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S,", &ts);
	//write(STDOUT_FILENO, buf, strlen(buf));

	ts = *localtime(&stat_buf.st_mtime);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &ts);
	//write(STDOUT_FILENO, buf, strlen(buf));

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

	//write(STDOUT_FILENO, "\n", 1);

	if(flag & FLAGS_O){
		close(filedes);
	}

	write(STDOUT_FILENO, ret_string, strlen(ret_string));
	free(ret_string);
	return 0;
}
