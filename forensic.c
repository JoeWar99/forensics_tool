#include "forensic.h"
#include "sig_handlers.h"
#include "parse.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <wait.h>
#include <errno.h>

extern int sigint_received;


void concat(char *str1[], char *str2, size_t n)
{
	const size_t len1 = strlen(*str1);
	const size_t len2 = n < strlen(str2) ? n : strlen(str2);
	*str1 = (char *)realloc(*str1, len1 + len2 + 1); // +1 for the null-terminator

	/* Check for errors */
	if (*str1 == NULL)
	{
		perror("realloc");
		return;
	}

	/* Concatenate str2 */
	strncat(*str1, str2, len2);
}

int dir_forensic(char flag, char *start_point, char *outfile)
{

	DIR *dirp;
	struct dirent *direntp;
	struct stat stat_buf;
	char name[260];

	/* Open directory */
	if ((dirp = opendir(start_point)) == NULL)
	{
		perror("start_point");
		exit(1);
	}

	/* Read the specified directory */
	while ((direntp = readdir(dirp)) != NULL)
	{
	
		/* Skip . and .. directories */
		if (!strcmp(direntp->d_name, "..") || !strcmp(direntp->d_name, "."))
			continue;

		/* Assemble new file/directory name */
		if (strcmp(start_point, "/")) sprintf(name, "%s/%s", start_point, direntp->d_name);
		else sprintf(name, "/%s", direntp->d_name);

		/* Retrieve information */
		if (lstat(name, &stat_buf) == -1)
		{
			perror("lstat ERROR");
			exit(3);
		}

		/* If its a file print its information */
		if (S_ISREG(stat_buf.st_mode))
		{
			if (flag & FLAGS_O){
				write_in_log("SIGNAL USR2");
				raise(SIGUSR2);
			}
			while(file_forensic(flag, name, stat_buf, outfile) == PIPE_CMD_ERR);
		}

		/* If its a directory and recursive bit is on, read subdirectories */
		else if (S_ISDIR(stat_buf.st_mode) && flag & FLAGS_R)
		{

			/* Create a child */
			pid_t pid = fork();

			/* Fork error */
			if (pid == -1)
			{
				perror("fork");
				exit(1);
			}
			else if (pid == 0)
			{

				/* Override parent signal handlers */
				if (flag & FLAGS_O)
				{
					struct sigaction action;
					action.sa_handler = sigusr_handler_child;
					sigemptyset(&action.sa_mask);
					action.sa_flags = 0;
					sigaction(SIGUSR1, &action, NULL);
					sigaction(SIGUSR2, &action, NULL);
				}

				/* Generate SIGUSR1 signal */
				if (flag & FLAGS_O){
					write_in_log("SIGNAL USR1");
					raise(SIGUSR1);
				}
				/* Look recursively through the folder */
				dir_forensic(flag, name, outfile);

				/* Kill child */
				exit(0);
			}
			else
			{
				while (wait(NULL))
				{
					if (errno == EINTR)
						continue;
					else
						break;
				};
			}
		}
			
		if (sigint_received == 1) break;
	}
	/* Close opened directory */
	closedir(dirp);

	return 0;
}

int file_forensic(char flag, char *start_point, struct stat stat_buf, char *outfile)
{
	// file_name,file_type,file_size,file_access,file_created_date,file_modification_date,md5,sha1,sha256
	// Ex: hello.txt,ASCII text,100,rw,2018-01-04T16:30:19,2018-01-04T16:34:13,
	//		4ff75ff116aad93549013ef70f41e59c,d2d29b8b66e3ef44f3412224de6624edd09cdb0c,7605bf
	//		c397c3d78b15a8719ddbfa28e751b81c6127c61a9c171e3db60dd9d046
	struct tm ts;
	char buf[BUFFER_SIZE];
	char *full_cmd = (char *)malloc(1 + strlen(start_point) + strlen("sha256sum "));
	memset(full_cmd, '\0', 1);
	int n;
	FILE *fp;
	int filedes = STDOUT_FILENO;
	char *ret_string = (char *)malloc(1);
	memset(ret_string, '\0', 1);

	/* Open output file */
	if (flag & FLAGS_O)
	{
		filedes = open(outfile, O_WRONLY | O_APPEND | O_CREAT, 0644);
	}

	strcpy(full_cmd, "file ");
	strcat(full_cmd, start_point);
	/* Pipe with file command */
	if ((fp = popen(full_cmd, "r")) == NULL)
	{
		fprintf(stderr, "Error opening file pipe!\n");
		return -1;
	}
	
	int started = 0;
	char *next;
	/* Parsing file command output */
	while (fgets(buf, BUFFER_SIZE, fp) != NULL)
	{
		if (!started)
		{
			next = strtok(buf, ":");
			concat(&ret_string, next, strlen(next));
			concat(&ret_string, ",", 1);
			next = strtok(NULL, ",");
			started = 1;
		}
		else
			next = strtok(buf, ",");

		while (next != NULL)
		{
			if ('\n' == next[strlen(next) - 1])
			{
				concat(&ret_string, next + 1, strlen(next + 1) - 1);
			}
			else
			{
				concat(&ret_string, next + 1, strlen(next + 1));
			}
			concat(&ret_string, ",", 1);
			next = strtok(NULL, ",");
		}
	}
	/* Closing pipe */
	int ret = pclose(fp);
	if (ret)
	{
		if (ret == -1)
		{
			perror("pclose");
			return -1;
		}
		else {
			return PIPE_CMD_ERR;
		}
	}

	/* Get file size */
	n = sprintf(buf, "%ld,", stat_buf.st_size);
	concat(&ret_string, buf, n);

	/* Get file permission */
	if (stat_buf.st_mode & S_IRUSR)
		concat(&ret_string, "r", 1);
	if (stat_buf.st_mode & S_IWUSR)
		concat(&ret_string, "w", 1);
	if (stat_buf.st_mode & S_IXUSR)
		concat(&ret_string, "x", 1);
	concat(&ret_string, ",", 1);
	fflush(stdout);

	/* Get file access time */
	ts = *localtime(&stat_buf.st_atime);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S,", &ts);
	concat(&ret_string, buf, strlen(buf));

	/* Get file modified time */
	ts = *localtime(&stat_buf.st_mtime);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &ts);
	concat(&ret_string, buf, strlen(buf));

	/* Get SHA1SUM of the file */
	if (flag & FLAGS_SHA1)
	{
		strcpy(full_cmd, "sha1sum ");
		strcat(full_cmd, start_point);
		/* Open pipe with sha1sum command */
		if ((fp = popen(full_cmd, "r")) == NULL)
		{
			fprintf(stderr, "Error opening sha1sum pipe!\n");
			return -1;
		}
		/* Parsing pipe output */
		while (fgets(buf, BUFFER_SIZE, fp) != NULL)
		{
			char *next = strtok(buf, " ");
			concat(&ret_string, ",", 1);
			concat(&ret_string, next, strlen(next));
		}
		/* Close pipe */
		ret = pclose(fp);
		if (ret)
		{
			if (ret == -1)
			{
				perror("pclose");
				return -1;
			}
			else {
				return PIPE_CMD_ERR;
			}
		}
	}
	/* Get SHA256SUM of the file */
	if (flag & FLAGS_SHA256)
	{
		strcpy(full_cmd, "sha256sum ");
		strcat(full_cmd, start_point);
		/* Open pipe with sha256sum command */
		if ((fp = popen(full_cmd, "r")) == NULL)
		{
			fprintf(stderr, "Error opening sha256sum pipe!\n");
			return -1;
		}
		/* Parsing pipe output */
		while (fgets(buf, BUFFER_SIZE, fp) != NULL)
		{
			char *next = strtok(buf, " ");
			concat(&ret_string, ",", 1);
			concat(&ret_string, next, strlen(next));
		}
		/* Close pipe */
		ret = pclose(fp);
		if (ret)
		{
			if (ret == -1)
			{
				perror("pclose");
				return -1;
			}
			else {
				return PIPE_CMD_ERR;
			}
		}
	}
	/* Get MD5SUM of the file */
	if (flag & FLAGS_MD5)
	{
		strcpy(full_cmd, "md5sum ");
		strcat(full_cmd, start_point);
		/* Open pipe with md5sum command */
		if ((fp = popen(full_cmd, "r")) == NULL)
		{
			fprintf(stderr, "Error opening md5sum pipe!\n");
			return -1;
		}
		/* Parsing pipe output */
		while (fgets(buf, BUFFER_SIZE, fp) != NULL)
		{
			char *next = strtok(buf, " ");
			concat(&ret_string, ",", 1);
			concat(&ret_string, next, strlen(next));
		}
		/* Close pipe */
		ret = pclose(fp);
		if (ret)
		{
			if (ret == -1)
			{
				perror("pclose");
				return -1;
			}
			else {
				return PIPE_CMD_ERR;
			}
		}
	}

	concat(&ret_string, "\n", 1);
	write(filedes, ret_string, strlen(ret_string));
	free(ret_string);

	/* Close output file */
	if (flag & FLAGS_O)
	{
		close(filedes);
	}

	char *logDesc = (char *)malloc(9 + strlen(start_point) + 1);
	if (logDesc == NULL)
	{
		perror("logDesc");
		return -2;
	}

	memset(logDesc, '\0', 1);
	strcat(logDesc, "ANALIZED ");
	strcat(logDesc, start_point);

	/* Write in log operation performed */
	write_in_log(logDesc);
	free(logDesc);

	free(full_cmd);
	return 0;
}
