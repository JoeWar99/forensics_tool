#ifndef FORENSIC_H
#define FORENSIC_H

#include <sys/stat.h>

#define BUFFER_SIZE		128
#define PIPE_CMD_ERR    12

int file_forensic(char flag, char *start_point, struct stat stat_buf, char *outfile);

#endif