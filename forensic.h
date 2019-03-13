#ifndef FORENSIC_H
#define FORENSIC_H

struct stat;

int file_forensic(char flag, char * start_point,struct stat stat_buf);

#endif