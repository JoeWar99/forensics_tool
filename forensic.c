#include "forensic.h"
#include "parse.h"
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

int file_forensic(char flag, char * start_point,struct stat stat_buf){
	// TODO: analisar ficheiro
	// file_name,file_type,file_size,file_access,file_created_date,file_modification_date,md5,sha1,sha256
	// Ex: hello.txt,ASCII text,100,rw,2018-01-04T16:30:19,2018-01-04T16:34:13,
	//		4ff75ff116aad93549013ef70f41e59c,d2d29b8b66e3ef44f3412224de6624edd09cdb0c,7605bf
	//		c397c3d78b15a8719ddbfa28e751b81c6127c61a9c171e3db60dd9d046

    pid_t pid;
    pid = fork();

    if(pid == 0){
        execlp("file", "file", start_point, NULL);
    }
    else{
        wait(NULL);
    }
    printf("%d," stat_buf.st_size);




    return 0;
}