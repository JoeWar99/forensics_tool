#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parse.h"

char parse_cmd(int argc, char * argv[], char * output[]){
	char flags = 0;
	// printf("Usage: ./forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>\n");
	
	for (int i = 0 ; i < argc; i++) {
        /* Found -r flag */
        if (!strcmp(argv[i], "-r")) {
            if (flags & FLAGS_R) {
                printf("Repeated -r flag\n");
                exit(1);
            }
            /* Update flag */
            flags |= FLAGS_R;
        }

        /* Found -v flag */
        else if (!strcmp(argv[i], "-v")) {
            if (flags & FLAGS_V) {
                printf("Repeated -v flag\n");
                exit(1);
            }
            /* Update flag */
            flags |= FLAGS_V;
        }

        /* Found -h flag */
        else if (!strcmp(argv[i], "-h")) {
            if (flags & FLAGS_H) {
                printf("Repeated -h flag\n");
                exit(1);
            }
            /* Update flag */
            flags |= FLAGS_H;

            /* Iterate through the algorithms specified */
            char * algorithms = argv[i+1];
            char * next = strtok(algorithms, ",");
            if (next == NULL) {
                printf("-h flag requires an algorithm\n");
                exit(1);
            }
            while(next != NULL) {
                if (!strcmp(next, "md5")) {
                    if (flags & FLAGS_MD5) {
                        printf("Repeated md5 algorithm\n");
                        exit(1);
                    }
                    /* Update flag */
                    flags |= FLAGS_MD5;
                }
                else if (!strcmp(next, "sha1")) {
                    if (flags & FLAGS_SHA1) {
                        printf("Repeated sha1 algorithm\n");
                        exit(1);
                    }
                    /* Update flag */
                    flags |= FLAGS_SHA1;
                }
                else if (!strcmp(next, "sha256")) {
                    if (flags & FLAGS_SHA256) {
                        printf("Repeated sha256 algorithm\n");
                        exit(1);
                    }
                    /* Update flag */
                    flags |= FLAGS_SHA256;
                }
                else {
                    printf("Invalid algorithm specified: %s\n", next);
                    exit(1);
                }

                /* Get next string */
                next = strtok(NULL, ",");
            }
            /* Skip next element */
            i++;
        }
        
        /* Found -o flag */
        else if (!strcmp(argv[i], "-o")) {
            if (flags & FLAGS_O) {
                printf("Repeated -o flag\n");
                exit(1);
            }
            /* Check for outfile name */
            if (i >= argc+1) {
                printf("-o flag requires an outfile name\n");
                exit(1);
            }

            /* Update flag and out_file */
            flags |= FLAGS_O;
            *output = (char *) malloc(sizeof(char) * (strlen(argv[i + 1])+1));
   			strcpy(*output, argv[i + 1]);
            
            /* Skip next element */
            i++;
        }

        /* Do not accept any other option */
        else {
            printf("Invalid option: %s\n", argv[i]);
            exit(1);
        }
    }
	
	return flags;
}