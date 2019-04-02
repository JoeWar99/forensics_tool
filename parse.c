#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parse.h"

// TODO: virgula a seguir a algoritmo aceite
char parse_cmd(int argc, char * argv[], char * output[]){
	char flags = 0;
	// printf("Usage: ./forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>\n");
	
	for (int i = 0 ; i < argc; i++) {
        /* Found -r flag */
        if (!strcmp(argv[i], "-r")) {
            if (flags & FLAGS_R) {
				fprintf(stderr, "Repeated -r flag\n");
                flags |= FLAGS_ERROR;
				return flags;
            }
            /* Update flag */
            flags |= FLAGS_R;
        }

        /* Found -v flag */
        else if (!strcmp(argv[i], "-v")) {
            if (flags & FLAGS_V) {
				fprintf(stderr, "Repeated -v flag\n");
                flags |= FLAGS_ERROR;
				return flags;
            }
            /* Update flag */
            flags |= FLAGS_V;
        }

        /* Found -h flag */
        else if (!strcmp(argv[i], "-h")) {
            if (flags & FLAGS_H) {
				fprintf(stderr, "Repeated -h flag\n");
                flags |= FLAGS_ERROR;
				return flags;
            }

            /* -h requires something in front */
            if (i >= argc-1) {
				fprintf(stderr, "-h flag requires an algorithm\n");
                flags |= FLAGS_ERROR;
				return flags;
            }

            /* Update flag */
            flags |= FLAGS_H;

            /* Iterate through the algorithms specified */
            char * algorithms = (char*) malloc(sizeof(char) * strlen(argv[i+1] +1));
            algorithms = strcpy(algorithms, argv[i+1]);
            char * next = strtok(algorithms, ",");
            if (next == NULL) {
				fprintf(stderr, "-h flag requires an algorithm\n");
                flags |= FLAGS_ERROR;
				return flags;
            }
            while(next != NULL) {
                if (!strcmp(next, "md5")) {
                    if (flags & FLAGS_MD5) {
						fprintf(stderr, "Repeated md5 algorithm\n");
                        flags |= FLAGS_ERROR;
						return flags;
                    }
                    /* Update flag */
                    flags |= FLAGS_MD5;
                }
                else if (!strcmp(next, "sha1")) {
                    if (flags & FLAGS_SHA1) {
						fprintf(stderr, "Repeated sha1 algorithm\n");
                        flags |= FLAGS_ERROR;
						return flags;
                    }
                    /* Update flag */
                    flags |= FLAGS_SHA1;
                }
                else if (!strcmp(next, "sha256")) {
                    if (flags & FLAGS_SHA256) {
						fprintf(stderr, "Repeated sha256 algorithm\n");
                        flags |= FLAGS_ERROR;
						return flags;
                    }
                    /* Update flag */
                    flags |= FLAGS_SHA256;
                }
                else {
					fprintf(stderr, "Invalid algorithm specified: %s\n", next);
                    flags |= FLAGS_ERROR;
					return flags;
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
				fprintf(stderr, "Repeated -o flag\n");
                flags |= FLAGS_ERROR;
				return flags;
            }
            /* Check for outfile name */
			// TODO: think about how this should work. Accept -v as file name for example???
            if (i >= argc-1) {
				fprintf(stderr, "-o flag requires an outfile name\n");
                flags |= FLAGS_ERROR;
				return flags;
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
			fprintf(stderr, "Invalid option: %s\n", argv[i]);
            flags |= FLAGS_ERROR;
			return flags;
        }
    }

	return flags;
}
