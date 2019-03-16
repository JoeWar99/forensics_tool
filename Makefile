all: project

project: main.o forensic.o log.o parse.o sig_handlers.o
			gcc main.o forensic.o log.o parse.o sig_handlers.o -o forensic -Wall


main.o : main.c forensic.c log.c sig_handlers.c
			gcc -c main.c

forensic.o: forensic.c parse.c log.c
				gcc -c forensic.c

log.o: log.c
		gcc -c log.c

parse.o: parse.c
			gcc -c parse.c

sig_handlers.o: sig_handlers.c
					gcc -c sig_handlers.c

clean: 
		rm -rf *o forensic