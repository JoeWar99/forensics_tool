all: project

project: main.o forensic.o log.o parse.o sig_handlers.o
			gcc main.o forensic.o log.o parse.o sig_handlers.o -o forensic -Wextra


main.o : main.c forensic.c log.c sig_handlers.c
			gcc -c main.c -Wextra

forensic.o: forensic.c parse.c log.c
				gcc -c forensic.c -Wextra

log.o: log.c
		gcc -c log.c -Wextra

parse.o: parse.c
			gcc -c parse.c -Wextra

sig_handlers.o: sig_handlers.c
					gcc -c sig_handlers.c -Wextra

clean: 
		rm -rf *o forensic