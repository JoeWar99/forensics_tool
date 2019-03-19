#ifndef SIG_HANDLERS_H
#define SIG_HANDLERS_H

void sigusr_handler(int signo);

void sigusr_handler_child(int signo);
void sigint_handler(int signo);

#endif