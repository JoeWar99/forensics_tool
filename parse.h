#ifndef PARSE_H
#define PARSE_H


#define BIT(n)			(0x1<<(n))

/* Bits for the used flags */
#define FLAGS_ERROR		BIT(7)
#define FLAGS_R			BIT(6)
#define FLAGS_H			BIT(5)
#define FLAGS_MD5		BIT(4)
#define FLAGS_SHA1		BIT(3)
#define FLAGS_SHA256	BIT(2)
#define FLAGS_O			BIT(1)
#define FLAGS_V			BIT(0)

char parse_cmd(int argc, char * argv[], char * output[]);



#endif