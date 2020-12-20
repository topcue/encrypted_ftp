CC		= gcc
CFlAGS	= -W -Wall -o2
LDFLAGS	= -lcrypto -lpthread
INC		= -I.

S = server
C = client
O1 = aesenc
O2 = rsa
O3 = util

all: $S $C

%.o: %.c
	@echo "##### build object file"
	$(CC) -c $(INC) $<

$S: $S.c ${O1}.o ${O2}.o ${O3}.o
	@echo "##### [*] build server"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$C: $C.c ${O1}.o ${O2}.o ${O3}.o
	@echo "##### [*] build client"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -rf *.o

# EOF
