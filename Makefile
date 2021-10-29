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

%.o: src/%.c
	@echo "##### build object file"
	$(CC) -c $(INC) $<

$S: src/$S.c src/${O1}.o src/${O2}.o src/${O3}.o
	@echo "##### [*] build server"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$C: src/$C.c src/${O1}.o src/${O2}.o src/${O3}.o
	@echo "##### [*] build client"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -rf src/*.o $S $C

# EOF
