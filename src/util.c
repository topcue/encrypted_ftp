#include "msg.h"

// for both
void err(char* msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

// for client
int get_user_input(byte* buffer)
{
	int ret = -1;
	int len = -1;

	if(fgets(buffer, BUFSIZE+1, stdin) == NULL) {
		ret = -1;
		return ret;
	}

	len = strlen(buffer);
	if(buffer[len-1] == '\n') {
		buffer[len-1] = '\0';
	}
	if(strlen(buffer) == 0) {
		return 0;
	}

	ret = len;
	return len;
}

// for server
int check_rsa_key_exist(void)
{
	DIR* dp;
	struct dirent* dent;
	int flag = 0;
	int ret = 0;

	if((dp = opendir("dirServerSecret")) == NULL) {
		err("[-] opendir() error");
	}

	while(dent = readdir(dp)) {
		if(!(strcmp(dent->d_name, "public.pem")) || 
				!(strcmp(dent->d_name, "private.pem"))) {
			flag += 1;
		}
	}
	if(flag == 2) {
		ret = 1;
	} else {
		ret = 0;
	}

	closedir(dp);
	return ret;
}

// for client
int check_pubkey_exist(void)
{
	DIR* dp;
	struct dirent* dent;
	int flag = 0;
	int ret = 0;

	if((dp = opendir("dirClient")) == NULL) {
		err("[-] opendir() error");
	}

	while(dent = readdir(dp)) {
		if(!strcmp(dent->d_name, "public.pem")) {
			flag += 1;
		}
	}
	if(flag == 1) {
		ret = 1;
	} else {
		ret = 0;
	}

	closedir(dp);
	return ret;
}

// for server
int signup(int type, byte* buffer)
{
	FILE *fp = NULL;
	fp = fopen("./dirServerSecret/db", "a");
	if(!fp) {
		err("[-] fopen() err");
	}

	if(type == SIGNUP_ID) {
		fprintf(fp, "%s,", buffer);
	} else if(type == SIGNUP_PW) {
		fprintf(fp, "%s\n", buffer);
	} else {
		err("[-] invalid type\n");
	}
	fclose(fp);
}

// for server
int login(int type, byte* buffer)
{
	int ret = -1;
	byte* p = NULL;
	byte* str_tmp[512] = {0x00, };

	FILE *fp = NULL;
	fp = fopen("./dirServerSecret/db", "r");
	if(!fp) {
		err("[-] fopen() err");
	}

	if(type == LOGIN_ID) {
		while(!feof(fp)) {
			fgets(str_tmp, 512, fp);
			p = strtok(str_tmp, ",");
			if(!strcmp(p, buffer)) {
				ret = 1;
				break;
			}
		}
	} else if(type == LOGIN_PW) {
		while(!feof(fp)) {
			fgets(str_tmp, 512, fp);

			p = strtok(str_tmp, ",");
			p = strtok(NULL, ",");
			if(p != NULL) {
				p[strlen(p)-1] = '\0';			
				if(!strcmp(p, buffer)) {
					ret = 1;
					break;
				}
			}			
		}
	} else {
		err("[-] invalid type\n");
		ret = -1;
	}
	fclose(fp);

	return ret;
}

// for both
int extract_fname1(byte* buffer, byte* dir, byte* fname)
{
	int ret = -1;
	byte* p = NULL;

	p = strtok(buffer, " ");
	if(p != NULL) {
		printf("%s\n", p);
		p = strtok(NULL, " ");
	}
	
	sprintf(fname, "./%s/%s", dir, p);
	ret = 1;
	return ret;
}

// for both
int extract_fname2(byte* buffer, byte* dir, byte* fname)
{
	int ret = -1;
	byte* p = NULL;

	p = strtok(buffer, " ");
	if(p != NULL) {
		p = strtok(NULL, " ");
		p = strtok(NULL, " ");
	}
	sprintf(fname, "./%s/%s", dir, p);
	
	ret = 1;
	return ret;
}

// for both
int get_CMD_TYPE(byte* buffer)
{
	int ret = -1;
    byte* p = NULL;
	byte tmp_buf[64] = {0x00, };

	memcpy(tmp_buf, buffer, sizeof(tmp_buf));
    
	p = strtok(tmp_buf, " ");
	if(p == NULL) {
		ret = -1;
		return ret;
	}

	if(!strcmp(p, "list")) {
		ret = LIST;
	} else if(!strcmp(p, "down")) {
		ret = DOWN;
	}  else if(!strcmp(p, "up")) {
		ret = UP;
	} else if(!strcmp(p, "help")) {
		ret = HELP;
	} else {
		printf("ret = -1\n");
		ret = -1;
	}
    
	return ret;
}


// for server
int get_list(byte* buffer)
{
	DIR* dp;
	struct dirent* dent;
	int ret = -1;
	int len = -1;

	memset(buffer, 0, sizeof(buffer));
	if((dp = opendir("dirServer")) == NULL) {
		err("opendir() error");
	}

	while(dent = readdir(dp)) {
		if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) {
			continue;
		}
		sprintf(buffer, "%s%s,", buffer, dent->d_name);
	}
	
	len = strlen(buffer);
	if(len <= 0) {
		ret = 8;
		memcpy(buffer, "[EMPTY]", ret);
		return ret;
	}
	
	buffer[len-1] = '\0';
	buffer[len] = '\n';
	ret = len;
	
	closedir(dp);

	return ret;
}

// for client
int show_list(int sock, APP_MSG* msg_in, byte* buffer, int len, byte* key, byte* iv, EVP_PKEY* hmacKey)
{
	int ret = -1;
	byte* p = NULL;

	len = recv_encmsg(sock, msg_in, buffer, key, iv, hmacKey);

	p = strtok(buffer, ",");
	while(p != NULL) {
		printf(" %s ", p);
		p = strtok(NULL, ",");
	}
	printf("\n");
	
	ret = 1;
	return ret;
}

// for server
int file_check(byte* fname, int len)
{
	int ret = -1;
	int fd = -1;	
	int file_size;
	
	fd = open(fname, O_RDONLY, S_IRWXU);

	if(fd == -1) {
		printf("[-] file not found\n");
		ret = 0;
		return ret;
	}
	
	// get file size
	file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
#if DEBUG
	printf("file size : %d\n", file_size);
#endif
	
	if(file_size <= 0) {
		// 나중에 처리
		ret = 0;
		return 0;
		// err("file size is 0");
	}
	len = file_size;

	close(fd);

	ret = 1;
	return ret;
}

// for both
int send_msg(int sock, int type, APP_MSG* msg_out, byte* buffer, int len)
{
#if DEBUG
	printf("[*] send_msg()\n");
#endif
	int ret = -1;
	
	memset(msg_out, 0, sizeof(APP_MSG));
	
	msg_out->type = htonl(type);
	msg_out->msg_len = htonl(len);

	if(len == 0) {
#if DEBUG
		printf("[*] send HEADER\n");
#endif
		ret = writen(sock, msg_out, HEADER_SIZE+HASH_SIZE);
	} else {
#if DEBUG
		printf("[*] send HEADER+BODY\n");
#endif
		memcpy(msg_out->payload, buffer, len);
		ret = writen(sock, msg_out, HEADER_SIZE+HASH_SIZE+len);
	}
	
	return ret;
}

// for both
int send_encmsg(int sock, int type, APP_MSG* msg_out, byte* buffer, int len, byte* key, byte* iv, EVP_PKEY* hmacKey)
{
#if DEBUG
	printf("[*] send_encmsg()\n");
#endif

	int ciphertext_len = 0;
	int ret = -1;
	size_t slen = 0;
	byte* sig = NULL;

	memset(msg_out, 0, sizeof(APP_MSG));
	msg_out->type = htonl(type);

	// encrypt()
	ciphertext_len = encrypt(buffer, len, key, iv, (byte*)(msg_out->payload));
	msg_out->msg_len = htonl(ciphertext_len);

	// sign
	ret = sign_it(msg_out->payload, ciphertext_len, &sig, &slen, hmacKey);
	assert(ret == 0);
	if(ret != 0) {
		err("[-] Failed to create signature");
	}

	memcpy(msg_out->hash, sig, slen);

	ret = writen(sock, msg_out, HEADER_SIZE+HASH_SIZE+ciphertext_len);
	if(ret < 0) {
		err("writen() error");
	}
#if DEBUG
	print_it("[*] Signature", sig, slen);
#endif
	return ret;
}


// for both
int recv_msg(int sock, APP_MSG* msg_in)
{
#if DEBUG
	printf("[*] recv_msg()\n");
#endif
	int n = -1;
	
	n = readn(sock, &msg_in->type, sizeof(int));
	n = readn(sock, &msg_in->msg_len, LEN_SIZE);
	msg_in->type = ntohl(msg_in->type);
	msg_in->msg_len = ntohl(msg_in->msg_len);
	n = readn(sock, &msg_in->hash, HASH_SIZE);
	n = readn(sock, &msg_in->payload, msg_in->msg_len);
	
	return 1;
}


// for both
int recv_encmsg(int sock, APP_MSG* msg_in, byte* buffer, byte* key, byte* iv, EVP_PKEY* hmacKey)
{
#if DEBUG
	printf("[*] recv_encmsg()\n");
#endif
	int n = 0;
	int len = -1;
	int ret = -1;
	byte* sig = NULL;
	size_t slen = 0;

	n = readn(sock, &msg_in->type, TYPE_SIZE);
	n = readn(sock, &msg_in->msg_len, LEN_SIZE);
	
	msg_in->type = ntohl(msg_in->type);
	msg_in->msg_len = ntohl(msg_in->msg_len);
#if DEBUG
	printf("[*] msg_type = %d\n", msg_in->type);
	printf("[*] len = %d\n", msg_in->msg_len);
#endif

	if(msg_in->msg_len == 0) {
#if DEBUG
		printf("[*] recv HEADER!\n");
#endif
		n = readn(sock, &msg_in->hash, HASH_SIZE);
		return 0;
	}

	// msg_in->hash
	n = readn(sock, &msg_in->hash, HASH_SIZE);
	n = readn(sock, &msg_in->payload, msg_in->msg_len);
	
	
	// verify
	ret = verify_it(msg_in->payload, msg_in->msg_len, sig, slen, hmacKey);
	if(ret != 0) {
		err("Failed to verify signature\n");	
	}
	
#if DEBUG
	printf("[*] Verified signature\n");
	printf("\n* encryptedMsg:\n");
	BIO_dump_fp(stdout, (const byte*)msg_in->payload, msg_in->msg_len);
#endif

	// decrypt()
	len = decrypt(msg_in->payload, msg_in->msg_len, key, iv, (byte*)buffer);
	if(len < 0) {
		err("decrypt() error");
	}
#if DEBUG
	// show decrypted msg
	printf("\n* decryptedMsg:\n");
	BIO_dump_fp(stdout, (const byte*)buffer, len);
#endif
	return len;
}


int send_file_foo(FOO* foo)
{
	int ret = -1;
	int fd = -1;
	byte buffer[BUFSIZE] = {0x00, };
	int read_len = -1;
	int file_size = -1;
	
#if DEBUG
	printf("fname : %s\n", foo->app_msg->payload);
#endif

	fd = open(foo->app_msg->payload, O_RDONLY, S_IRWXU);
	if(fd == -1) {
		// send [NACK]
		send_msg(foo->sock, NACK, foo->app_msg, NULL, 0);
		printf("[-] open() error...\n");
		return -1;
	}

	// send [DOWN|file size]
	file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	byte tmp[4] = {0x00, };
	tmp[0] = file_size >> 24;
	tmp[1] = file_size >> 16;
	tmp[2] = file_size >> 8;
	tmp[3] = file_size;
	send_encmsg(foo->sock, ENCRYPTED_MSG, foo->app_msg, tmp, 4, foo->key, foo->iv, foo->hmacKey);
	memset(buffer, 0, sizeof(buffer));

	// send [DOWN|file]
	int nleft = file_size;
	while(nleft > 0) {
		read_len = readn(fd, buffer, sizeof(buffer));
#if DEBUG
		printf("[*] read_buffer : %s\n", buffer);
		printf("[*] read_len : %d\n", read_len);
#endif
		if(read_len == 0) {
			break;
		}
		foo->len = send_encmsg(foo->sock, DOWN, foo->app_msg, buffer, read_len, foo->key, foo->iv, foo->hmacKey);
		nleft -= read_len;
		usleep(100000);
	}
	close(fd);

	ret = 1;
	return ret;
}

int recv_file_foo(FOO* foo)
{
	int ret = -1;
	int fd = -1;
	int read_len = -1;
	int file_size = -1;
	int nleft = -1;
#if DEBUG
	printf("fname : %s\n", foo->app_msg->payload);
#endif

	fd = open(foo->app_msg->payload, O_CREAT | O_WRONLY, S_IRWXU);
	if(fd == -1) {
		err("open() error");
	}

	// recv [UP|file_size]
	read_len = recv_encmsg(foo->sock, foo->app_msg, foo->buffer, foo->key, foo->iv, foo->hmacKey);
	file_size = (foo->buffer[0]<<24)|(foo->buffer[1]<<16)|(foo->buffer[2]<<8)|foo->buffer[3];
	memset(foo->buffer, 0, sizeof(foo->buffer));

#if DEBUG
	printf("[file size] file_size:%d\n", file_size);
#endif

	// recv [DOWN|file]
	nleft = file_size;
	while(nleft > 0) {
		read_len = recv_encmsg(foo->sock, foo->app_msg, foo->buffer, foo->key, foo->iv, foo->hmacKey);		
		if(write(fd, foo->buffer, read_len) != read_len) {
			err("[-] write() error");
		}
		nleft -= read_len;
		usleep(100000);
	}
	printf("[*] File receiving completed\n");
	if(fd != -1) {
		close(fd);
	}
	ret = 1;
	return ret;
}


void gen_foo(FOO* foo, int sock, int type, APP_MSG* app_msg, byte* buffer, int len, byte* key, byte* iv, EVP_PKEY* hmacKey)
{
	foo->sock = sock;
	foo->type = type;
	memcpy(foo->app_msg, app_msg, sizeof(APP_MSG));
	if(buffer != NULL) {
		memcpy(foo->buffer, buffer, len);
	}
	foo->len = len;
	if(key != NULL) {
		memcpy(foo->key, key, AES_KEY_128);
	}
	if(iv != NULL) {
		memcpy(foo->iv, iv, AES_KEY_128);
	}
	if(hmacKey != NULL) {
		memcpy(foo->hmacKey, hmacKey, sizeof(hmacKey));
	}
}
 

// EOF
