#include "msg.h"
#include "mac.h"
#include "util.h"
#include "rsa.h"
#include "aesenc.h"
#include "readnwrite.h"

int clnt_cnt = 0;
int clnt_socks[MAX_CLNT];
pthread_mutex_t mutex;


void* handle_clnt(void* arg)
{
	int clnt_sock = *((int*)arg);
	
	// APP_MSG
	APP_MSG* msg_in = NULL;
	APP_MSG* msg_out = NULL;
	msg_in = (APP_MSG*)malloc(sizeof(APP_MSG));
	msg_out = (APP_MSG*)malloc(sizeof(APP_MSG));
	byte* buffer = NULL;
	buffer = (byte*)malloc(sizeof(byte)*(BUFSIZE+AES_BLOCK_SIZE));
	memset(buffer, 0, sizeof(sizeof(byte)*(BUFSIZE+AES_BLOCK_SIZE)));

	// RSA
	BIO* bp_public = NULL;
	BIO* bp_private = NULL;
	BIO* pub = NULL;
	RSA* rsa_pubkey = NULL;
	RSA* rsa_privkey = NULL;
	
	// Session key
	byte key[AES_KEY_128] = {0x00, };
	byte tmp_key[AES_KEY_128] = {0x00, };
	byte iv[AES_KEY_128] = {0x00, };

	// MAC
	EVP_PKEY* hmacKey = NULL;
	const EVP_MD* md = EVP_get_digestbyname("SHA256");
	int size = EVP_MD_size(md);

	// thread
	pthread_t t_id;
	FOO* foo = foo = (FOO*)malloc(sizeof(FOO));
	foo->app_msg = (APP_MSG*)malloc(sizeof(APP_MSG));
	foo->buffer = (byte*)malloc(sizeof(byte)*BUFSIZE+AES_BLOCK_SIZE);
	foo->key = (byte*)malloc(sizeof(byte)*AES_KEY_128);;
	foo->iv = (byte*)malloc(sizeof(byte)*AES_BLOCK_SIZE);

	// etc.
	int len = -1;
	int cnt_i = -1;
	int CMD_TYPE = -1;
	int id_flag = -1;
	int login_flag = -1;
	byte fname[32] = {0x00, };

	
	// ==================== 키 쌍 준비 ====================
	printf("==================== 키 쌍 준비 ====================\n");

	if(!check_rsa_key_exist()) {
		printf("[*] gen_rsa_key_pair()\n");
		gen_rsa_key_pair();
	} else {
		printf("[*] RSA key pair exist!\n");
	}
	printf("[*] Read RSA key pair!\n");

	// reading public key
	bp_public = BIO_new_file("./dirServerSecret/public.pem", "r");
	if(PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL) == NULL) {
		err("[-] PEM_read_bio_RSAPublicKey() error");
	}
	
	// reading private key
	bp_private = BIO_new_file("./dirServerSecret/private.pem", "r");
	if(!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL)) {
		err("[-] PEM_read_bio_RSAPrivateKey() error");
	}

	// ==================== 공개키 준비 ====================
	printf("==================== 공개키 준비 ====================\n");

	recv_msg(clnt_sock, msg_in);
	if(msg_in->type == PUBLIC_KEY_REQUEST) {
		// recv [PUBLIC_KEY_REQUEST]
		printf("[*] recv [PUBLIC_KEY_REQUEST]\n");
		
		// send [PUBLIC_KEY|pubkey]
		printf("[*] send [PUBLIC_KEY|pubkey]\n");
		
		pub = BIO_new(BIO_s_mem());
		PEM_write_bio_RSAPublicKey(pub, rsa_pubkey);
		len = BIO_pending(pub);
		BIO_read(pub, buffer, len);

		// send_msg()
		send_msg(clnt_sock, PUBLIC_KEY, msg_out, buffer, len);
	} else if(msg_in->type == PUBLIC_KEY_EXIST) {
		// recv [PUBLIC_KEY_EXIST]
		printf("[*] recv [PUBLIC_KEY_EXIST]\n");
		// send [ACK]
		printf("[*] send [ACK]\n");
		send_msg(clnt_sock, ACK, msg_out, NULL, 0);
	} else {
		err("[-] not ACK");
	}

	// ==================== 세션 연결 ====================
	printf("==================== 세션 연결 ====================\n");

	// recv [SESSION_KEY|sess_key]
	recv_msg(clnt_sock, msg_in);
	if(msg_in->type != SESSION_KEY) {
		err("[-] not SESSION_KEY");
	} else {
		printf("[*] recv [SESSION_KEY|sess_key]\n");
		len = RSA_private_decrypt(msg_in->msg_len, msg_in->payload,
				buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
		memcpy(key, buffer, len);	
	}

	// recv [SESSION_IV|iv]
	recv_msg(clnt_sock, msg_in);
	if(msg_in->type != SESSION_IV) {
		err("[-] not SESSION_IV");
	} else {
		printf("[*] recv [SESSION_IV|iv]\n");
		len = RSA_private_decrypt(msg_in->msg_len, msg_in->payload,
				buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
		memcpy(iv, buffer, len);
	}

	// MAC init
	foo->hmacKey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, tmp_key, size);
	assert(foo->hmacKey != NULL);
	hmacKey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, tmp_key, size);
	assert(hmacKey != NULL);
	OPENSSL_cleanse(tmp_key, sizeof(tmp_key));
	

	// ==================== 로그인 시도 ====================
	printf("==================== 로그인 시도 ====================\n");	
	while(1) {
		len = recv_encmsg(clnt_sock, msg_in, buffer, key, iv, hmacKey);
		if(len == 0) {
			printf("[*] recv EOF signal\n"); 
			goto EOF_SIGNAL;
		}
		switch(msg_in->type) {
			case SIGNUP_ID:
				// recv [SIGNUP_ID|ID]
				printf("recv [SIGNUP_ID|ID]\n");
				signup(SIGNUP_ID, buffer);
				break;

			case SIGNUP_PW:
				// recv [SIGNUP_PW|PW]
				printf("recv [SIGNUP_PW|PW]\n");
				signup(SIGNUP_PW, buffer);

				// send [ACK]
				printf("send [ACK]\n");
				send_msg(clnt_sock, ACK, msg_out, NULL, 0);
				break;

			case LOGIN_ID:
				// recv [LOGIN_ID|ID]
				printf("recv [LOGIN_ID|ID]\n");
				id_flag = login(LOGIN_ID, buffer);
				if(id_flag == 1) {
					printf("[+] ID found!\n");
				} else {
					printf("[-] ID not found!\n");
				}
				break;

			case LOGIN_PW:
				// recv [LOGIN_PW|PW]
				printf("recv [LOGIN_PW|PW]\n");
				if(id_flag == 1) {
					login_flag = login(LOGIN_PW, buffer);
				}
				
				if(login_flag == 1) {
					// send [LOGIIN]
					printf("[+] PW found!\n");
					printf("[*] send [LOGIIN]\n");
					send_msg(clnt_sock, LOGIN, msg_out, NULL, 0);
				} else {
					// send [NACK]
					printf("[-] ID or PW not found!\n");
					printf("[*] send [NACK]\n");
					send_msg(clnt_sock, NACK, msg_out, NULL, 0);
				}
				break;
				
			default:
				break;
		}
		// if login success
		if(login_flag == 1) {
			printf("[*] LOGIN SUCC\n");
			break;
		}
	}

	// ==================== 커맨드 쉘 획득 ====================
	printf("==================== 커맨드 쉘 획득 ====================\n");
	
	while(1) {	
		len = recv_encmsg(clnt_sock, msg_in, buffer, key, iv, hmacKey);
		if(len == 0) {
			printf("[*] Recv EOF signal\n");
			goto EOF_SIGNAL;
		}

		if(msg_in->type != CMD) {
			printf("[*] not cmd\n");
		}
		CMD_TYPE = get_CMD_TYPE(buffer);
		switch(CMD_TYPE) {
			case LIST:
				printf("[*] recv [LIST]\n");
				len = get_list(buffer);
				send_encmsg(clnt_sock, LIST, msg_out, buffer, len, key, iv, hmacKey);
				break;

			case DOWN:
				printf("[*] recv [DOWN]\n");
				extract_fname1(buffer, "dirServer", fname);
				if(file_check(fname, len) == 0) {
					// send [NACK]
					printf("[*] send [NACK]\n");
					send_msg(clnt_sock, NACK, msg_out, NULL, 0);
				} else {
					// send [ACK]
					printf("[*] send [ACK]\n");
					send_msg(clnt_sock, ACK, msg_out, NULL, 0);
					// send file
					gen_foo(foo, clnt_sock, NULL, msg_out, buffer, strlen(fname), key, iv, hmacKey);
					memcpy(foo->app_msg->payload, fname, strlen(fname));
					
					pthread_create(&t_id, NULL, send_file_foo, (void*)foo);
					pthread_detach(t_id);
					sleep(5);
				}
				break;

			case UP:
				printf("[*] recv [UP]\n");
				recv_encmsg(clnt_sock, msg_in, buffer, key, iv, hmacKey);
				if(msg_in->type == ACK) {
					// recv [ACK]
					printf("[*] recv [ACK]\n");
				} else {
					// recv [NACK]
					printf("[*] recv [NACK]\n");
					break;
				}
				extract_fname1(buffer, "dirServer", fname);
				
				// recv file
				len = strlen(fname);
				gen_foo(foo, clnt_sock, NULL, msg_in, buffer, len, key, iv, hmacKey);
				memcpy(foo->app_msg->payload, fname, len+1);

				pthread_create(&t_id, NULL, recv_file_foo, (void*)foo);
				pthread_detach(t_id);
				sleep(5);
				
				break;

			default:
				break;
		}
	}
EOF_SIGNAL:
	printf("[TCP Server] Client disconnected\n");

	pthread_mutex_lock(&mutex);
	// sort
	for(cnt_i = 0; cnt_i < clnt_cnt; cnt_i++) {
		if(clnt_sock == clnt_socks[cnt_i]) {
			while(cnt_i++ < clnt_cnt - 1 ) {
				clnt_socks[cnt_i] = clnt_socks[cnt_i+1];
			}
			break;
		}
	}
	clnt_cnt--;
	pthread_mutex_unlock(&mutex);

	// close()
	close(clnt_sock);

	// free
	free(msg_in);
	free(msg_out);
	free(buffer);

	free(buffer);
	free(key);
	free(iv);
	free(foo->app_msg);
	free(foo);
	

	return NULL;
}

// =======================================================

int main(int argc, char* argv[])
{
	// socket
	int serv_sock = -1;
	int clnt_sock = -1;
	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size;

	// thread
	pthread_t t_id;
	pthread_mutex_init(&mutex, NULL);

	if(argc != 2) {
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}

	// ==================== 소켓 준비  ====================
	printf("==================== 소켓 준비  ====================\n");

	// socket()
	serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(serv_sock == -1) {
		err("[-] socket() error");
	}

	// set addr
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));

	// bind()
	if(bind(serv_sock, (struct sockaddr* restrict)&serv_addr, sizeof(serv_addr)) == -1) {
		err("[-] bind() error");
	}

	// listen()
	if(listen(serv_sock, 5) == -1) {
		err("[-] listen() error");
	}
	
	while(1) {
		// accept()
		clnt_addr_size = sizeof(clnt_addr);
		clnt_sock = accept(serv_sock, (struct sockaddr* restrict)&clnt_addr, &clnt_addr_size);
		if(clnt_sock == -1) {
			err("[-] accept() error");
		}

		// ==================== 소켓 연결  ====================
		printf("==================== 소켓 연결  ====================\n");

		// thread
		pthread_mutex_lock(&mutex);
		clnt_socks[clnt_cnt++] = clnt_sock;
		pthread_mutex_unlock(&mutex);
		// pthread_create() -> handle_clnt()
		pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);
		pthread_detach(t_id);

		printf("\n[TCP Server] Client connected: IP=%s, port=%d\n", \
				inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
	}

	// close()
	pthread_mutex_destroy(&mutex);
	
	close(serv_sock);
	return 0;
}

// EOF
