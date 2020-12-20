#include "msg.h"
#include "mac.h"
#include "util.h"
#include "rsa.h"
#include "aesenc.h"
#include "readnwrite.h"

int clnt_cnt = 0;
int clnt_socks[MAX_CLNT];
pthread_mutex_t mutex;

int main(int argc, char* argv[])
{
	// socket
	int sock = -1;
	struct sockaddr_in serv_addr;

	// APP_MSG
	APP_MSG* msg_in = NULL;
	APP_MSG* msg_out = NULL;
	msg_in = (APP_MSG*)malloc(sizeof(APP_MSG));
	msg_out = (APP_MSG*)malloc(sizeof(APP_MSG));
	byte* buffer = NULL;
	buffer = (byte*)malloc(sizeof(byte)*(BUFSIZE+AES_BLOCK_SIZE));
	memset(buffer, 0, sizeof(sizeof(byte)*(BUFSIZE+AES_BLOCK_SIZE)));

	// RSA
	BIO* rpub = NULL;
	RSA* rsa_pubkey = NULL;
	
	// Session key
	byte key[AES_KEY_128] = {0x00, };
	byte tmp_key[AES_KEY_128] = {0x00, };
	byte iv[AES_BLOCK_LEN] = {0x00, };

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
	int menu = -1;
	int CMD_TYPE = -1;
	int login_flag = -1;
	byte gc = -1;
	byte fname[32] = {0x00, };
	
	pthread_mutex_init(&mutex, NULL);

	if(argc != 3) {
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

	// ==================== 소켓 초기화 ====================
	printf("==================== 소켓 초기화 ====================\n");
	
	// socket()
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1) {
		err("[-] socket() error");
	}

	// set addr
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	// connect()
	if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
		err("[-] connect() error");
	}

	// ==================== 공개키 준비 ====================
	printf("==================== 공개키 준비 ====================\n");
	
	if(!check_pubkey_exist()) {
		// send [PUBLIC_KEY_REQUEST]
		printf("[*] send [PUBLIC_KEY_REQUEST]\n");
		send_msg(sock, PUBLIC_KEY_REQUEST, msg_out, NULL, 0);

		// recv [PUBLIC_KEY|pubkey]
		printf("[*] recv [PUBLIC_KEY|pubkey]\n");
		recv_msg(sock, msg_in);
		if(msg_in->type != PUBLIC_KEY) {
			err("[-] not PUBLIC_KEY");
		} else {

#if DEBUG
			BIO_dump_fp(stdout, (const char*)msg_in->payload, msg_in->msg_len);
#endif
			printf("[*] Save public key as \"public.pem\"\n");
			FILE* fp = NULL;
			fp = fopen("./dirClient/public.pem", "w+");
			fputs((const byte*)msg_in->payload, fp);
			fclose(fp);
			
			// extract pubkey and write at rsa_pubkey
			rpub = BIO_new_mem_buf(msg_in->payload, -1);
			BIO_write(rpub, msg_in->payload, msg_in->msg_len);
			if(!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL)) {
				err("PEM_read_bio_RSAPublicKey() error");
			}
		}
	} else {
		// send [PUBLIC_KEY_EXIST]
		printf("[*] send [PUBLIC_KEY_EXIST]\n");
		send_msg(sock, PUBLIC_KEY_EXIST, msg_out, NULL, 0);

		// read pubkey from "public.pem"
		if(!read_pubkey_pem(&rsa_pubkey)) {
			err("[-] read_pubkey_pem() error");
		}
		
		// recv [ACK]
		printf("[*] recv [ACK]\n");
		recv_msg(sock, msg_in);
		if(msg_in->type != ACK) {
			err("[-] not ACK");
		}
	}

	// ==================== 세션 연결 ====================
	printf("==================== 세션 연결 ====================\n");
	
	// gen random session key and iv
	RAND_poll();
	RAND_bytes(key, sizeof(key));
	RAND_bytes(iv, sizeof(iv));

	// send [SESSION_KEY|sess_key]
	printf("[*] send [SESSION_KEY|sess_key]\n");
	len = RSA_public_encrypt(sizeof(key), key, buffer, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
	len = send_msg(sock, SESSION_KEY, msg_out, buffer, len);
	if(len == -1) {
		err("[-] invalid session key length!");
	}

	// send [SESSION_IV|iv]
	printf("[*] send [SESSION_IV|iv]\n");
	len = RSA_public_encrypt(sizeof(iv), iv, buffer, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
	len = send_msg(sock, SESSION_IV, msg_out, buffer, len);
	if(len == -1) {
		err("[-] invalid session key length!");
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
		printf("\n   ********** [ LOGIN MENU ]  **********\n");
		printf("   ********** [ 1. Sign Up ]  **********\n");
		printf("   ********** [ 2. Login   ]  **********\n");
		// printf("   ********** Press 1 or 2     **********\n");
		printf("\n[SYSTEM] Press 1 or 2\n");
		printf("[GUEST] $ ");

		scanf("%d%c", &menu, &gc);
		switch (menu) {
			case 1:
				// send [SIGNUP_ID|ID]
				printf("\n[SYSTEM] Select Sign Up\n");
				fputs("\n[SYSTEM] Input ID\n", stdout);
				printf("[GUEST] $ ");
				len = get_user_input(buffer);
				send_encmsg(sock, SIGNUP_ID, msg_out, buffer, len, key, iv, hmacKey);
				
				// send [SIGNUP_PW|PW]
				fputs("\n[SYSTEM] Input PW\n", stdout);
				printf("[GUEST] $ ");
				len = get_user_input(buffer);
				send_encmsg(sock, SIGNUP_PW, msg_out, buffer, len, key, iv, hmacKey);
				
				// recv [ACK]
				len = recv_msg(sock, msg_in);
				if(msg_in->type == ACK) {
					fputs("\n[SYSTEM] Sign Up Success!\n", stdout);
				} else {
					fputs("\n[SYSTEM] Sign Up Failed..\n", stdout);
				}
				break;

			case 2:
				// send [LOGIN_ID|ID]
				printf("\n[SYSTEM] Select Login\n");
				
				fputs("\n[SYSTEM] Input ID\n", stdout);
				printf("[GUEST] $ ");
				len = get_user_input(buffer);
				send_encmsg(sock, LOGIN_ID, msg_out, buffer, len, key, iv, hmacKey);

				// send [LOGIN_PW|PW]
				fputs("\n[SYSTEM] Input PW\n", stdout);
				printf("[GUEST] $ ");
				len = get_user_input(buffer);
				send_encmsg(sock, LOGIN_PW, msg_out, buffer, len, key, iv, hmacKey);
				
				// recv [LOGIN]
				recv_msg(sock, msg_in);
				if(msg_in->type == LOGIN) {
					fputs("\n[SYSTEM] Login Success!\n", stdout);
					login_flag = 1;
					break;
				} else {
					fputs("\n[SYSTEM] Login Failed..!\n", stdout);
				}
				break;
				
			default:
				printf("\n[-] Invalid Input..\n");
				getc(stdin);
				menu = -1;
				break;
		}
		if(login_flag == 1) {
			printf("[*] LOGIN SUCCESS!\n");
			break;
		}
	}
	// ==================== 커맨드 쉘 획득 ====================
	printf("==================== 커맨드 쉘 획득 ====================\n");

	while(1) {
		printf("\n[USER] $ ");
		len = get_user_input(buffer);
		send_encmsg(sock, CMD, msg_out, buffer, len, key, iv, hmacKey);	
		
		CMD_TYPE = get_CMD_TYPE(buffer);
		switch (CMD_TYPE) {
			case HELP:
				printf("[*] CMD : [HELP]\n");
				printf("[*] available commands : ");
				printf("list  down  up\n");
				break;

			case LIST:
				printf("[*] CMD : [LIST]\n");
				printf("[Server File List] ");
				show_list(sock, msg_in, buffer, len, key, iv, hmacKey);
				break;

			case DOWN:
				printf("[*] CMD : [DOWN]\n");
				recv_encmsg(sock, msg_in, buffer, key, iv, hmacKey);
				if(msg_in->type == ACK) {
					printf("[*] recv [ACK]]\n");
				} else {
					printf("[*] recv [NACK]]\n");
					break;
				}
				extract_fname2(buffer, "dirClient", fname);
				// recv file
				len = strlen(fname);
				gen_foo(foo, sock, NULL, msg_in, buffer, len, key, iv, hmacKey);
				memcpy(foo->app_msg->payload, fname, len+1);

				pthread_create(&t_id, NULL, recv_file_foo, (void*)foo);
				pthread_detach(t_id);
				sleep(5);
				break;
				
			case UP:
				printf("[*] CMD : [UP]\n");
				extract_fname1(buffer, "dirClient", fname);
				if(file_check(fname, len) == 0) {
					// send [NACK]
					printf("[*] send [NACK]\n");
					send_msg(sock, NACK, msg_out, NULL, 0);
				} else {
					// send [ACK]
					printf("[*] send [ACK]\n");
					send_msg(sock, ACK, msg_out, NULL, 0);

					// send file
					printf("[*] send file\n");
					gen_foo(foo, sock, NULL, msg_out, buffer, strlen(fname), key, iv, hmacKey);
					memcpy(foo->app_msg->payload, fname, strlen(fname));
					pthread_create(&t_id, NULL, send_file_foo, (void*)foo);
					pthread_detach(t_id);
					sleep(5);
				}
				break;
			
			default:
				printf("[SYSTEM] Command not found..\n");
				printf("[SYSTEM] \'help\' to see available commands.\n");
				break;
		}
	}

	// free
	free(msg_in);
	free(msg_out);
	free(buffer);

	free(buffer);
	free(key);
	free(iv);
	free(foo->app_msg);
	free(foo);

	// close()
	close(sock);

	return 0;
}


// EOF
