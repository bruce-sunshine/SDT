/*
 * ssl_server.cpp
 *
 *  Created on: Apr 10, 2018
 *      Author: root
 */


#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
//openssl头文件
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/gmsdf.h>
#include <openssl/engine.h>
#include <openssl/sm2.h>
using namespace std;
/*
 *1.generate sm2 key pairs: openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out priv_key.pem
 *2.generate sm2 pubkey derived from privatekey: openssl pkey -pubout -in priv_key.pem -out pub_key.pem
 *3.generate certification from  privatekey: openssl req -new -x509 -key priv_key.pem -out cert_sm2.pem
 *
 *
 *
 *	生成rsa证书:
 *  openssl genrsa -out privkey.pem 2048
 *  openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095
 *
 *
 *
*/

struct dic{
	int val;
	const unsigned char mes[20];
};

static void PrintData(char *p, char *buf,int len,char *filename)
{
	char *name=p;
	printf("%s[%d]:\n",p,len);
	for (p=buf; p && p++-buf<len;)
		printf("%02x%c",(unsigned char)p[-1],(!((p-buf)%16) || p-buf==len)?'\n':' ');
//	if (filename) FileWrite(name,buf,len,filename);
}


int main(int argc, char *argv[])
{
	int listen_fd=-1;              /* TCP监听套接字 */
	int accept_fd=-1;              /* 已连接TCP套接字 */
	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));

	SSL_CTX *ctx=NULL;             /* SSL会话环境 */
	SSL *ssl=NULL;                 /* SSL安全套接字 */
	unsigned char buf[1500]={0};              /* 服务器接收数据buffer */

	if( 3 != argc )
	{
		printf("argcment wrong:ip port\n");
	}

	do
	{
		//使用SSL_CTX_new()创建会话环境，建立连接时要使用协议由TLS_server_method()来定。如果这一步出错，需要查看错误栈来查看原因
		if( NULL==(ctx=SSL_CTX_new(TLSv1_2_method())))		//using sm3
		{
			ERR_print_errors_fp(stdout);
			break;
		}
		SSL_CTX_set_cipher_list(ctx,"ECDHE-SM2-WITH-SMS4-SM3");
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);	//双向认证
		int ret = SSL_CTX_load_verify_locations(ctx, "./pem/cacert.pem", NULL);

		//服务器需要进行用户证书和私匙加载，必须验证两者的一致性；客户端不需要这3步
		if( 0>=SSL_CTX_use_certificate_file(ctx, "./pem/ubuntu_cert.pem", SSL_FILETYPE_PEM/*SSL_FILETYPE_ASN1*/) ) /* 为SSL会话加载用户证书 */
		{
			ERR_print_errors_fp(stdout);
			break;
		}

		if( 0>=SSL_CTX_use_PrivateKey_file(ctx, "./pem/ubuntu_key.pem", SSL_FILETYPE_PEM/*SSL_FILETYPE_ASN1*/) ) /* 为SSL会话加载用户私钥 */
		{
			ERR_print_errors_fp(stdout);
			break;
		}

		if(!SSL_CTX_check_private_key(ctx))                                 										 /* 验证私钥和证书是否相符 */
		{
			ERR_print_errors_fp(stdout);
			break;
		}


		//TCP服务器：创建、绑定、监听
		if( -1==(listen_fd=socket(PF_INET, SOCK_STREAM, 0)) )
		{
			printf("socket create wrong\n");
			break;
		}
		server_addr.sin_family = PF_INET;
		server_addr.sin_port = htons(atoi(argv[2]));
		server_addr.sin_addr.s_addr = inet_addr(argv[1]);
		if( -1==(bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr))) )
		{
			printf("bind wrong\n");
			break;
		}
		if( -1==(listen(listen_fd, 2)) )
		{
			printf("listen wrong\n");
			break;
		}

		//服务器和客户端建立连接
		if( -1==(accept_fd=accept(listen_fd, NULL, NULL)) )    //tcp层连接
		{
			printf("accept wrong\n");
			break;
		}
		else 							//ssl层连接
		{
			ssl=SSL_new(ctx);            /* 由会话环境申请一个SSL层套接字 */
			SSL_set_fd(ssl, accept_fd);  /* 绑定SSL层套接字和TCP层套接字 */

			if( -1==SSL_accept(ssl) )    /* SSL层握手 */
			{
				printf("SSL_accept wrong\n");
				SSL_shutdown(ssl);
				SSL_free(ssl);
				ssl=NULL;
				close(accept_fd);
				accept_fd=-1;
				break;
			}
		}

	}while(0);


	//在SSL层接收数据

	unsigned char buffer[16];
	SSL_export_keying_material(ssl, buffer, 16, NULL, 0, NULL, 0, 1);
	PrintData("SSL_export_keying_material", (char*)buffer, 16, NULL);

	int i;
	memset(buf, 0, sizeof(buf));
	int recvLen = SSL_read(ssl, buf, sizeof(buf));
	printf("recvLen = %d, get media secret is:\n", recvLen);
	for(i = 0; i < 16 - 1; i++)
	{
		printf("0x%02x,", buf[i]);
	}
	printf("0x%02x\n", buf[i]);


	/* 关闭SSL连接，释放SSL安全套接字资源 */
	if( NULL!=ssl )
	{
		SSL_shutdown(ssl);  //关闭一个活的TLS/SSL连接，会向对端发送"close notify"，告诉对方
		SSL_free(ssl);      //减少ssl的引用次数，如果引用次数为零，就移除ssl指向的对象、释放分配的内存；如果ssl是NULL，什么都不做
		ssl=NULL;
	}
	/* 关闭TCP连接 */
	if( -1!=accept_fd)
	{
		close(accept_fd);
		accept_fd=-1;
	}
	/* 释放SSL会话环境 */
	if( NULL!=ctx )
	{
		SSL_CTX_free(ctx);//减少ctx的引用次数，如果引用次数为零，就移除ctx指向的对象、释放分配的内存；如果ctx是NULL，什么都不做
		ctx=NULL;
	}

	return 0;
}


