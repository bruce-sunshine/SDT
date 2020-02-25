/*
 * ssl_client.cpp
 *
 *  Created on: Apr 10, 2018
 *      Author: root
 */
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
//openssl头文件
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/sm2.h>
#include <openssl/skf.h>
#include <openssl/gmapi.h>
using namespace std;

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

	int sock_fd=-1;			 		/* TCP套接字    */
	SSL_CTX *ctx=NULL;    			/* SSL会话环境 */
	SSL *ssl=NULL;         			/* SSL安全套接字 */
	struct sockaddr_in ser_addr;	/* 服务器地址 */
	bzero(&ser_addr, sizeof(ser_addr));
	int err;

	if( argc != 3 )
	{
		printf("argcment wrong:ip port content\n");
		exit(0);
	}

	do
	{
		/* 申请SSL会话环境 */
		if( NULL==(ctx=SSL_CTX_new(TLSv1_2_method())))    //使用SSL_CTX_new()创建会话环境，建立连接时要使用协议由TLS_client_method()来定，服务器由对应的TLS_server_method()来定。如果这一步出错，需要查看错误栈来查看原因
		{
			ERR_print_errors_fp(stdout);
			break;
		}
		SSL_CTX_set_cipher_list(ctx,"ECDHE-SM2-WITH-SMS4-SM3");
		/* TCP连接 */
		//服务器需要进行用户证书和私匙加载，必须验证两者的一致性；客户端不需要这3步
		if( 0>=SSL_CTX_use_certificate_file(ctx, "./pem/Terminal_cert.pem", SSL_FILETYPE_PEM/*SSL_FILETYPE_ASN1*/) ) /* 为SSL会话加载用户证书 */
		{
			ERR_print_errors_fp(stdout);
			break;
		}
		if( 0>=SSL_CTX_use_PrivateKey_file(ctx, "./pem/Terminal_key.pem", SSL_FILETYPE_PEM/*SSL_FILETYPE_ASN1*/) ) /* 为SSL会话加载用户私钥 */
		{
			ERR_print_errors_fp(stdout);
			break;
		}
		if(!SSL_CTX_check_private_key(ctx))                                 										 /* 验证私钥和证书是否相符 */
		{
			ERR_print_errors_fp(stdout);
			break;
		}

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);	//双向认证
		SSL_CTX_load_verify_locations(ctx, "./pem/cacert.pem", NULL);

		if( -1==(sock_fd=socket(AF_INET, SOCK_STREAM, 0)) )
		{
			printf("creat socket wrong\n");
			break;
		}
		ser_addr.sin_family = AF_INET;
		ser_addr.sin_port = htons(atoi(argv[2]));
		ser_addr.sin_addr.s_addr = inet_addr(argv[1]);
		if( -1==(connect(sock_fd, (struct sockaddr *)&ser_addr, sizeof(ser_addr))) )
		{
			printf("connect wrong\n");
			break;
		}
		/* SSL连接 */
		ssl=SSL_new(ctx);         /* 由会话环境申请一个SSL套接字 */
		SSL_set_fd(ssl, sock_fd); /* 绑定SSL安全套接字和已连接TCP套接字 */
		if( 0>=SSL_connect(ssl) ) /* 安全套接层握手 */    //返回值为1，成功建立连接；小于等于零失败，使用SSL_get_error()找出错误原因
		{
			ERR_print_errors_fp(stderr);
			break;
		}

		printf("ssl version %s\n",SSL_get_version(ssl));
		printf("ssleay version %s\n",SSLeay_version(0));
		printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

		unsigned char buf[16];
		err = SSL_export_keying_material(ssl, buf, 16, NULL,0, NULL, 0, 1);
		PrintData("SSL_export_keying_material", (char*)buf, 16, NULL);

		/* 发送数据 */
		unsigned char session_key[16];
		RAND_bytes(session_key, sizeof(session_key));
		if((err = SSL_write(ssl, session_key, sizeof(session_key))) < 0)
			printf("error is %d\n",SSL_get_error(ssl,err));
	}while(0);

	/* 关闭SSL连接，释放SSL安全套接字资源 */
	if( NULL!=ssl )
	{
		SSL_shutdown(ssl);  //关闭一个活的TLS/SSL连接，会向对端发送"close notify"，告诉对方
		SSL_free(ssl);      //减少ssl的引用次数，如果引用次数为零，就移除ssl指向的对象、释放分配的内存；如果ssl是NULL，什么都不做
		ssl=NULL;
	}
	/* 关闭TCP连接 */
	if( -1!=sock_fd)
	{
		close(sock_fd);
		sock_fd=-1;
	}
	/* 释放SSL会话环境 */
	if( NULL!=ctx )
	{
		SSL_CTX_free(ctx);//减少ctx的引用次数，如果引用次数为零，就移除ctx指向的对象、释放分配的内存；如果ctx是NULL，什么都不做
		ctx=NULL;
	}

	return 0;
}


