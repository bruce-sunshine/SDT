#ifndef __SKF_H__
#define __SKF_H__ 1


#ifdef  __cplusplus
extern "C" {
#endif

#ifdef WIN32
#pragma pack(push, 1)
#endif


/* 分组密码算法标识 */

/* SM1算法ECB加密模式 */
#define SGD_SM1_ECB 0x00000101

/* SM1算法CBC加密模式 */
#define SGD_SM1_CBC 0x00000102

/* SSF33算法ECB加密模式 */
#define SGD_SSF33_ECB 0x00000201

/* SSF33算法CBC加密模式 */
#define SGD_SSF33_CBC 0x00000202

/* SMS4算法ECB加密模式 */
#define SGD_SMS4_ECB 0x00000401

/* SMS4算法CBC加密模式 */
#define SGD_SMS4_CBC 0x00000402


/* 非对称密码算法标识 */

/* RSA算法 */
#define SGD_RSA    0x00010000

#define SGD_SM2_1  0x00020100


/* 密码杂凑算法标识 */

/* SM3密码杂凑算法 */
#define SGD_SM3     0x00000001

#define SGD_SHA1    0x00000002

#define SGD_SHA256  0x00000004


/* 基本数据类型 */

/* 布尔类型，取值为TRUE或FALSE */
typedef int BOOL;


/* 字节类型，无符号8位整数 */
typedef unsigned char BYTE;

typedef char CHAR;

typedef unsigned long ULONG;

typedef unsigned long DWORD;

typedef char *LPSTR;

/* 句柄，指向任意数据对象的起始地址 */
typedef void * HANDLE;

/* 设备句柄 */
typedef HANDLE DEVHANDLE;

/* 应用句柄 */
typedef HANDLE HAPPLICATION;

/* 容器句柄 */
typedef HANDLE HCONTAINER;


/* 常量定义 */

#ifndef TRUE
#define TRUE 0x00000001
#endif

#ifndef FALSE
#define FALSE 0x00000000
#endif

/* 管理员PIN类型 */
#define ADMIN_TYPE 0

/* 用户PIN类型 */
#define USER_TYPE  1




/* 成功 */
#define SAR_OK                  0x00000000

/* 失败 */
#define SAR_FAIL                0x0A000001

#define SAR_UNKNOWNERR          0x0A000002

/* 无效的参数 */
#define SAR_INVALIDPARAMERR     0x0A000006

/* PIN不正确 */
#define SAR_PIN_INCORRECT       0x0A000024

/* 用户没有登录 */
#define SAR_USER_NOT_LOGGED_IN  0x0A00002D

/* 文件已经存在 */
#define SAR_FILE_ALREADY_EXIST  0x0A00002F



/* 版本 */
typedef struct Struct_Version {
  BYTE major;
  BYTE minor;
} VERSION;

/* 设备信息 */
typedef struct Struct_DEVINFO {
  VERSION       Version;
  CHAR          Manufacturer[64];
  CHAR          Issuer[64];
  CHAR			Label[32];
  CHAR			SerialNumber[32];
  VERSION       HWVersion;
  VERSION       FirmwareVersion;
  ULONG         AlgSymCap;
  ULONG         AlgAsymCap;
  ULONG         AlgHashCap;
  ULONG         DevAuthAlgId;
  ULONG         TotalSpace;
  ULONG         FreeSpace;
  BYTE          Reserved[64];
} DEVINFO, *PDEVINFO;

/* RSA公钥数据结构 */
#define MAX_RSA_MODULUS_LEN 256
#define MAX_RSA_EXPONENT_LEN 4
typedef struct Struct_RSAPUBLICKEYBLOB {
  ULONG AlgID;
  ULONG BitLen;
  BYTE  Modulus[MAX_RSA_MODULUS_LEN];
  BYTE  PublicExponent[MAX_RSA_EXPONENT_LEN];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

/* RSA私钥数据结构 */
typedef struct Struct_RSAPRIVATEKEYBLOB {
  ULONG AlgID;
  ULONG BitLen;
  BYTE  Modulus[MAX_RSA_MODULUS_LEN];
  BYTE  PublicExponent[MAX_RSA_EXPONENT_LEN];
  BYTE  PrivateExponent[MAX_RSA_MODULUS_LEN];
  BYTE  Prime1[MAX_RSA_MODULUS_LEN/2];
  BYTE  Prime2[MAX_RSA_MODULUS_LEN/2];
  BYTE  Prime1Exponent[MAX_RSA_MODULUS_LEN/2];
  BYTE  Prime2Exponent[MAX_RSA_MODULUS_LEN/2];
  BYTE  Coefficient[MAX_RSA_MODULUS_LEN/2];
} RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

/* ECC公钥数据结构 */
#define ECC_MAX_XCOORDINATE_BITS_LEN 512
#define ECC_MAX_YCOORDINATE_BITS_LEN 512
typedef struct Struct_ECCPUBLICKEYBLOB {
  ULONG BitLen;
  BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
  BYTE  YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

/* ECC私钥数据结构 */
#define ECC_MAX_MODULUS_BITS_LEN 512
typedef struct Struct_ECCPRIVATEKEYBLOB {
  ULONG BitLen;
  BYTE  PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];
} ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

/* ECC密文数据结构 */
typedef struct Struct_ECCCIPHERBLOB {
  BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
  BYTE  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
  BYTE  HASH[32]; 
  ULONG CipherLen;
  BYTE  Cipher[1]; 
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

/* ECC签名数据结构 */
typedef struct Struct_ECCSIGNATUREBLOB {
  BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
  BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

/* 分组密码参数 */
#define MAX_IV_LEN 32
typedef struct Struct_BLOCKCIPHERPARAM {
  BYTE  IV[MAX_IV_LEN];
  ULONG IVLen;
  ULONG PaddingType;
  ULONG FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

/* ECC加密密钥对保护结构 */
typedef struct SKF_ENVELOPEDKEYBLOB {
  ULONG Version;                  /* 当前版本为 1 */
  ULONG ulSymmAlgID;              /* 对称算法标识，限定ECB模式 */
  ULONG ulBits;                   /* 加密密钥对的密钥位长度 */
  BYTE cbEncryptedPriKey[64];     /* 加密密钥对私钥的密文 */
  ECCPUBLICKEYBLOB PubKey;        /* 加密密钥对的公钥 */
  ECCCIPHERBLOB ECCCipherBlob;    /* 用保护公钥加密的对称密钥密文 */
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

/* 文件属性 */
typedef struct Struct_FILEATTRIBUTE {
  CHAR  FileName[32];
  ULONG FileSize;
  ULONG ReadRights;
  ULONG WriteRights; 
} FILEATTRIBUTE, *PFILEATTRIBUTE;


/* 设备状态 */

/* 设备不存在 */
#define DEV_ABSENT_STATE   0x00000000

/* 设备存在 */
#define DEV_PRESENT_STATE  0x00000001


#ifdef WIN32
#pragma pack(pop)
#endif


#ifdef WIN32
#define SKF_API_FUNCTION( return_type, function_name )	\
  return_type __stdcall function_name
#else /* not WIN32 */
#define SKF_API_FUNCTION( return_type, function_name )	\
  return_type function_name
#endif /* not WIN32 */


/* 等待设备插拔事件 */
SKF_API_FUNCTION (ULONG, SKF_WaitForDevEvent) (LPSTR szDevName,
					       ULONG *pulDevNameLen,
					       ULONG *pulEvent);

/* 取消等待设备插拔事件 */
SKF_API_FUNCTION (ULONG, SKF_CancelWaitForDevEvent) (void);

/* 枚举设备 */
SKF_API_FUNCTION (ULONG, SKF_EnumDev) (BOOL bPresent,
				       LPSTR szNameList, ULONG *pulSize);

/* 连接设备*/
SKF_API_FUNCTION (ULONG, SKF_ConnectDev) (LPSTR szName, DEVHANDLE *phDev);

/* 断开连接 */
SKF_API_FUNCTION (ULONG, SKF_DisConnectDev) (DEVHANDLE hDev);

/* 获取设备状态 */
SKF_API_FUNCTION (ULONG, SKF_GetDevState) (LPSTR szDevName, ULONG *pulDevState);

/* 设置设备标签 */
SKF_API_FUNCTION (ULONG, SKF_SetLabel) (DEVHANDLE hDev, LPSTR szLabel);

/* 获取设备信息 */
SKF_API_FUNCTION (ULONG, SKF_GetDevInfo) (DEVHANDLE hDev, DEVINFO *pDevInfo);

/* 锁定设备 */
SKF_API_FUNCTION (ULONG, SKF_LockDev) (DEVHANDLE hDev, ULONG ulTimeOut);

/* 解锁设备 */
SKF_API_FUNCTION (ULONG, SKF_UnlockDev) (DEVHANDLE hDev);

/* 设备命令传输 */
SKF_API_FUNCTION (ULONG, SKF_Transmit) (DEVHANDLE hDev,
					BYTE* pbCommand, ULONG ulCommandLen,
					BYTE* pbData, ULONG* pulDataLen);


/* 修改设备认证密钥 */
SKF_API_FUNCTION (ULONG, SKF_ChangeDevAuthKey) (DEVHANDLE hDev,
						BYTE *pbKeyValue,
						ULONG ulKeyLen);

/* 设备认证 */
SKF_API_FUNCTION (ULONG, SKF_DevAuth) (DEVHANDLE hDev,
				       BYTE *pbAuthData, ULONG ulLen);

/* 修改PIN */
SKF_API_FUNCTION (ULONG, SKF_ChangePIN) (HAPPLICATION hApplication,
					 ULONG ulPINType,
					 LPSTR szOldPin,
					 LPSTR szNewPin,
					 ULONG *pulRetryCount);

/* 获取PIN信息 */
SKF_API_FUNCTION (ULONG, SKF_GetPINInfo) (HAPPLICATION hApplication,
					  ULONG  ulPINType,
					  ULONG *pulMaxRetryCount,
					  ULONG *pulRemainRetryCount,
					  BOOL *pbDefaultPin);

/* 校验PIN */
SKF_API_FUNCTION (ULONG, SKF_VerifyPIN) (HAPPLICATION hApplication,
					 ULONG ulPINType,
					 LPSTR szPIN,
					 ULONG *pulRetryCount);

/* 解锁PIN */
SKF_API_FUNCTION (ULONG, SKF_UnblockPIN) (HAPPLICATION hApplication,
					  LPSTR szAdminPIN,
					  LPSTR szNewUserPIN,
					  ULONG *pulRetryCount);

/* 清除应用安全状态 */
SKF_API_FUNCTION (ULONG, SKF_ClearSecureState) (HAPPLICATION hApplication);


/* 创建应用 */
SKF_API_FUNCTION (ULONG, SKF_CreateApplication) (DEVHANDLE hDev,
						 LPSTR szAppName,
						 LPSTR szAdminPin,
						 DWORD dwAdminPinRetryCount,
						 LPSTR szUserPin,
						 DWORD dwUserPinRetryCount,
						 DWORD dwCreateFileRights,
						 HAPPLICATION *phApplication);

/* 枚举应用 */
SKF_API_FUNCTION (ULONG, SKF_EnumApplication) (DEVHANDLE hDev,
					       LPSTR szAppName,
					       ULONG *pulSize);

/* 删除应用 */
SKF_API_FUNCTION (ULONG, SKF_DeleteApplication) (DEVHANDLE hDev,
						 LPSTR szAppName);

/* 打开应用 */
SKF_API_FUNCTION (ULONG, SKF_OpenApplication) (DEVHANDLE hDev,
					       LPSTR szAppName,
					       HAPPLICATION *phApplication);

/* 关闭应用 */
SKF_API_FUNCTION (ULONG, SKF_CloseApplication) (HAPPLICATION hApplication);


/* 创建文件 */
SKF_API_FUNCTION (ULONG, SKF_CreateFile) (HAPPLICATION hApplication,
					  LPSTR szFileName,
					  ULONG ulFileSize,
					  ULONG ulReadRights,
					  ULONG ulWriteRights);

/* 删除文件 */
SKF_API_FUNCTION (ULONG, SKF_DeleteFile) (HAPPLICATION hApplication,
					  LPSTR szFileName);

/* 枚举文件 */
SKF_API_FUNCTION (ULONG, SKF_EnumFiles) (HAPPLICATION hApplication,
					 LPSTR szFileList, ULONG *pulSize);

/* 获取文件属性 */
SKF_API_FUNCTION (ULONG, SKF_GetFileInfo) (HAPPLICATION hApplication,
					   LPSTR szFileName,
					   FILEATTRIBUTE *pFileInfo);

/* 读文件 */
SKF_API_FUNCTION (ULONG, SKF_ReadFile) (HAPPLICATION hApplication,
					LPSTR szFileName,
					ULONG ulOffset,
					ULONG ulSize,
					BYTE *pbOutData,
					ULONG *pulOutLen);

/* 写文件 */
SKF_API_FUNCTION (ULONG, SKF_WriteFile) (HAPPLICATION hApplication,
					 LPSTR szFileName,
					 ULONG  ulOffset,
					 BYTE *pbData,
					 ULONG ulSize);


/* 创建容器 */
SKF_API_FUNCTION (ULONG, SKF_CreateContainer) (HAPPLICATION hApplication,
					       LPSTR szContainerName,
					       HCONTAINER *phContainer);

/* 删除容器 */
SKF_API_FUNCTION (ULONG, SKF_DeleteContainer) (HAPPLICATION hApplication,
					       LPSTR szContainerName);

/* 打开容器 */
SKF_API_FUNCTION (ULONG, SKF_OpenContainer) (HAPPLICATION hApplication,
					     LPSTR szContainerName,
					     HCONTAINER *phContainer);

/* 关闭容器 */
SKF_API_FUNCTION (ULONG, SKF_CloseContainer) (HCONTAINER hContainer);

/* 枚举容器 */
SKF_API_FUNCTION (ULONG, SKF_EnumContainer) (HAPPLICATION hApplication,
					     LPSTR szContainerName,
					     ULONG *pulSize);

/* 获得容器类型 */
SKF_API_FUNCTION (ULONG, SKF_GetContainerType) (HCONTAINER hContainer,
						ULONG *pulContainerType);
SKF_API_FUNCTION (ULONG, SKF_GetContianerType) (HCONTAINER hContainer,
						ULONG *pulContainerType);

/* 导入数字证书 */
SKF_API_FUNCTION (ULONG, SKF_ImportCertificate) (HCONTAINER hContainer,
						 BOOL bSignFlag,
						 BYTE *pbCert,
						 ULONG ulCertLen);

/* 导出数字证书 */
SKF_API_FUNCTION (ULONG, SKF_ExportCertificate) (HCONTAINER hContainer,
						 BOOL bSignFlag,
						 BYTE *pbCert,
						 ULONG *pulCertLen);

/* 生成随机数 */
SKF_API_FUNCTION (ULONG, SKF_GenRandom) (DEVHANDLE hDev,
					 BYTE *pbRandom, ULONG ulRandomLen);

/* 生成外部RSA密钥对 */
SKF_API_FUNCTION (ULONG, SKF_GenExtRSAKey) (DEVHANDLE hDev,
					    ULONG ulBitsLen,
					    RSAPRIVATEKEYBLOB *pBlob);

/* 生成RSA签名密钥对 */
SKF_API_FUNCTION (ULONG, SKF_GenRSAKeyPair) (HCONTAINER hContainer,
					     ULONG ulBitsLen,
					     RSAPUBLICKEYBLOB *pBlob);

/* 导入RSA加密密钥对 */
SKF_API_FUNCTION (ULONG, SKF_ImportRSAKeyPair) (HCONTAINER hContainer,
						ULONG ulSymAlgId, 
						BYTE *pbWrappedKey,
						ULONG ulWrappedKeyLen,
						BYTE *pbEncryptedData,
						ULONG ulEncryptedDataLen);

/* RSA签名 */
SKF_API_FUNCTION (ULONG, SKF_RSASignData) (HCONTAINER hContainer,
					   BYTE *pbData,
					   ULONG ulDataLen,
					   BYTE *pbSignature,
					   ULONG *pulSignLen);

/* RSA验签 */
SKF_API_FUNCTION (ULONG, SKF_RSAVerify) (DEVHANDLE hDev,
					 RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
					 BYTE *pbData,
					 ULONG ulDataLen,
					 BYTE *pbSignature,
					 ULONG ulSignLen);

/* RSA生成并导出会话密钥 */
SKF_API_FUNCTION (ULONG, SKF_RSAExportSessionKey) (HCONTAINER hContainer,
						   ULONG ulAlgId,
						   RSAPUBLICKEYBLOB *pPubKey,
						   BYTE *pbData,
						   ULONG  *pulDataLen,
						   HANDLE *phSessionKey);

/* RSA外来公钥运算 */
SKF_API_FUNCTION (ULONG, SKF_ExtRSAPubKeyOperation)
(DEVHANDLE hDev,
 RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
 BYTE* pbInput,
 ULONG ulInputLen,
 BYTE* pbOutput,
 ULONG* pulOutputLen);

/* RSA外来私钥运算 */
SKF_API_FUNCTION (ULONG, SKF_ExtRSAPriKeyOperation)
(DEVHANDLE hDev,
 RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,
 BYTE* pbInput,
 ULONG ulInputLen,
 BYTE* pbOutput,
 ULONG* pulOutputLen);

/* 生成ECC签名密钥对 */
SKF_API_FUNCTION (ULONG, SKF_GenECCKeyPair) (HCONTAINER hContainer,
					     ULONG ulAlgId,
					     ECCPUBLICKEYBLOB *pBlob);

/* 导入ECC加密密钥对 */
SKF_API_FUNCTION (ULONG, SKF_ImportECCKeyPair)
(HCONTAINER hContainer,
 PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

/* ECC签名 */
SKF_API_FUNCTION (ULONG, SKF_ECCSignData) (HCONTAINER hContainer,
					   BYTE *pbData, ULONG ulDataLen,
					   PECCSIGNATUREBLOB pSignature);

/* ECC验签 */
SKF_API_FUNCTION (ULONG, SKF_ECCVerify) (DEVHANDLE hDev,
					 ECCPUBLICKEYBLOB *pECCPubKeyBlob,
					 BYTE *pbData, ULONG ulDataLen,
					 PECCSIGNATUREBLOB pSignature);

/* ECC生成并导出会话密钥 */
SKF_API_FUNCTION (ULONG, SKF_ECCExportSessionKey) (HCONTAINER hContainer,
						   ULONG ulAlgId,
						   ECCPUBLICKEYBLOB *pPubKey,
						   PECCCIPHERBLOB pData,
						   HANDLE *phSessionKey);

/* ECC外来公钥加密 */
SKF_API_FUNCTION (ULONG, SKF_ExtECCEncrypt) (DEVHANDLE hDev,
					     ECCPUBLICKEYBLOB* pECCPubKeyBlob,
					     BYTE* pbPlainText,
					     ULONG ulPlainTextLen,
					     PECCCIPHERBLOB pCipherText);

/* ECC外来私钥解密 */
SKF_API_FUNCTION (ULONG, SKF_ExtECCDecrypt) (DEVHANDLE hDev,
					     ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
					     PECCCIPHERBLOB pCipherText,
					     BYTE* pbPlainText,
					     ULONG* pulPlainTextLen);

/* ECC外来私钥签名 */
SKF_API_FUNCTION (ULONG, SKF_ExtECCSign) (DEVHANDLE hDev,
					  ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
					  BYTE* pbData,
					  ULONG ulDataLen,
					  PECCSIGNATUREBLOB pSignature);

/* ECC外来公钥验签 */
SKF_API_FUNCTION (ULONG, SKF_ExtECCVerify) (DEVHANDLE hDev,
					    ECCPUBLICKEYBLOB* pECCPubKeyBlob,
					    BYTE* pbData,
					    ULONG ulDataLen,
					    PECCSIGNATUREBLOB pSignature);

/* ECC生成密钥协商参数并输出 */
SKF_API_FUNCTION (ULONG, SKF_GenerateAgreementDataWithECC)
(HCONTAINER hContainer,
 ULONG ulAlgId,ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
 BYTE* pbID,
 ULONG ulIDLen,
 HANDLE *phAgreementHandle);

/* ECC产生协商数据并计算会话密钥 */
SKF_API_FUNCTION (ULONG, SKF_GenerateAgreementDataAndKeyWithECC)
(HANDLE hContainer, ULONG ulAlgId,
 ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,
 ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,
 ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
 BYTE *pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
 HANDLE *phKeyHandle);

/* ECC计算会话密钥 */
SKF_API_FUNCTION (ULONG, SKF_GenerateKeyWithECC)
(HANDLE hAgreementHandle,
 ECCPUBLICKEYBLOB *pECCPubKeyBlob,
 ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
 BYTE *pbID, ULONG ulIDLen, HANDLE *phKeyHandle);

/* 导出公钥 */
SKF_API_FUNCTION (ULONG, SKF_ExportPublicKey) (HCONTAINER hContainer,
					       BOOL bSignFlag,
					       BYTE *pbBlob,
					       ULONG *pulBlobLen);

/* 导入会话密钥 */
SKF_API_FUNCTION (ULONG, SKF_ImportSessionKey) (HCONTAINER hContainer,
						ULONG ulAlgId,
						BYTE *pbWrapedData,
						ULONG ulWrapedLen,
						HANDLE *phKey);

/* 明文导入会话密钥 */
SKF_API_FUNCTION (ULONG, SKF_SetSymmKey) (DEVHANDLE hDev,
					  BYTE *pbKey,
					  ULONG ulAlgID,
					  HANDLE *phKey);

/* 加密初始化 */
SKF_API_FUNCTION (ULONG, SKF_EncryptInit) (HANDLE hKey,
					   BLOCKCIPHERPARAM EncryptParam);

/* 单组数据加密 */
SKF_API_FUNCTION (ULONG, SKF_Encrypt) (HANDLE hKey,
				       BYTE *pbData,
				       ULONG ulDataLen,
				       BYTE *pbEncryptedData,
				       ULONG *pulEncryptedLen);

/* 多组数据加密 */
SKF_API_FUNCTION (ULONG, SKF_EncryptUpdate) (HANDLE hKey,
					     BYTE *pbData,
					     ULONG ulDataLen,
					     BYTE *pbEncryptedData,
					     ULONG *pulEncryptedLen);

/* 结束加密 */
SKF_API_FUNCTION (ULONG, SKF_EncryptFinal) (HANDLE hKey,
					    BYTE *pbEncryptedData,
					    ULONG *ulEncryptedDataLen);

/* 解密初始化 */
SKF_API_FUNCTION (ULONG, SKF_DecryptInit) (HANDLE hKey,
					   BLOCKCIPHERPARAM DecryptParam);

/* 单组数据解密 */
SKF_API_FUNCTION (ULONG, SKF_Decrypt) (HANDLE hKey,
				       BYTE *pbEncryptedData,
				       ULONG ulEncryptedLen,
				       BYTE *pbData,
				       ULONG *pulDataLen);

/* 多组数据解密 */
SKF_API_FUNCTION (ULONG, SKF_DecryptUpdate) (HANDLE hKey,
					     BYTE *pbEncryptedData,
					     ULONG ulEncryptedLen,
					     BYTE *pbData,
					     ULONG *pulDataLen);

/* 结束解密 */
SKF_API_FUNCTION (ULONG, SKF_DecryptFinal) (HANDLE hKey,
					    BYTE *pbDecryptedData,
					    ULONG *pulDecryptedDataLen);

/* 密码杂凑初始化 */
SKF_API_FUNCTION (ULONG, SKF_DigestInit) (DEVHANDLE hDev,
					  ULONG ulAlgID,
					  ECCPUBLICKEYBLOB *pPubKey,
					  unsigned char *pucID,
					  ULONG ulIDLen,
					  HANDLE *phHash);

/* 单组数据密码杂凑 */
SKF_API_FUNCTION (ULONG, SKF_Digest) (HANDLE hHash,
				      BYTE *pbData,
				      ULONG ulDataLen,
				      BYTE *pbHashData,
				      ULONG *pulHashLen);

/* 多组数据密码杂凑 */
SKF_API_FUNCTION (ULONG, SKF_DigestUpdate) (HANDLE hHash,
					    BYTE *pbData,
					    ULONG ulDataLen);

/* 结束密码杂凑 */
SKF_API_FUNCTION (ULONG, SKF_DigestFinal) (HANDLE hHash,
					   BYTE *pHashData,
					   ULONG *pulHashLen);

/* 消息鉴别码运算初始化 */
SKF_API_FUNCTION (ULONG, SKF_MacInit) (HANDLE hKey,
				       BLOCKCIPHERPARAM* pMacParam,
				       HANDLE *phMac);

/* 单组数据消息鉴别码运算 */
SKF_API_FUNCTION (ULONG, SKF_Mac) (HANDLE hMac,
				   BYTE* pbData, ULONG ulDataLen,
				   BYTE *pbMacData, ULONG *pulMacLen);

/* 多组数据消息鉴别码运算 */
SKF_API_FUNCTION (ULONG, SKF_MacUpdate) (HANDLE hMac,
					 BYTE * pbData, ULONG ulDataLen);

/* 结束消息鉴别码运算 */
SKF_API_FUNCTION (ULONG, SKF_MacFinal) (HANDLE hMac,
					BYTE *pbMacData, ULONG *pulMacDataLen);

/* 关闭密码对象句柄 */
SKF_API_FUNCTION (ULONG, SKF_CloseHandle) (HANDLE hHandle);


#ifdef  __cplusplus
}
#endif

#endif /* not __SKF_H__ */
