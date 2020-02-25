#ifndef _SDF_ENGINE_H_
#define _SDF_ENGINE_H_
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define  DLL_API _declspec(dllexport)
#else
#define DLL_API
#endif

	#define JMJ_SWXA_ENGINE 1
	#define JMK_SWXA_ENGINE 2
	#define UKEY_SWXA_ENGINE 3
	#define SD_SWXA_ENGINE 6

	DLL_API void ENGINE_load_swxa(void);
	DLL_API int ENGINE_load_log(int level);

	DLL_API const EVP_CIPHER *EVP_3des_cbc(void);
	DLL_API const EVP_CIPHER *EVP_3des_ecb(void);

	DLL_API const EVP_CIPHER *EVP_aes_cbc(void);
	DLL_API const EVP_CIPHER *EVP_aes_ecb(void);

	DLL_API const EVP_CIPHER *EVP_sm1_cbc(void);
	DLL_API const EVP_CIPHER *EVP_sm1_ecb(void);

	DLL_API const EVP_CIPHER *EVP_sm4_cbc(void);
	DLL_API const EVP_CIPHER *EVP_sm4_ecb(void);

	DLL_API const EVP_MD *EVP_sm3(void);

	DLL_API const RAND_METHOD *RAND_swxa(void);

	DLL_API int swxa_generate_ecc_key(EC_KEY *ecc);

	DLL_API int swxa_GenerateAgreementDataWithECC(unsigned char *pSponsorID,int *piSponsorIDLen,EC_KEY **ppTmpPubSponsor,EC_KEY **ppPubSponsor,void **phAgree);
	DLL_API int swxa_GenerateAgreementDataAndKeyWithECC(unsigned char *pSponsorID,int iSponsorIDLen,EC_KEY *pPubSponsor,EC_KEY *pTmpPubSponsor,
														unsigned char *pResID,int *piResIDLen,EC_KEY **ppTmpPubRes,EC_KEY **ppPubRes,void **phSymKey);
	DLL_API int swxa_GenerateKeyWithECC(unsigned char *pResID,int iResIDLen,EC_KEY *pPubRes,EC_KEY *pTmpPubRes,void **hAgree,void **phSymKey);
	DLL_API int swxa_CloseHandle_sm2_2(void **hSymKey,int flag);

	DLL_API int swxa_GetCertFromUKEY(int iCertType,char *pCert,int *piCertLen);

#ifdef __cplusplus
}
#endif
#endif
