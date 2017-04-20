#include <jni.h>
#include <stddef.h>
#include "openssl/rsa.h"
#include "com_cn_czj_Crypto.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "android/log.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/conf.h"
#include "openssl/obj_mac.h"
#include "openssl/aes.h"

#define TAG "myDemo-jni"


//#include "include/memory.h"
//#include "include/memory"
//using  namespace std;
//using  std::unique_ptr;
//
//
//
//using BN_ptr =std:: unique_ptr<BIGNUM, decltype(&::BN_free)>;
//using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
//using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
//using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) // 定义LOGE类型

const char *g_pPubFile = "public.pem";
const char *g_pPriFile = "private.pem";
BIO *pBio = NULL;
BIO *keybio=NULL ;
RSA *psa=NULL;
int pri_len;          // Length of private key
int pub_len;          // Length of public key
char *pri_key = NULL;           // Private key
char *pub_key = NULL;
BIO *pri = BIO_new(BIO_s_mem());
BIO *pub = BIO_new(BIO_s_mem());

int make(int keyLen);
RSA* createRSA( char* key, int flag);
//maxCodeByte = g_nBits/8-11
const int g_nBits = 1024;
JNIEXPORT jstring JNICALL
Java_com_cn_czj_Crypto_CZJ_1ECC_1GenPrivateKey(JNIEnv *env, jclass type, jint keyLen) {

    // TODO


    return    env->NewStringUTF(pub_key),env->NewStringUTF(pri_key);
}

JNIEXPORT jstring JNICALL
Java_com_cn_czj_Crypto_CZJ_1ECC_1GenPublicKey(JNIEnv *env, jclass type, jstring privateKey_) {
    const char *privateKey = env->GetStringUTFChars( privateKey_, 0);

    // TODO

    env->ReleaseStringUTFChars( privateKey_, privateKey);

    return env->NewStringUTF ("2");
}

JNIEXPORT jstring JNICALL
Java_com_cn_czj_Crypto_CZJ_1ECC_1GetPublicKey_1X(JNIEnv *env, jclass type, jstring publicKey_) {
    const char *publicKey = env->GetStringUTFChars( publicKey_, 0);

    // TODO

    env->ReleaseStringUTFChars( publicKey_, publicKey);

    return env->NewStringUTF( "3");
}

JNIEXPORT jstring JNICALL
Java_com_cn_czj_Crypto_CZJ_1ECC_1GetPublicKey_1Y(JNIEnv *env, jclass type, jstring publicKey_) {
    const char *publicKey = env->GetStringUTFChars( publicKey_, 0);

    // TODO

    env->ReleaseStringUTFChars( publicKey_, publicKey);

    return env->NewStringUTF( "4");
}

JNIEXPORT jstring JNICALL
Java_com_cn_czj_Crypto_CZJ_1ECC_1GetPublicKeyByXY(JNIEnv *env, jclass type, jstring xParam_,
                                                  jstring yParam_) {
    const char *xParam = env->GetStringUTFChars( xParam_, 0);
    const char *yParam = env->GetStringUTFChars( yParam_, 0);

    // TODO

    env->ReleaseStringUTFChars( xParam_, xParam);
    env->ReleaseStringUTFChars( yParam_, yParam);

    return env->NewStringUTF( "5");
}

JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1GeneratePEMKeys(JNIEnv *env , jclass type, jbyteArray pubKey_,
                                                 jbyteArray priKey_, jint keyLen) {


    make(1024);
    env->SetByteArrayRegion(pubKey_, 0, pub_len, (jbyte*)pub_key);
    env->SetByteArrayRegion(priKey_, 0, pri_len, (jbyte*)pri_key);
    env->ReleaseByteArrayElements( pubKey_, (jbyte*)pub_key, 0);
    env->ReleaseByteArrayElements( priKey_, (jbyte*)pri_key, 0);
    return (jint)23;
}

JNIEXPORT jstring JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1GenPublicKey(JNIEnv *env, jclass type, jstring privateKey_) {
    const char *privateKey = env->GetStringUTFChars(privateKey_, 0);




    env->ReleaseStringUTFChars( privateKey_, privateKey);

    return env->NewStringUTF( "6");
}

JNIEXPORT jstring JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1GenPrivateKey(JNIEnv *env, jclass type, jint keyLen) {

    // TODO
    make(keyLen);

    return env->NewStringUTF(pri_key);
}
/**
 * 根据公钥进行加密
 */
JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1EncryptByPublicKey(JNIEnv *env, jclass type, jbyteArray message_,
                                                    jint msgLen, jbyteArray encryptedData_,
                                                    jbyteArray pubKey_) {
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    jbyte *encryptedData = env->GetByteArrayElements( encryptedData_, NULL);
    jbyte *pubKey = env->GetByteArrayElements( pubKey_, NULL);
//    LOGE((char*)pubKey);
//    make(1024);
//    LOGE((char*)message);
    RSA *psa1=createRSA(( char*)pubKey,1);
    int outLen = RSA_public_encrypt(
            strlen((char*)message),
            reinterpret_cast<unsigned char*>(message),
            reinterpret_cast<unsigned char*>(encryptedData),
            psa1,
            RSA_PKCS1_PADDING);
    LOGE((char*)encryptedData);
    env->SetByteArrayRegion(encryptedData_, 0,  strlen((char*)encryptedData),encryptedData);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements( encryptedData_, encryptedData, 0);
    env->ReleaseByteArrayElements( pubKey_, pubKey, 0);


    return outLen;
}
/**
 * 根据私钥进行解密
 */
JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1DecryptByPrivateKey(JNIEnv *env, jclass type,
                                                     jbyteArray encryptedData_, jint dataLen,
                                                     jbyteArray message_, jbyteArray priKey_) {
    jbyte *encryptedData = env->GetByteArrayElements( encryptedData_, NULL);
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    jbyte *priKey = env->GetByteArrayElements( priKey_, NULL);
    RSA *psa2=createRSA(( char*)priKey,0);
    int outLen = RSA_private_decrypt(
            dataLen,
            reinterpret_cast<unsigned char*>(encryptedData),
            reinterpret_cast<unsigned char*>(message),
            psa2,
            RSA_PKCS1_PADDING);
    env->SetByteArrayRegion(message_, 0,  strlen((char*)message),message);
    env->ReleaseByteArrayElements( encryptedData_, encryptedData, 0);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements( priKey_, priKey, 0);

    return outLen;
}
/**
 * 根据私钥加密
 */
JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1EncryptByPrivateKey(JNIEnv *env, jclass type, jbyteArray message_,
                                                     jint msgLen, jbyteArray encryptedData_,
                                                     jbyteArray priKey_) {
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    jbyte *encryptedData = env->GetByteArrayElements( encryptedData_, NULL);
    jbyte *priKey =env->GetByteArrayElements( priKey_, NULL);

    RSA *psa=createRSA(( char*)priKey,0);
    int outLen = RSA_private_encrypt(
            msgLen,
            reinterpret_cast<unsigned char*>(message),
            reinterpret_cast<unsigned char*>(encryptedData),
            psa,
            RSA_PKCS1_PADDING);
    env->SetByteArrayRegion(encryptedData_, 0,  strlen((char*)encryptedData),encryptedData);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements( encryptedData_, encryptedData, 0);
    env->ReleaseByteArrayElements(priKey_, priKey, 0);
}
/**
 * 根据公钥解密
 */
JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1DecryptByPublicKey(JNIEnv *env, jclass type,
                                                    jbyteArray encryptedData_, jint dataLen,
                                                    jbyteArray message_, jbyteArray pubKey_) {
    jbyte *encryptedData = env->GetByteArrayElements( encryptedData_, NULL);
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    jbyte *pubKey = env->GetByteArrayElements( pubKey_, NULL);

    RSA *psa=createRSA(( char*)pubKey,1);
    int outLen = RSA_public_decrypt(
            dataLen,
            reinterpret_cast<unsigned char*>(encryptedData),
            reinterpret_cast<unsigned char*>(message),
            psa,
            RSA_PKCS1_PADDING);
    env->SetByteArrayRegion(message_, 0,  strlen((char*)message),message);
    env->ReleaseByteArrayElements( encryptedData_, encryptedData, 0);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements( pubKey_, pubKey, 0);
}
/**
 * 签名
 */
JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1SignByPrivateKey(JNIEnv *env, jclass type, jbyteArray message_,
                                                  jint msgLen, jbyteArray signedData_,
                                                  jbyteArray priKey_) {
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    jbyte *signedData = env->GetByteArrayElements( signedData_, NULL);
    jbyte *priKey = env->GetByteArrayElements(priKey_, NULL);
    RSA *rsa=createRSA((char*)priKey,0);
    int result=RSA_sign((int)SN_sha1,(const unsigned char *)message,strlen((char*)message),( unsigned char *)signedData,(unsigned int *)(strlen((char*)signedData)),rsa);
    env->SetByteArrayRegion(message_, 0,  strlen((char*)message),message);
    env->SetByteArrayRegion(signedData_, 0,  strlen((char*)signedData),signedData);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements( signedData_, signedData, 0);
    env->ReleaseByteArrayElements( priKey_, priKey, 0);
    return  result;
}
/**
 * 认证公钥
 */
JNIEXPORT jboolean JNICALL
Java_com_cn_czj_Crypto_CZJ_1RSA_1VerifyByPublicKey(JNIEnv *env, jclass type, jbyteArray message_,
                                                   jint msgLen, jbyteArray signedData_,
                                                   jbyteArray pubKey_) {
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    jbyte *signedData = env->GetByteArrayElements( signedData_, NULL);
    jbyte *pubKey = env->GetByteArrayElements( pubKey_, NULL);
    RSA *rsa=createRSA((char*)pubKey,1);
    int result=RSA_verify((int)SN_sha1,(const unsigned char *)message,strlen((char*)message),( unsigned char *)signedData,(int)(strlen((char*)signedData)),rsa);
    env->SetByteArrayRegion(message_, 0,  strlen((char*)message),message);
    env->SetByteArrayRegion(signedData_, 0,  strlen((char*)signedData),signedData);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements( signedData_, signedData, 0);
    env->ReleaseByteArrayElements( pubKey_, pubKey, 0);

    return true;
}

JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1SHA1_1Hash(JNIEnv *env, jclass type, jbyteArray message_, jint msgLen,
                                       jbyteArray digestData_) {
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    jbyte *digestData = env->GetByteArrayElements( digestData_, NULL);

    // TODO
    SHA1((const unsigned char *)message,msgLen,(unsigned char *)digestData);
    env->SetByteArrayRegion(digestData_, 0,  strlen((char*)digestData),digestData);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements(digestData_, digestData, 0);
}
/**
 * sha 256
 */
JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1SHA256_1Hash(JNIEnv *env, jclass type, jbyteArray message_, jint msgLen,
                                         jbyteArray digestData_) {
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    jbyte *digestData = env->GetByteArrayElements( digestData_, NULL);

    SHA256((const unsigned char *)message,msgLen,(unsigned char *)digestData);
    env->SetByteArrayRegion(digestData_, 0,  strlen((char*)digestData),digestData);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements( digestData_, digestData, 0);
}

JNIEXPORT jstring JNICALL
Java_com_cn_czj_Crypto_CZJ_1AES_1GenerateKey(JNIEnv *env, jclass type, jint keyLen) {

    // TODO
    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    //Generate own AES Key
    for(int iLoop = 0; iLoop < 16; iLoop++)
    {
        key[iLoop] = 32 + iLoop;
    }
    // Set encryption key
    for (int iLoop=0; iLoop<AES_BLOCK_SIZE; iLoop++)
    {
        iv[iLoop] = 0;
    }
    return env->NewStringUTF( (char*)key);
}

JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1AES_1EncryptByKey(JNIEnv *env, jclass type, jbyteArray message_,
                                              jint msgLen, jbyteArray encryptedData_, jstring key_,
                                              jint mode) {
    jbyte *message = env->GetByteArrayElements(message_, NULL);
    jbyte *encryptedData = env->GetByteArrayElements( encryptedData_, NULL);
    const char *key = env->GetStringUTFChars(key_, 0);

    // TODO
    void AES_encrypt(const unsigned char *in, unsigned char *out,
                     const AES_KEY *key);

    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseByteArrayElements(encryptedData_, encryptedData, 0);
    env->ReleaseStringUTFChars( key_, key);
}

JNIEXPORT jint JNICALL
Java_com_cn_czj_Crypto_CZJ_1AES_1DecryptByKey(JNIEnv *env, jclass type, jbyteArray encryptedData_,
                                              jint dataLen, jbyteArray message_, jstring key_,
                                              jint mode) {
    jbyte *encryptedData = env->GetByteArrayElements( encryptedData_, NULL);
    jbyte *message = env->GetByteArrayElements( message_, NULL);
    const char *key = env->GetStringUTFChars( key_, 0);

    // TODO
    void AES_decrypt(const unsigned char *in, unsigned char *out,
                     const AES_KEY *key);
    env->ReleaseByteArrayElements( encryptedData_, encryptedData, 0);
    env->ReleaseByteArrayElements( message_, message, 0);
    env->ReleaseStringUTFChars( key_, key);
}

JNIEXPORT jbyteArray JNICALL
Java_com_cn_czj_Crypto_hmacSha256(JNIEnv *env, jobject instance, jbyteArray data_) {
//    jbyte *data = env->GetByteArrayElements(data_, NULL);
//
//    // TODO
//
//    env->ReleaseByteArrayElements(data_, data, 0);
    unsigned char key[] = {0x6B, 0x65, 0x79};

    unsigned int result_len;
    unsigned char result[EVP_MAX_MD_SIZE];

    // get data from java array
    jbyte *data = env->GetByteArrayElements(data_, NULL);
    size_t dataLength = env->GetArrayLength(data_);

    HMAC(EVP_sha256(),
         key, 3,
         (unsigned char *) data, dataLength,
         result, &result_len);

    // release the array
    env->ReleaseByteArrayElements(data_, data, JNI_ABORT);

    // the return value
    jbyteArray return_val = env->NewByteArray(result_len);
    env->SetByteArrayRegion(return_val, 0, result_len, (jbyte *) result);
    LOGE("成功");
    return return_val;

}

RSA* createRSA(char* key, int flag)
{
    RSA *rsa= NULL;
    keybio = BIO_new_mem_buf(key, -1);

    if (keybio==NULL) {

        LOGE("Failed to create key BIO");
        return 0;
    }
//    int	BIO_write(BIO *b, const void *data, int len);
//    rsa= PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL,NULL);
    if(flag==1){
        rsa= PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL,NULL);
    }else{
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if(rsa == NULL){
        LOGE("Failed to create RSA");
    }else{
        LOGE("终于不为空了吼吼吼吼吼吼吼吼吼");
    }


    return rsa;
}
int make(int keyLen){
    int rc=0;
    psa=RSA_new();
    BIGNUM *bignum=NULL;
    bignum=BN_new();
    rc = BN_set_word(bignum, RSA_F4);
    rc = RSA_generate_key_ex(psa, keyLen, bignum, NULL);

    pBio= BIO_new_file(g_pPubFile,"wb");


    PEM_write_bio_RSAPrivateKey(pri, psa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, psa);
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = new char[pri_len + 1];
    pub_key = new char[pub_len + 1];
    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    LOGE(pub_key);
    LOGE(pri_key);
    return  0;
}