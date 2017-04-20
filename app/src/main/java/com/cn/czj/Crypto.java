package com.cn.czj;

public class Crypto {
	public native  static byte[] hmacSha256(byte[] data);
	public native static String CZJ_ECC_GenPrivateKey(int keyLen);
	public native static String CZJ_ECC_GenPublicKey(String privateKey);
	public native static String CZJ_ECC_GetPublicKey_X(String publicKey);
	public native static String CZJ_ECC_GetPublicKey_Y(String publicKey);
	public native static String CZJ_ECC_GetPublicKeyByXY(String xParam, String yParam);
	public native static  int CZJ_RSA_GeneratePEMKeys(byte[] pubKey,
			byte[] priKey,int keyLen);
	public native static String CZJ_RSA_GenPublicKey(String privateKey);
	public native static String CZJ_RSA_GenPrivateKey(int keyLen);
	public native static int CZJ_RSA_EncryptByPublicKey(byte[] message, int msgLen, byte[] encryptedData,
			byte[] pubKey);
	public native static int CZJ_RSA_DecryptByPrivateKey(byte[] encryptedData,
			int dataLen, byte[] message, byte[] priKey);
	public native static int CZJ_RSA_EncryptByPrivateKey(byte[] message, int msgLen,
			byte[] encryptedData, byte[] priKey);
	public native static int CZJ_RSA_DecryptByPublicKey(byte[] encryptedData,
			int dataLen, byte[] message, byte[] pubKey);
	public native static int CZJ_RSA_SignByPrivateKey(byte[] message,
			int msgLen, byte[] signedData, byte[] priKey);
	public native static boolean CZJ_RSA_VerifyByPublicKey(byte[] message, 
			int msgLen, byte[] signedData, byte[] pubKey);
	public native static int CZJ_SHA1_Hash(byte[] message,
			int msgLen, byte[] digestData);
	public native static int CZJ_SHA256_Hash(byte[] message,
			int msgLen, byte[] digestData);
	public native static String CZJ_AES_GenerateKey(int keyLen);
	public native static int CZJ_AES_EncryptByKey(byte[] message, int msgLen,
			byte[] encryptedData, String key,int mode);
	public native static int CZJ_AES_DecryptByKey(byte[] encryptedData,
			int dataLen, byte[] message,String key,int mode);
}
