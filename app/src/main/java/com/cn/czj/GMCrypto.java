package com.cn.czj;

public class GMCrypto {
	public native static String CZJ_SM2_GenPrivateKey(int keyLen);
	public native static String CZJ_SM2_GenPublicKey(String privateKey);
	public native static String CZJ_SM2_GetPublicKey_X(String publicKey);
	public native static String CZJ_SM2_GetPublicKey_Y(String publicKey);
	public native static String CZJ_SM2_GetPublicKeyByXY(String xParam, String yParam);
	public native static int CZJ_SM2_EncryptByPublicKey(byte[] message, int msgLen,
			byte[] encryptedData,String publicKey);
	public native static int CZJ_SM2_DecryptByPrivateKey(byte[] encryptedData,
			int dataLen, byte[] message, String privateKey);
	public native static int CZJ_SM2_EncryptByPrivateKey(byte[] message, int msgLen,
			byte[] encryptedData, int[] dataLen, String privateKey);
	public native static int CZJ_SM2_DecryptByPublicKey(byte[] encryptedData,
			int dataLen, byte[] message, int[] msgLen, String publicKey);
	public native static int CZJ_SM2_SignByPrivateKey(byte[] message, int msgLen,
			byte[] signedData, int[] dataLen, String privateKey);
	public native static boolean CZJ_SM2_VerifyByPublicKey(byte[] message, int msgLen,
			byte[] signedData, int dataLen, String publicKey);
	public native static int CZJ_SM3_Hash(byte[] message, int msgLen,
			byte[] digestData);
	public native static String CZJ_SM4_GenerateKey(int keyLen);
	public native static String CZJ_SM4_GenerateKey();
	public native static int CZJ_SM4_EncryptByKey(byte[] message, int msgLen,
			byte[] encryptedData, String key);
	public native static int CZJ_SM4_DecryptByKey(byte[] encryptedData, int dataLen,
			byte[] message, String key);
}	
