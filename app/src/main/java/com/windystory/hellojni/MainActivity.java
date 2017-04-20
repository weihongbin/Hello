package com.windystory.hellojni;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import com.cn.czj.Crypto;

public class MainActivity extends Activity {
    private static byte [] pubkey;
    private static byte [] prikey;
    private static byte [] endata;
    private static byte [] prikey3;
    static {
        System.loadLibrary("openssl-jni");

    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        pubkey = new byte [520];
        prikey = new byte [1420];
        endata = new byte [1024];
        prikey3 = new byte [1420];
//        JNI jni = new JNI();
//        Toast.makeText(MainActivity.this, jni.Hello(), Toast.LENGTH_SHORT).show();
        Crypto.CZJ_RSA_GeneratePEMKeys(pubkey,prikey,1024);
//        public native static int CZJ_RSA_EncryptByPrivateKey(byte[] message, int msgLen,
//        byte[] encryptedData, byte[] priKey);
       ;
        String a=new String(pubkey,0,pubkey.length);
//
//        ( (TextView)findViewById(R.id.tv)).setText(a);
//        public native static int CZJ_RSA_DecryptByPublicKey(byte[] encryptedData,
//        int dataLen, byte[] message, byte[] pubKey);
//        Crypto.CZJ_RSA_DecryptByPublicKey(a.getBytes(),a.getBytes().length,prikey3,null);
//        String b=new String(prikey3,0,prikey3.length);
//
//        pubkey= Utils.getStringTrue(a,0).getBytes();
//        Log.e("atg", Utils.getStringTrue(a,0));
        ( (TextView)findViewById(R.id.tv)).setText( Crypto.CZJ_RSA_EncryptByPublicKey("123".getBytes(),"123".getBytes().length,endata,pubkey)+new String(endata,0,endata.length));
    }

}
