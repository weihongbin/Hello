package com.windystory.hellojni;

/**
 * Created by Administrator on 2016/10/27.
 */
public class Utils {

    public static String   getStringTrue(String a ,int type){
     if(type==0){
         a=a.replace(" ","");
         a=a.replace("-----BEGINRSAPUBLICKEY-----","");
         a=a.replace("-----ENDRSAPUBLICKEY-----","");
     }else{
         a=a.replace(" ","");
         a=a.replace("-----BEGINRSAPRIVATEKEY-----","");
         a=a.replace("-----ENDRSAPRIVATEKEY-----","");
     }


        return a;
    }
}
