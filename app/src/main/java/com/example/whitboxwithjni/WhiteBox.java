package com.example.whitboxwithjni;

public class WhiteBox {

    static {
        System.loadLibrary("whitebox");
    }

    public native byte[] encrypt(String input, String inOrNonce);

    public native byte[] decrypt(String input,String inOrNonce);

}
