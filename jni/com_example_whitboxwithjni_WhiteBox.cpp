//
// Created by Antonio Nicolas Alfonso on 28/12/2021.
//
#include "com_example_whitboxwithjni_WhiteBox.h"
#include <string>
#include "aes_whitebox.cc"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>

JNIEXPORT jbyteArray JNICALL Java_com_example_whitboxwithjni_WhiteBox_encrypt(JNIEnv *env, jobject jobj, jstring input, jstring ivOrNonce) {

    u_int8_t iv_or_nonce[16], plain[16], cipher[16];

    const char* in = env->GetStringUTFChars(input, 0);
    const char* ivOrNonceOK = env->GetStringUTFChars(ivOrNonce, 0);
    const int lenIn = strlen(in)/2;

    read_hex(in, plain, sizeof(plain));
    read_hex(ivOrNonceOK, iv_or_nonce, 16);

    aes_whitebox_encrypt_ctr(iv_or_nonce,plain, sizeof(plain),cipher);
    jbyteArray resultReturn = env->NewByteArray(lenIn);
    env->SetByteArrayRegion(resultReturn, 0, lenIn, reinterpret_cast<const jbyte *>(cipher));

    return resultReturn;
}

JNIEXPORT jbyteArray JNICALL Java_com_example_whitboxwithjni_WhiteBox_decrypt(JNIEnv *env, jobject jobj, jstring input, jstring ivOrNonce){

    u_int8_t iv_or_nonce[16], plain[16], cipher[16];

    const char* in = env->GetStringUTFChars(input, 0);
    const char* ivOrNonceOK = env->GetStringUTFChars(ivOrNonce, 0);
    const int lenIn = strlen(in)/2;

    read_hex(in, cipher, sizeof(cipher));
    read_hex(ivOrNonceOK, iv_or_nonce, 16);

    aes_whitebox_decrypt_ctr(iv_or_nonce, cipher, sizeof(cipher), plain);
    jbyteArray resultReturn = env->NewByteArray(lenIn);
    env->SetByteArrayRegion(resultReturn, 0, lenIn, reinterpret_cast<const jbyte *>(plain));

    return resultReturn;
}