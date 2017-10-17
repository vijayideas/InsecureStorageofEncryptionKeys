//
// Created by 4 way on 16-10-2017.
//

#include <jni.h>

JNIEXPORT jstring JNICALL

Java_com_fourway_insecurestorageofencryptionkeys_MainActivity_getNativeKey(JNIEnv *env, jobject instance) {

 return (*env)->  NewStringUTF(env, "TmF0aXZlNWVjcmV0UEBzc3cwcmQxytsk");
}


