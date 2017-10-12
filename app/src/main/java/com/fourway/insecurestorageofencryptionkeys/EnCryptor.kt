package com.fourway.insecurestorageofencryptionkeys

import java.io.IOException
import java.security.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec


/**
 * Created by Vijay Kumar on 06-10-2017.
 */
class EnCryptor internal constructor() {


    @Throws(UnrecoverableEntryException::class, NoSuchAlgorithmException::class, KeyStoreException::class, NoSuchProviderException::class,
            NoSuchPaddingException::class, InvalidKeyException::class, IOException::class, InvalidAlgorithmParameterException::class, SignatureException::class,
            BadPaddingException::class, IllegalBlockSizeException::class)
    internal fun encryptText(secreteKey: Key, textToEncrypt: String, decryptionIv: ByteArray): ByteArray {


        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secreteKey, GCMParameterSpec(128,decryptionIv))


        return cipher.doFinal(textToEncrypt.toByteArray(charset("UTF-8")))
    }


    companion object {

        private val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}