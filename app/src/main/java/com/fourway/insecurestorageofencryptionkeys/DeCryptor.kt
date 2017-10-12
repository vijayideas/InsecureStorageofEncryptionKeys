package com.fourway.insecurestorageofencryptionkeys

import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec

/**
 * Created by Vijay Kumar on 06-10-2017.
 */

class DeCryptor @Throws(CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class, IOException::class)
internal constructor() {



    @Throws(UnrecoverableEntryException::class, NoSuchAlgorithmException::class, KeyStoreException::class, NoSuchProviderException::class, NoSuchPaddingException::class, InvalidKeyException::class, IOException::class, BadPaddingException::class, IllegalBlockSizeException::class, InvalidAlgorithmParameterException::class)
    internal fun decryptData(secreteKey: Key, encryptedData: ByteArray, encryptionIv: ByteArray): String {

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(128, encryptionIv)
        cipher.init(Cipher.DECRYPT_MODE, secreteKey, spec)

        return String(cipher.doFinal(encryptedData), charset("UTF-8"))
    }


    companion object {

        private val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
