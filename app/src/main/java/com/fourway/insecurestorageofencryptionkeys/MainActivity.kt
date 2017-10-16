package com.fourway.insecurestorageofencryptionkeys

import android.content.Context
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.util.Base64
import android.util.Log
import java.security.*
import android.security.KeyPairGeneratorSpec
import java.math.BigInteger
import java.util.*
import javax.security.auth.x500.X500Principal
import javax.crypto.*
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {


    private lateinit var pref: SharedPreferences

    private lateinit var plainEt: EditText
    private lateinit var encryptedTv: TextView
    private lateinit var decryptedTv: TextView

    private lateinit var encryptor: EnCryptor
    private lateinit var decryptor: DeCryptor

    private lateinit var keyStore: KeyStore


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initView()

        pref = getSharedPreferences(getString(R.string.pref_name), Context.MODE_PRIVATE)

        encryptor = EnCryptor()

        decryptor = DeCryptor()

        keyStore = KeyStore.getInstance(SecurityConstants.ANDROID_KEY_STORE)
        keyStore.load(null)


    }



    private fun initView() {
        plainEt = findViewById(R.id.plain_et)

        encryptedTv = findViewById(R.id.encrypted_tv)
        decryptedTv = findViewById(R.id.decrypted_tv)

        findViewById<Button>(R.id.encryption_btn).setOnClickListener(onClickListener)
        findViewById<Button>(R.id.decryption_btn).setOnClickListener(onClickListener)
        findViewById<Button>(R.id.clear_btn).setOnClickListener(onClickListener)

    }



    private val onClickListener = View.OnClickListener {

            view -> when(view.id) {

                R.id.encryption_btn -> if (plainEt.text.toString().isNotEmpty()) {

                    val encryptedData = encryptText(plainEt.text.toString())
                    encryptedTv.text = encryptedData
                    saveEncryptedDataInSharedPref(encryptedData)

                    plainEt.error = null

                } else {
                    plainEt.error = "Write something here"
                }


                R.id.decryption_btn -> {

                    val encryptedData = decryptText(retrieveEncryptedData())
                    decryptedTv.text = encryptedData
                }

                R.id.clear_btn -> clearAll()
            }

    }



    private fun saveEncryptedDataInSharedPref(encryptedData: String) {
        val editor = pref.edit()

        editor.putString(getString(R.string.encrypted_data), encryptedData)

        editor.apply()
    }


    private fun retrieveEncryptedData(): String {
        return pref.getString(getString(R.string.encrypted_data), "")
    }



    private fun clearAll() {
        val dataEditor = pref.edit()
        dataEditor.putString(getString(R.string.encrypted_data), null)
        dataEditor.apply()


        plainEt.setText("")
        encryptedTv.text = ""
        decryptedTv.text = ""

    }


    private fun decryptText(encryptedText: String): String {
        try {
            val valueBytes = Base64.decode(encryptedText, Base64.DEFAULT)
            return decryptor
                    .decryptData(getSecretKey(SecurityConstants.SAMPLE_ALIAS), valueBytes, FIXED_IV.toByteArray())
        } catch (e: Exception) {
            Log.e(TAG, "decryptText() called with: " + e.message, e)
        }

        return ""
    }



    private fun encryptText(plainText: String): String {

        try {
            val encryptedText = encryptor
                    .encryptText(generateSecretKey(SecurityConstants.SAMPLE_ALIAS), plainText, FIXED_IV.toByteArray())
            return Base64.encodeToString(encryptedText, Base64.DEFAULT)

        } catch (e: Exception) {
            Log.e(TAG, "encryptText() called with: " + e.message, e)
        }

        return ""
    }




    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    private fun generateSecretKey(alias: String): Key {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {

            /*val keyStore: KeyStore = KeyStore.getInstance(SecurityConstants.ANDROID_KEY_STORE)
            keyStore.load(null)*/

            // Generate the RSA key pairs
            if (!keyStore.containsAlias(alias)) {

                // Generate a key pair for encryption
                val start = Calendar.getInstance()
                val end = Calendar.getInstance()
                end.add(Calendar.YEAR, 30)

                val spec = KeyPairGeneratorSpec.Builder(this)
                        .setAlias(alias)
                        .setSubject(X500Principal("CN=" + alias))
                        .setSerialNumber(BigInteger.TEN)
                        .setStartDate(start.time)
                        .setEndDate(end.time)
                        .build()

                val kpg = KeyPairGenerator.getInstance(SecurityConstants.TYPE_RSA, SecurityConstants.ANDROID_KEY_STORE)
                kpg.initialize(spec)
                kpg.generateKeyPair()


                //Generate and Store the AES Key
                generateAndStoreRsaKey()

            }

            return getSecretKey(SecurityConstants.SAMPLE_ALIAS)

        }else{

            val keyGenerator:KeyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, SecurityConstants.ANDROID_KEY_STORE)



            keyGenerator.init(KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(false)
                    .build())

            return keyGenerator.generateKey()
        }



    }



    /*@Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    private fun generateSecretKey(alias: String): SecretKey {

        val keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, MainActivity.ANDROID_KEY_STORE)



        keyGenerator.init(KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(false)
                .build())

        return keyGenerator.generateKey()
    }*/

    @Throws(NoSuchAlgorithmException::class, UnrecoverableEntryException::class, KeyStoreException::class)
    private fun getSecretKey(alias: String): SecretKey {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {

            val encryptedKeyB64 = pref.getString(getString(R.string.encrypted_key), null)

            val encryptedKey = Base64.decode(encryptedKeyB64, Base64.DEFAULT)
            val key = rsaDecrypt(encryptedKey)


            return SecretKeySpec(key, "AES")
        }

        /*val keyStore: KeyStore = KeyStore.getInstance(SecurityConstants.ANDROID_KEY_STORE)
        keyStore.load(null)*/

        return (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
    }









    /**Pre Android M**/

    private fun generateAndStoreRsaKey() {

        var encryptedKeyB64 = pref.getString(getString(R.string.encrypted_key), null)

        if (encryptedKeyB64 == null) {

            val key = ByteArray(32)

            val secureRandom = SecureRandom()
            secureRandom.nextBytes(key)

            val encryptedKey = rsaEncrypt(key)

            encryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT)

            val edit = pref.edit()
            edit.putString(getString(R.string.encrypted_key), encryptedKeyB64)
            edit.apply()
        }
    }



    @Throws(Exception::class)
    private fun rsaEncrypt(secret: ByteArray): ByteArray {

        /*val keyStore: KeyStore = KeyStore.getInstance(SecurityConstants.ANDROID_KEY_STORE)
        keyStore.load(null)*/

        val privateKeyEntry = keyStore.getEntry(SecurityConstants.SAMPLE_ALIAS, null) as KeyStore.PrivateKeyEntry

        // Encrypt the text
        val inputCipher = Cipher.getInstance(SecurityConstants.RSA_MODE, "AndroidOpenSSL")
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)

        return inputCipher.doFinal(secret)
    }


    @Throws(Exception::class)
    private fun rsaDecrypt(encrypted: ByteArray): ByteArray {

        /*val keyStore: KeyStore = KeyStore.getInstance(SecurityConstants.ANDROID_KEY_STORE)
        keyStore.load(null)*/

        val privateKeyEntry = keyStore.getEntry(SecurityConstants.SAMPLE_ALIAS, null) as KeyStore.PrivateKeyEntry
        val cipher = Cipher.getInstance(SecurityConstants.RSA_MODE, "AndroidOpenSSL")
        cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)


        return cipher.doFinal(encrypted)
    }






    companion object {
        private val TAG = MainActivity::class.java.simpleName

        private val FIXED_IV = "0123456789ab" //The IV you use in the encryption must be the same one you use in the decryption

//        private val SECRETE_KEY = "my_secrete_keyhu"

    }









    /*private fun getHardcoded() : Key {
        val key = SECRETE_KEY.toByteArray()

       *//* val key = rsaDecrypt(encryptedKey)*//*
        return SecretKeySpec(key, "AES")
    }*/
}
