package com.fourway.insecurestorageofencryptionkeys

import android.content.Context
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.content.SharedPreferences
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.util.Base64
import android.util.Log
import java.security.*

import javax.crypto.*
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {


    private lateinit var pref: SharedPreferences

    private lateinit var plainEt: EditText
    private lateinit var encryptedTv: TextView
    private lateinit var decryptedTv: TextView

    private lateinit var encryptor: EnCryptor
    private lateinit var decryptor: DeCryptor



    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initView()

        pref = getSharedPreferences(getString(R.string.pref_name), Context.MODE_PRIVATE)

        encryptor = EnCryptor()

        decryptor = DeCryptor()

    }



    private fun initView() {
        plainEt = findViewById(R.id.plain_et)

        encryptedTv = findViewById(R.id.encrypted_tv)
        decryptedTv = findViewById(R.id.decrypted_tv)

        findViewById<Button>(R.id.encryption_btn).setOnClickListener(onClickListener)
        findViewById<Button>(R.id.decryption_btn).setOnClickListener(onClickListener)
        findViewById<Button>(R.id.clear_btn).setOnClickListener(onClickListener)

    }


    /**
     * OnClickListener
     */
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

    /**
     * native function to access the from the C/C++ file
     */
    private external fun getNativeKey(): String


    private fun decryptText(encryptedText: String): String {
        try {
            val valueBytes = Base64.decode(encryptedText, Base64.DEFAULT)
            return decryptor
                    .decryptData(getSecretKey(), valueBytes, FIXED_IV.toByteArray())
        } catch (e: Exception) {
            Log.e(TAG, "decryptText() called with: " + e.message, e)
        }

        return ""
    }



    private fun encryptText(plainText: String): String {

        try {
            val encryptedText = encryptor
                    .encryptText(getSecretKey(), plainText, FIXED_IV.toByteArray())
            return Base64.encodeToString(encryptedText, Base64.DEFAULT)

        } catch (e: Exception) {
            Log.e(TAG, "encryptText() called with: " + e.message, e)
        }

        return ""
    }




    @Throws(NoSuchAlgorithmException::class, UnrecoverableEntryException::class, KeyStoreException::class)
    private fun getSecretKey(): SecretKey {

        val key = Base64.decode(getNativeKey(), Base64.DEFAULT)


        return SecretKeySpec(key, "AES")

    }




    companion object {
        private val TAG = MainActivity::class.java.simpleName

        private val FIXED_IV = "0123456789ab" //The IV you use in the encryption must be the same one you use in the decryption

        init {
            //here goes static initializer code
            System.loadLibrary("keys")
        }

    }


}
