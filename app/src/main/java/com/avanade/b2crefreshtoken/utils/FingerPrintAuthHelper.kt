package com.avanade.b2crefreshtoken.utils

import android.Manifest.permission.USE_FINGERPRINT
import android.app.KeyguardManager
import android.content.Context
import android.content.Context.FINGERPRINT_SERVICE
import android.content.Context.KEYGUARD_SERVICE
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import androidx.core.hardware.fingerprint.FingerprintManagerCompat
import androidx.fragment.app.FragmentManager
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.lang.Exception
import java.lang.IllegalArgumentException
import java.lang.StringBuilder
import java.nio.charset.Charset
import java.security.AlgorithmParameterGenerator
import java.security.Key
import java.security.KeyStore
import java.util.jar.Manifest
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

@RequiresApi(Build.VERSION_CODES.M)
open class FingerPrintAuthHelper(context: Context) {
    private lateinit var mContext: Context
    private lateinit var mKeyStore : KeyStore
    private lateinit var mKeyGenerator: KeyGenerator
    private lateinit var mFingerPrintManager: FingerprintManager
    private lateinit var mKeyGuardManager : KeyguardManager

    private val ANDROID_KEY_STORE : String = "AndroidKeyStore"
    private val LAST_USED_IV_SHARED_PREF_KEY : String = "LAST_USED_IV_SHARED_PREF_KEY"
    private val MY_APP_ALIAS : String = "MY_APP_ALIAS"

    init {
        mContext = context

        mFingerPrintManager = mContext.getSystemService(FINGERPRINT_SERVICE) as FingerprintManager
        mKeyGuardManager = mContext.getSystemService(KEYGUARD_SERVICE) as KeyguardManager

        if(!mKeyGuardManager.isKeyguardSecure){
            throw Exception("Usuário não habilitou lock screen")
        }

        if(!mFingerPrintManager.isHardwareDetected){
            throw Exception("Hardware não detectado!")
        }

        if(!mFingerPrintManager.hasEnrolledFingerprints()){
            throw Exception("Não há nenhuma digital cadastrada!")
        }


        initKeyStore()
    }

    interface IFingerPrintCallback{
        fun onSuccess(password : String)
        fun onFailure(message : String)
        fun onHelp(helpCode : Int, helpString : String)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    protected open class FingerprintAuthenticationListener(callback: IFingerPrintCallback) : FingerprintManager.AuthenticationCallback() {
        protected var mCallback: IFingerPrintCallback = callback

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
            mCallback.onFailure("Erro de authenticação [${errorCode}] - ${errString}")
        }

        override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
            mCallback.onHelp(helpCode, helpString.toString())
        }

        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {

        }

        override fun onAuthenticationFailed() {
            mCallback.onFailure("Erro na autenticação.")
        }

        fun getCallback(): IFingerPrintCallback{
            return mCallback
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    protected class FingerPrintEncryptPasswordListener : FingerprintAuthenticationListener{
        private lateinit var mPassword : String
        private lateinit var mContext: Context

        constructor(context: Context, callback: IFingerPrintCallback, password: String) : super(callback){
            mPassword = password
            mContext = context
        }

        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
            val cipher = result?.cryptoObject?.cipher

            try{
                if(encryptPassword(mContext, cipher, mPassword)){
                    mCallback.onSuccess("Senha encriptado e armazenado.")
                }
                else{
                    mCallback.onFailure("Problema ao encriptar a senha.")
                }
            }
            catch (e: Exception){
                mCallback.onFailure("Falha ao encriptar - ${e.message}")
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    protected class FingerPrintDecryptPasswordListener : FingerprintAuthenticationListener{
        private lateinit var mContext: Context

        constructor(context:Context, callback: IFingerPrintCallback) : super(callback){
            mContext = context
        }

        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
            val cipher = result?.cryptoObject?.cipher
            try {
                val savedPass = decipher(mContext, cipher!!)
                if(savedPass != null){
                    mCallback.onSuccess(savedPass)
                }
                else{
                    mCallback.onFailure("Falha ao decriptar senha")
                }
            }
            catch (e: Exception){
                mCallback.onFailure("Falha ao decriptar senha - ${e.message}")
            }
        }

    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun savePassword(password : String, cancellationSignal : CancellationSignal, callback : IFingerPrintCallback){
        authenticate(cancellationSignal, FingerPrintEncryptPasswordListener(mContext, callback, password), Cipher.ENCRYPT_MODE)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun getPassword(cancellationSignal: CancellationSignal, callback: IFingerPrintCallback){
        authenticate(cancellationSignal, FingerPrintDecryptPasswordListener(mContext, callback), Cipher.DECRYPT_MODE)
    }

    private fun authenticate(cancellationSignal: CancellationSignal, listener : FingerprintAuthenticationListener, mode : Int){
        try {
            if(hasPermission()){
                val cipher = createCipher(mode)
                val crypto : FingerprintManager.CryptoObject = FingerprintManager.CryptoObject(cipher!!)
                mFingerPrintManager.authenticate(crypto, cancellationSignal, 0, listener, null)
            }
            else{
                listener.getCallback().onFailure("Usuário não concedeu permissão para usar biometria")
            }
        }
        catch (t: Throwable){
            listener.getCallback().onFailure("Erro ao solicitar a biometria - ${t.message}")
        }
    }

    private fun createCipher(mode: Int): Cipher? {
        val cipher : Cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)

        val key = mKeyStore.getKey(MY_APP_ALIAS, null)

        if(key == null){
            return null
        }

        if(mode == Cipher.ENCRYPT_MODE){
            cipher.init(mode, key)
            var iv = cipher.iv
            saveIv(iv)
        }
        else{
            val lastIv = getLastIv()
            cipher.init(mode, key, IvParameterSpec(lastIv))
        }

        return cipher
    }

    private fun saveIv(iv: ByteArray) {
        val editor : SharedPreferences.Editor = getSharedPrefences(mContext).edit()
        val string2BSaved = encodeBytes(iv)
        editor.putString(LAST_USED_IV_SHARED_PREF_KEY, string2BSaved)
        editor.commit()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun initKeyStore(): Boolean{
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
            mKeyStore.load(null)

            if(getLastIv() == null){
                val keyGenParameterSpec : KeyGenParameterSpec = createKeyGenParameterSpec()
                mKeyGenerator.init(keyGenParameterSpec)
                mKeyGenerator.generateKey()
            }
        }
        catch (t: Throwable){
            setError("Erro ao iniciar a keystore: ${t.message}")
            return false
        }
        return true
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun createKeyGenParameterSpec(): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(MY_APP_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setUserAuthenticationRequired(true)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()
    }

    private fun getLastIv(): ByteArray? {
        val sharedPreferences = getSharedPrefences(mContext)
        if(sharedPreferences != null){
            val ivString = sharedPreferences.getString(LAST_USED_IV_SHARED_PREF_KEY, null)

            if(ivString != null){
                return decodeBytes(ivString)
            }
        }

        return null
    }

    private fun hasPermission(): Boolean {
        return ActivityCompat.checkSelfPermission(mContext, USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED
    }

    companion object{
        private var mLastError : String? = null
        private val FINGER_PRINT_HELPER : String = "FINGER_PRINT_HELPER"
        private val ENCRYPTEDPASS_SHARED_PREF_KEY : String = "ENCRYPTEDPASS_SHARED_PREF_KEY"
        private val hexCode : CharArray = "0123456789ABCDEF".toCharArray()

        fun encryptPassword(context: Context, cipher: Cipher?, password: String) : Boolean {
            try {
                val outputStream: ByteArrayOutputStream = ByteArrayOutputStream()
                val cipherOutputStream: CipherOutputStream = CipherOutputStream(outputStream, cipher)
                val bytes: ByteArray = password.toByteArray(Charset.defaultCharset())
                cipherOutputStream.write(bytes)
                cipherOutputStream.flush()
                cipherOutputStream.close()
                saveEncryptedPassword(context, encodeBytes(outputStream.toByteArray()))
                return true
            } catch (t : Throwable){
                setError("Falha na encriptação ${t.message}")
                return false
            }
        }

        fun decipher(context: Context, cipher: Cipher): String?{
            val savedPassword = getSavedPassword(context)
            var output : String? = null

            if(savedPassword != null){
                var decodedPassword : ByteArray = decodeBytes(savedPassword)
                val cipherInputStream : CipherInputStream = CipherInputStream(ByteArrayInputStream(decodedPassword), cipher)

                var values : ArrayList<Byte> = arrayListOf<Byte>()
                var nextByte : Int = cipherInputStream.read()
                while (nextByte != -1){
                    values.add(nextByte.toByte())
                    nextByte= cipherInputStream.read()
                }
                cipherInputStream.close()

                var bytes : ByteArray = ByteArray(values.size)
                for(i in 0 until values.size){
                    bytes[i] = values.get(i).toByte()
                }

                output = String(bytes, Charset.defaultCharset())
            }

            return output
        }

        private fun decodeBytes(s: String): ByteArray {
            val len = s.length

            if(len%2 != 0){
                throw IllegalArgumentException("O valor hexadecimal precisa ser par")
            }

            var output : ByteArray = ByteArray(len/2)

            for(i in 0 until len step 2){
                var h = hexToBin(s[i])
                var l = hexToBin(s[i + 1])
                if (h == -1 || l == -1){
                    throw IllegalArgumentException("O texto contém caracters ilegais ${s}")
                }

                output[i/2] = (h*16+l).toByte()
            }

            return output
        }

        private fun hexToBin(c: Char): Int {
            return when (c) {
                in '0'..'9' -> c-'0'
                in 'A'..'F' -> c-'A'+10
                in 'a'..'f' -> c-'a'+10
                else -> -1
            }
        }

        private fun getSavedPassword(context: Context): String? {
            val sharedPreferences : SharedPreferences = getSharedPrefences(context)
            return sharedPreferences.getString(ENCRYPTEDPASS_SHARED_PREF_KEY, null)
        }

        private fun saveEncryptedPassword(context: Context, encryptedPassword: String) {
            val sharedPreferences : SharedPreferences.Editor = getSharedPrefences(context).edit()
            sharedPreferences.putString(ENCRYPTEDPASS_SHARED_PREF_KEY, encryptedPassword)
            sharedPreferences.commit()
        }

        private fun getSharedPrefences(context : Context): SharedPreferences {
            return context.getSharedPreferences(FINGER_PRINT_HELPER, 0)
        }

        private fun encodeBytes(data: ByteArray): String {
            val sbOutput : StringBuilder = StringBuilder(data.size * 2)
            for(b : Byte in data){
                sbOutput.append(hexCode[(b.toInt() shr 4) and 0xF])
                sbOutput.append(hexCode[b.toInt() and 0xF])
            }

            return sbOutput.toString()
        }

        private fun setError(error: String) {
            mLastError = error
            Log.w(FINGER_PRINT_HELPER, mLastError!!)
        }
    }
}