package com.avanade.b2crefreshtoken

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.CancellationSignal
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.fragment.app.FragmentManager
import com.avanade.b2crefreshtoken.utils.B2cUtils
import com.avanade.b2crefreshtoken.utils.FingerPrintAuthHelper
import com.avanade.b2crefreshtoken.utils.FingerPrintAuthHelper.IFingerPrintCallback
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.InstanceCreator
import com.google.gson.JsonSerializationContext
import com.microsoft.identity.client.*
import com.microsoft.identity.client.exception.MsalException
import com.microsoft.identity.common.internal.cache.IAccountCredentialCache
import com.microsoft.identity.common.internal.dto.AccountRecord
import com.microsoft.identity.common.internal.dto.IAccountRecord
import org.w3c.dom.Text
import java.lang.reflect.Type

class MainActivity : AppCompatActivity() {
    private lateinit var b2capp : IMultipleAccountPublicClientApplication
    private lateinit var bLogin : Button
    private lateinit var bRenewToken : Button
    private var account : IAccount? = null
    private lateinit var tvToken : TextView
    private lateinit var tvExpires : TextView
    private lateinit var mFingerPrintAuthHelper: FingerPrintAuthHelper
    private lateinit var mFragmentManager: FragmentManager
    private lateinit var mFragment: FingerPrintDIalogFragment

    @RequiresApi(Build.VERSION_CODES.M)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bLogin = findViewById(R.id.bLogin)
        bRenewToken = findViewById(R.id.bRenewToken)
        tvToken = findViewById(R.id.tvToken)
        tvExpires = findViewById(R.id.tvExpires)

        mFingerPrintAuthHelper = FingerPrintAuthHelper(baseContext)

        mFragmentManager = supportFragmentManager
        mFragment = FingerPrintDIalogFragment.newInstance("", "")

        bLogin.setOnClickListener { login() }
        bRenewToken.setOnClickListener { renewToken() }

        PublicClientApplication.createMultipleAccountPublicClientApplication(baseContext,
            R.raw.auth_config_b2c,
            object : IPublicClientApplication.IMultipleAccountApplicationCreatedListener{
                override fun onCreated(application: IMultipleAccountPublicClientApplication?) {
                    b2capp = application!!
                }

                override fun onError(exception: MsalException?) {
                    println("Erro ao criar app B2C. ${exception.toString()}")
                }

            }
        )
    }

    private fun login(){
        val parameters = AcquireTokenParameters.Builder()
            .startAuthorizationFromActivity(this)
            .fromAuthority(B2cUtils.getAuthorityFromPolicyName("B2C_1_default_login"))
            .withScopes(B2cUtils.getScopes())
            .withPrompt(Prompt.LOGIN)
            .withCallback(authInterativeCallback)
            .build()

        b2capp!!.acquireToken(parameters)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun renewToken(){
        mFingerPrintAuthHelper.getPassword(CancellationSignal(), decryptAuthListener)
        mFragment.show(supportFragmentManager, "")
    }

//    private class IAccountInstanceCreator() : InstanceCreator<IAccount>{
//        override fun createInstance(type: Type?): IAccount {
//            return IAccountRecord()
//        }
//
//    }

//    private data class AccountY() : IAccount {
//        override fun getIdToken(): String? {
//            TODO("Not yet implemented")
//        }
//
//        override fun getClaims(): MutableMap<String, *> {
//            TODO("Not yet implemented")
//        }
//
//        override fun getUsername(): String {
//            TODO("Not yet implemented")
//        }
//
//        override fun getTenantId(): String {
//            TODO("Not yet implemented")
//        }
//
//        override fun getId(): String {
//            TODO("Not yet implemented")
//        }
//
//        override fun getAuthority(): String {
//            TODO("Not yet implemented")
//        }
//    }
//
//    private class AccountX : IAccount{
//        override fun getIdToken(): String? {
//            TODO("Not yet implemented")
//        }
//
//        override fun getClaims(): MutableMap<String, *> {
//            TODO("Not yet implemented")
//        }
//
//        override fun getUsername(): String {
//            TODO("Not yet implemented")
//        }
//
//        override fun getTenantId(): String {
//            TODO("Not yet implemented")
//        }
//
//        override fun getId(): String {
//            TODO("Not yet implemented")
//        }
//
//        override fun getAuthority(): String {
//            TODO("Not yet implemented")
//        }
//
//    }

    private val decryptAuthListener: IFingerPrintCallback
        private get() = object : IFingerPrintCallback{
            override fun onSuccess(password: String) {
//                mFragment.dismiss()
//                val gson = GsonBuilder()
//                    .create()
////                    .registerTypeAdapter()
//                val oAccount = gson.fromJson(password, AccountX::class.java)
////                oAccount.
//
//                b2capp.getAccount()


                val parameters = AcquireTokenSilentParameters.Builder()
                    .fromAuthority(B2cUtils.getAuthorityFromPolicyName("B2C_1_default_login"))
                    .withScopes(B2cUtils.getScopes())
                    .forAccount(account)
                    .withCallback(authSilentInterativeCallback)
                    .build()

                b2capp!!.acquireTokenSilentAsync(parameters)
            }

            override fun onFailure(message: String) {
                Toast.makeText(baseContext, "Falha - ${message}", Toast.LENGTH_LONG).show()
                mFragment.dismiss()
            }

            override fun onHelp(helpCode: Int, helpString: String) {
                TODO("Not yet implemented")
            }

        }

    private val authListener: IFingerPrintCallback
        private get() = object : IFingerPrintCallback{
            override fun onSuccess(password: String) {
                Toast.makeText(baseContext, "Sucesso - ${password}", Toast.LENGTH_LONG).show()
                mFragment.dismiss()
            }

            override fun onFailure(message: String) {
                Toast.makeText(baseContext, "Falha - ${message}", Toast.LENGTH_LONG).show()
                mFragment.dismiss()
            }

            override fun onHelp(helpCode: Int, helpString: String) {
                TODO("Not yet implemented")
            }

        }

    private val authInterativeCallback : AuthenticationCallback
        private get() = object : AuthenticationCallback{
            @RequiresApi(Build.VERSION_CODES.M)
            override fun onSuccess(authenticationResult: IAuthenticationResult?) {
                Toast.makeText(baseContext, "Login com sucesso!", Toast.LENGTH_LONG).show()
                account = authenticationResult?.account
                tvToken.setText(authenticationResult?.accessToken.toString())
                tvExpires.setText(authenticationResult?.expiresOn.toString())

                val gson = Gson()
                val string2BSaved = gson.toJson(authenticationResult?.account)

                mFingerPrintAuthHelper.savePassword(string2BSaved, CancellationSignal(), authListener)
                mFragment.show(supportFragmentManager, "")
            }

            override fun onError(exception: MsalException?) {
                println("Erro ao realizar o login. ${exception.toString()}")
            }

            override fun onCancel() {
                println("Usuário cancelou a ação!")
            }

        }

    private val authSilentInterativeCallback : AuthenticationCallback
        private get() = object : AuthenticationCallback{
            @RequiresApi(Build.VERSION_CODES.M)
            override fun onSuccess(authenticationResult: IAuthenticationResult?) {
                Toast.makeText(baseContext, "Token Renew com sucesso!", Toast.LENGTH_LONG).show()
                account = authenticationResult?.account
                tvToken.setText(authenticationResult?.accessToken.toString())
                tvExpires.setText(authenticationResult?.expiresOn.toString())
            }

            override fun onError(exception: MsalException?) {
                println("Erro ao realizar o login. ${exception.toString()}")
            }

            override fun onCancel() {
                println("Usuário cancelou a ação!")
            }

        }
}