package com.avanade.b2crefreshtoken.utils

import java.util.*

class B2cUtils {
    companion object{
        private val azureAdB2CHostName : String = "nextdevpoc.b2clogin.com"
        private val tenantName : String = "nextdevpoc"
        fun getAuthorityFromPolicyName(policyName : String) : String{
            //return "https://" + azureAdB2CHostName + "/" + tenantName + ".onmicrosoft.com/oauth2/v2.0/authorize?p=" + policyName
            return "https://nextdevpoc.b2clogin.com/tfp/nextdevpoc.onmicrosoft.com/B2C_1_default_login/"
        }

        fun getScopes() : List<String>{
            return Arrays.asList("https://nextdevpoc.onmicrosoft.com/api/demo.read")
        }
    }
}