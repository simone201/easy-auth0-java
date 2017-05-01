package it.simonerenzo.easyauth0.helpers

import it.simonerenzo.easyauth0.models.Credentials

interface IAuth0Helper {
    fun login(authHeader: String): Credentials
    fun logout(authHeader: String): Boolean
    fun authorize(authHeader: String): Boolean
    fun refresh(authHeader: String): Credentials?
    fun reset(email: String): Boolean
}