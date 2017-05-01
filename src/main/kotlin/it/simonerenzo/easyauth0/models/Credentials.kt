package it.simonerenzo.easyauth0.models

data class Credentials(val user: User, var accessToken: String, var refreshToken: String, var expiresIn: Long)