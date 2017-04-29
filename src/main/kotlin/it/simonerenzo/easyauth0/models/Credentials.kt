package it.simonerenzo.easyauth0.models

data class Credentials(val user: User, val accessToken: String, val refreshToken: String, val expiresIn: Long)