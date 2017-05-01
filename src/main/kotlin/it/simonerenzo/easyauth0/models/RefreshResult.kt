package it.simonerenzo.easyauth0.models

import com.fasterxml.jackson.annotation.JsonProperty

data class RefreshResult(@JsonProperty("token_type") val tokenType: String,
                         @JsonProperty("expires_in") val expiresIn: Long,
                         @JsonProperty("id_token") val idToken: String)