package it.simonerenzo.easyauth0.data

import com.fasterxml.jackson.annotation.JsonProperty

data class CredsHolder(@JsonProperty("email") val email: String,
                       @JsonProperty("username") val username: String,
                       @JsonProperty("password") val password: String)
