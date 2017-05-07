package it.simonerenzo.easyauth0.data

import com.fasterxml.jackson.annotation.JsonProperty

data class ConfigHolder(@JsonProperty("domain") val domain: String,
                        @JsonProperty("client_id") val clientId: String,
                        @JsonProperty("client_secret") val clientSecret: String,
                        @JsonProperty("realm") val realm: String,
                        @JsonProperty("audience") val audience: String,
                        @JsonProperty("user_right") val userRight: CredsHolder,
                        @JsonProperty("user_wrong") val userWrong: CredsHolder,
                        @JsonProperty("users_expected") val usersExpected: List<String>)