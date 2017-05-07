/*
 * Easy Auth0 Java Library
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/lgpl-3.0.html>.
 */

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