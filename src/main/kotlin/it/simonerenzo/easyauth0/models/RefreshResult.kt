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

package it.simonerenzo.easyauth0.models

import com.fasterxml.jackson.annotation.JsonProperty

data class RefreshResult(@JsonProperty("token_type") val tokenType: String,
                         @JsonProperty("expires_in") val expiresIn: Long,
                         @JsonProperty("id_token") val idToken: String,
                         @JsonProperty("access_token") val accessToken: String,
                         @JsonProperty("scope") val scope: String)