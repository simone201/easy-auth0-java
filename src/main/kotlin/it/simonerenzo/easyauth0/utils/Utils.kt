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

package it.simonerenzo.easyauth0.utils

import mu.KLogger
import java.nio.charset.Charset
import java.util.*
import javax.security.auth.login.LoginException

/**
 * Utility Object
 */
object Utils {

    /**
     * An advanced version of the usual string trim function
     *
     * @param string input string
     * @return cleaned version of the string
     */
    fun trim(string: String): String {
        Objects.requireNonNull<Any>(string)

        val strLength = string.length
        var len = string.length
        var st = 0
        val `val` = string.toCharArray()

        if (strLength == 0) {
            return ""
        }

        while (st < len && `val`[st] <= ' ' || `val`[st] == '\u00A0') {
            st++
            if (st == strLength) {
                break
            }
        }

        while (st < len && `val`[len - 1] <= ' ' || `val`[len - 1] == '\u00A0') {
            len--
            if (len == 0) {
                break
            }
        }

        return if (st > len) ""
        else if (st > 0 || len < strLength)
            string.substring(st, len)
        else
            string
    }

    /**
     * Parse Authorization header and extract Basic value
     *
     * @param authHeader input header string
     * @param logger logging object
     * @return Base64 decoded value of the header
     */
    fun getBasicHeader(authHeader: String, logger: KLogger): String {
        if (authHeader.startsWith("Basic")) {
            return String(Base64.getDecoder().decode(trim(authHeader).split(" ")[1]),
                    Charset.forName("UTF-8"))
        } else {
            logger.error("Invalid Authentication header")
            throw LoginException("Invalid Authentication header")
        }
    }

    /**
     * Parse Authorization header and extract Bearer value
     *
     * @param authHeader input header string
     * @param logger logging object
     * @return value of the header (token)
     */
    fun getBearerToken(authHeader: String, logger: KLogger): String {
        if (authHeader.startsWith("Bearer")) {
            return trim(authHeader).split(" ")[1].trim()
        } else {
            logger.error("Invalid Authentication header")
            throw LoginException("Invalid Authentication header")
        }
    }

}