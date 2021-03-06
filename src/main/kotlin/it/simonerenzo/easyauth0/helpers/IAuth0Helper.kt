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

package it.simonerenzo.easyauth0.helpers

import it.simonerenzo.easyauth0.models.Credentials
import it.simonerenzo.easyauth0.models.User

interface IAuth0Helper {
    fun login(authHeader: String): Credentials
    fun logout(authHeader: String): Boolean
    fun authorize(authHeader: String): Boolean
    fun refresh(authHeader: String): Credentials?
    fun reset(email: String): Boolean
    fun mails(audience: String): MutableList<User>
}