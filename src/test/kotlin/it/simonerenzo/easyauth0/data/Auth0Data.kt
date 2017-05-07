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

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

class Auth0Data private constructor() {

    private val CONFIG_FILE_NAME = "auth0-config.json"

    private val data: ConfigHolder

    init {
        val config_file = javaClass.classLoader.getResource(CONFIG_FILE_NAME).readText()
        data = jacksonObjectMapper().readValue<ConfigHolder>(config_file)
    }

    private object Holder {
        @JvmStatic
        val instance = Auth0Data()
    }

    companion object {
        @JvmStatic
        val instance: Auth0Data by lazy { Holder.instance }
    }

    fun getData(): ConfigHolder {
        return data
    }

}