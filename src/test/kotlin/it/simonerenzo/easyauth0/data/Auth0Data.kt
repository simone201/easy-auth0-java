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