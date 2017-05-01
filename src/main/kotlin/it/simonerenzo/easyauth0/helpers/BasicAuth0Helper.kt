package it.simonerenzo.easyauth0.helpers

import it.simonerenzo.easyauth0.client.Auth0Client
import it.simonerenzo.easyauth0.models.Credentials
import it.simonerenzo.easyauth0.utils.Utils
import mu.KLogging
import javax.security.auth.login.LoginException

/**
 * Basic Authentication using Auth0 APIs
 *
 * Wraps the authentication client and provides easier access
 * to Basic authentication methods for your application
 *
 * @property domain Auth0 Account domain URL
 * @property clientId application Client ID
 * @property clientSecret application Client Secret
 * @property connection users database in Auth0
 * @constructor creates a single Auth0 client instance with Basic configuration
 */
open class BasicAuth0Helper(val domain: String, val clientId: String,
                            val clientSecret: String, val connection: String): IAuth0Helper {

    // Kotlin Logger
    private companion object: KLogging()

    // Auth0 Client
    private val authClient: Auth0Client = Auth0Client(domain, clientId, clientSecret, connection)

    /**
     * Authenticate your user using Basic auth header
     *
     * Use "Authorization" header with this format
     * Basic <Base64 Encoded Data>
     * where data is "username:password" encoded in Base64
     *
     * @param authHeader Authorization header value (Basic <encoded data>)
     * @return credentials object with logged user data
     */
    override fun login(authHeader: String): Credentials {
        val decoded: String

        try {
            decoded = Utils.getBasicHeader(authHeader, logger)
        } catch (e: Exception) {
            logger.error(e) { e.message }
            throw LoginException("Invalid header encoding")
        }

        val user: String
        val pwd: String

        try {
            user = decoded.split(":")[0]
            pwd = decoded.split(":")[1]
        } catch (e: Exception) {
            logger.error(e) { e.message }
            throw LoginException("Invalid header format")
        }

        return authClient.login(user, pwd)
    }

    /**
     * Logout your user using Bearer auth header
     *
     * Use "Authorization" header with this format
     * Bearer <Access Token>
     *
     * @param authHeader Authorization header value (Bearer <Access Token>)
     * @return logout result state
     */
    override fun logout(authHeader: String): Boolean {
        return authClient.logout(Utils.getBearerToken(authHeader, logger))
    }

    /**
     * Check if the access token is valid and authorize an operation
     *
     * Use "Authorization" header with this format
     * Bearer <Access Token>
     *
     * @param authHeader Authorization header value (Bearer <Access Token>)
     * @return operation authorization result
     */
    override fun authorize(authHeader: String): Boolean {
        return authClient.validateAccessToken(Utils.getBearerToken(authHeader, logger))
    }

    /**
     * Request a new access token by using a refresh token
     *
     * Use "Authorization" header with this format
     * Bearer <Refresh Token>
     *
     * @param authHeader Authorization header value (Bearer <Refresh Token>)
     * @return credentials object with logged new user data
     */
    override fun refresh(authHeader: String): Credentials? {
        return authClient.refreshToken(Utils.getBearerToken(authHeader, logger))
    }

    /**
     * Start a password reset flow
     *
     * @param email user email
     * @return request result state
     */
    override fun reset(email: String): Boolean {
        return authClient.resetPassword(email)
    }

}