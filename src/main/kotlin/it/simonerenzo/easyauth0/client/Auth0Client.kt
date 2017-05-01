package it.simonerenzo.easyauth0.client

import com.auth0.client.auth.AuthAPI
import com.auth0.json.auth.TokenHolder
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import it.simonerenzo.easyauth0.exceptions.LoginException
import it.simonerenzo.easyauth0.models.Credentials
import it.simonerenzo.easyauth0.models.RefreshResult
import it.simonerenzo.easyauth0.models.User
import mu.KLogging
import okhttp3.FormBody
import java.io.UnsupportedEncodingException
import okhttp3.OkHttpClient
import okhttp3.Request
import org.apache.commons.validator.routines.UrlValidator
import java.net.MalformedURLException

/**
 * Auth0 Client Class
 *
 * Implements various helper methods to make life simpler.
 * Handles instance logged users, intended to be used as singleton.
 *
 * @property domain Auth0 Account domain URL
 * @property clientId application Client ID
 * @property clientSecret application Client Secret
 * @property connection users database in Auth0
 * @constructor creates a single Auth0 client instance
 */
class Auth0Client(val domain: String, val clientId: String,
                  val clientSecret: String, val connection: String) {

    // Kotlin Logger
    private companion object: KLogging()

    // Auth0 Client API
    private val authClient: AuthAPI = AuthAPI(domain, clientId, clientSecret)

    // OkHttp Client
    private val httpClient = OkHttpClient()

    // Jackson Parser
    private val jsonMapper = jacksonObjectMapper()

    // Auth0 JWT Verifier
    private val algorithm = Algorithm.HMAC256(clientSecret)
    private val verifier: JWTVerifier

    // Credentials Data
    private val credsMap: HashMap<String, Credentials> = HashMap()
    private val tokensMap: HashMap<String, String> = HashMap()

    // URLs
    private var fullUrl: String = ""

    // Initialization
    init {
        // Check domain and fix it if needed
        if (!domain.startsWith("https://") && !domain.startsWith("http://"))
            fullUrl = "https://$domain"
        else if (domain.startsWith("http://"))
            fullUrl = "https://" + domain.split("http://")[1]

        // Then check if it valid
        if(!UrlValidator.getInstance().isValid(fullUrl))
            throw MalformedURLException("Invalid Domain URL")

        // Now we can initialize the verifier with the domain
        verifier = JWT.require(algorithm)
                .withIssuer(fullUrl + "/")
                .build()
    }

    /**
     * Do a simple authentication to Auth0
     *
     * @param userOrEmail the username or email
     * @param password the user password
     * @return credentials object with logged user data
     */
    fun login(userOrEmail: String, password: String): Credentials {
        logger.debug("User login request=[userOrEmail=$userOrEmail, password=$password]")

        try {
            // Get the auth tokens
            val tokenHolder = authClient.login(userOrEmail, password, connection)
                    .setScope("openid offline_access")
                    .execute()

            return buildCredentials(tokenHolder)
        } catch (e: Exception) {
            logger.error(e) { e.message }
            throw LoginException(e.message!!)
        }
    }

    /**
     * Do a simple logout after being logged in
     *
     * @param accessToken logged user access token
     * @return logout result state
     */
    fun logout(accessToken: String): Boolean {
        if (accessToken in tokensMap) {
            credsMap.remove(tokensMap[accessToken])
            tokensMap.remove(accessToken)

            return true
        } else
            return false
    }

    /**
     * Validate an inbound access token
     *
     * @param idToken logged user id token
     * @return token validation result state
     */
    fun validateAccessToken(idToken: String): Boolean {
        try {
            verifier.verify(idToken)
            return idToken in tokensMap
        } catch (e: UnsupportedEncodingException) {
            logger.error(e) { e.message }
            return false
        } catch (e: JWTVerificationException) {
            logger.error(e) { e.message }
            return false
        }
    }

    /**
     * Request a new access token by using a refresh token
     *
     * @param refreshToken logged user refresh token
     * @return credentials object with logged new user data
     */
    fun refreshToken(refreshToken: String): Credentials? {
        val requestBody = FormBody.Builder()
                .add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .add("client_id", clientId)
                .add("refresh_token", refreshToken)
                .add("scope", "openid")
                .build()

        val request = Request.Builder()
                .url("$fullUrl/delegation")
                .post(requestBody)
                .build()

        val response = httpClient.newCall(request).execute()

        if (response.isSuccessful) {
            try {
                return refreshCredentials(refreshToken,
                        jsonMapper.readValue<RefreshResult>(response.body().string()))
            } catch(e: Exception) {
                logger.error(e) { e.message }
                throw LoginException("Refresh token request not valid")
            }
        } else {
            throw LoginException("Refresh token request not valid")
        }
    }

    /**
     * Start a password reset flow
     *
     * @param email user email
     * @return request result state
     */
    fun resetPassword(email: String): Boolean {
        try {
            authClient.resetPassword(email, connection).execute()
            return true
        } catch (e: Exception) {
            logger.error(e) { e.message }
            return false
        }
    }

    /**
     * Updates user credentials by injecting new idToken (access token) after refresh,
     * may throw NPE because of security purposes
     *
     * @param refreshToken request refresh_token to search for user
     * @param refreshResult result parsed from refresh request
     * @return updated credentials object with new idToken (access token)
     */
    private fun refreshCredentials(refreshToken: String, refreshResult: RefreshResult): Credentials? {
        var updatedCred: Credentials? = null

        credsMap.forEach { _, credentials ->
            if (credentials.refreshToken == refreshToken) {
                tokensMap.remove(credentials.accessToken)
                tokensMap.put(refreshResult.idToken, credentials.user.email)
                credentials.accessToken = refreshResult.idToken
                credentials.expiresIn = refreshResult.expiresIn

                updatedCred = credentials

                return@forEach
            }
        }

        return updatedCred
    }

    /**
     * Builds Credentials object based on TokenHolder data
     *
     * @param tokenHolder Auth0 TokenHolder object from previous request
     * @return credentials object with logged user data
     */
    private fun buildCredentials(tokenHolder: TokenHolder): Credentials {
        // Get logged user info
        val userInfo = authClient.userInfo(tokenHolder.accessToken)
                .execute()
                .values

        // Clean any eventual duplicate in data maps
        tokensMap.remove(credsMap[userInfo["email"]]?.accessToken)
        credsMap.remove(userInfo["email"])

        // Parse info as User object
        val loggedUser = User(userInfo["nickname"] as String,
                userInfo["name"] as String,
                userInfo["email"] as String)

        // Parse auth data to Credentials object
        val credentials = Credentials(loggedUser,
                tokenHolder.idToken,
                tokenHolder.refreshToken,
                tokenHolder.expiresIn)

        // Save the new credentials
        credsMap.put(credentials.user.email, credentials)
        tokensMap.put(credentials.accessToken, credentials.user.email)

        return credentials
    }

}