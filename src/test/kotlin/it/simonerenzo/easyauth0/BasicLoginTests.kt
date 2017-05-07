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

package it.simonerenzo.easyauth0

import io.kotlintest.matchers.fail
import io.kotlintest.matchers.shouldBe
import io.kotlintest.matchers.shouldEqual
import io.kotlintest.matchers.shouldNotBe
import io.kotlintest.specs.FeatureSpec
import it.simonerenzo.easyauth0.data.Auth0Data
import it.simonerenzo.easyauth0.helpers.BasicAuth0Helper
import it.simonerenzo.easyauth0.models.Credentials
import java.util.*

class BasicLoginTests: FeatureSpec() {

    private val config = Auth0Data.instance.getData()
    private val client = BasicAuth0Helper(config.domain, config.clientId,
            config.clientSecret, config.realm)

    init {
        feature("Authentication") {
            scenario("Right Credentials") {
                client.login(getBasicHeader(config.userRight.username, config.userRight.password))
                        .shouldNotBe(null)
            }

            scenario("Wrong Credentials") {
                try {
                    client.login(getBasicHeader(config.userWrong.username, config.userWrong.password))
                    fail("This test cannot result in a successful login")
                } catch (e: Exception) { }
            }
        }

        feature("Authorization") {
            scenario("Login correct, use retrieved idToken") {
                val user = client.login(getBasicHeader(config.userRight.username, config.userRight.password))

                client.authorize(getBearerHeader(user.accessToken)).shouldBe(true)
            }

            scenario("Use fake idToken") {
                client.authorize(getBearerHeader("x.y.z")).shouldBe(false)
            }
        }

        feature("Reset Password") {
            scenario("Existing email address") {
                client.reset(config.userRight.email).shouldBe(true)
            }

            scenario("Wrong email address") {
                client.reset(config.userWrong.email).shouldBe(true)
            }
        }

        feature("Retrieve Application Emails") {
            scenario("Compare with expected emails") {
                val users = client.mails(config.audience)

                users.forEach { user ->
                    config.usersExpected.contains(user.email).shouldBe(true)
                }
            }
        }

        feature("Refresh Token") {
            scenario("Login, get refresh token and retrieve new idToken") {
                val user = client.login(getBasicHeader(config.userRight.username, config.userRight.password))

                val fresh = client.refresh(getBearerHeader(user.refreshToken))!!
                fresh.accessToken.shouldNotBe(equals(user.accessToken))
                fresh.refreshToken.shouldEqual(user.refreshToken)
            }

            scenario("Refresh a fake access token") {
                try {
                    client.refresh(getBearerHeader("fakeAccessToken"))
                    fail("This test cannot result in a successful refresh request")
                } catch (e: Exception) { }
            }
        }
    }

    private fun getBasicHeader(user: String, pwd: String): String {
        return "Basic " + Base64.getEncoder().encodeToString("$user:$pwd".toByteArray())
    }

    private fun getBearerHeader(idToken: String): String {
        return "Bearer $idToken"
    }

}