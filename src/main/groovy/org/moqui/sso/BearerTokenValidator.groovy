package org.moqui.sso

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import groovy.json.JsonSlurper
import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityValue
import org.moqui.util.SystemBinding

import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.time.Duration

/**
 * Validates an access token issued by the OpenID provider of an SSO auth flow, for a request that carries it as a Bearer
 * token (a service that is called on behalf of a person, such as the MCP endpoint called by LibreChat).
 *
 * The signature is checked against the keys of the provider (RS256 only), together with the issuer, the expiry and the
 * client the token was issued to. The name of the person is the preferred_username claim; whether that person has a Moqui
 * account, and as whom the request goes on, is for the caller to decide.
 *
 * Settings (system property or environment): sso_bearer_auth_flow (the OIDC auth flow whose discovery document is used,
 * default KeycloakDev), sso_bearer_clients (client ids accepted, default "librechat,moqui-web"), sso_ca_file (a PEM file with
 * the certificate authority of a provider that has a certificate of its own).
 */
final class BearerTokenValidator {
    private static final long CACHE_MILLIS = 10 * 60 * 1000L
    private static final long SKEW_SECONDS = 30L
    private static volatile Map<String, Object> cachedDiscovery = null
    private static volatile JWKSet cachedKeys = null
    private static volatile long cachedAt = 0L

    private BearerTokenValidator() { }

    /** The username the token stands for; a SecurityException says why the token is not accepted. */
    static String usernameFor(ExecutionContext ec, String token) {
        SignedJWT jwt
        try { jwt = SignedJWT.parse(token) } catch (Exception e) { throw new SecurityException("The Bearer token is not a JWT") }
        if (jwt.header.algorithm != JWSAlgorithm.RS256) throw new SecurityException("Only RS256 tokens are accepted")

        Map<String, Object> discovery = discovery(ec)
        JWKSet keys = keys(discovery, jwt.header.keyID, false)
        com.nimbusds.jose.jwk.JWK key = keys.getKeyByKeyId(jwt.header.keyID)
        if (key == null) {
            // the provider may have rotated its keys since they were read
            keys = keys(discovery, jwt.header.keyID, true)
            key = keys.getKeyByKeyId(jwt.header.keyID)
        }
        if (!(key instanceof RSAKey)) throw new SecurityException("The key of the token is not known to the provider")
        if (!jwt.verify(new RSASSAVerifier((RSAKey) key))) throw new SecurityException("The signature of the token is not valid")

        JWTClaimsSet claims = jwt.JWTClaimsSet
        long now = System.currentTimeMillis()
        if (claims.expirationTime == null || claims.expirationTime.time + SKEW_SECONDS * 1000 < now)
            throw new SecurityException("The token has expired")
        if (claims.notBeforeTime != null && claims.notBeforeTime.time - SKEW_SECONDS * 1000 > now)
            throw new SecurityException("The token is not valid yet")
        if (claims.issuer != discovery.issuer) throw new SecurityException("The token was issued by another provider")

        Set<String> clients = (SystemBinding.getPropOrEnv("sso_bearer_clients") ?: "librechat,moqui-web").split(",")*.trim() as Set<String>
        String authorizedParty = claims.getStringClaim("azp")
        if (!(authorizedParty in clients) && !claims.audience?.any { it in clients })
            throw new SecurityException("The token was not issued to a client that is accepted")

        String username = claims.getStringClaim("preferred_username")
        if (!username) throw new SecurityException("The token has no preferred_username")
        return username
    }

    private static Map<String, Object> discovery(ExecutionContext ec) {
        long now = System.currentTimeMillis()
        if (cachedDiscovery != null && now - cachedAt < CACHE_MILLIS) return cachedDiscovery
        String flowId = SystemBinding.getPropOrEnv("sso_bearer_auth_flow") ?: "KeycloakDev"
        EntityValue flow = ec.entity.find("moqui.security.sso.OidcFlow").condition("authFlowId", flowId).disableAuthz().useCache(false).one()
        if (flow == null || !flow.discoveryUri) throw new SecurityException("No OpenID auth flow ${flowId} to check the token against")
        Map<String, Object> found = (Map<String, Object>) new JsonSlurper().parseText(fetch(flow.discoveryUri as String))
        if (!found.issuer || !found.jwks_uri) throw new SecurityException("The discovery document of the provider is incomplete")
        cachedDiscovery = found
        cachedKeys = null
        cachedAt = now
        return found
    }

    private static JWKSet keys(Map<String, Object> discovery, String keyId, boolean refresh) {
        if (!refresh && cachedKeys != null) return cachedKeys
        JWKSet loaded = JWKSet.parse(fetch(discovery.jwks_uri as String))
        cachedKeys = loaded
        return loaded
    }

    private static String fetch(String url) {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
        SSLContext ssl = sslContext()
        if (ssl != null) builder.sslContext(ssl)
        HttpResponse<String> response = builder.build().send(
                HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) throw new SecurityException("The provider answered ${response.statusCode()} for ${url}")
        return response.body()
    }

    /** The default trust of the JVM, plus the authority of sso_ca_file when it is set. */
    private static SSLContext sslContext() {
        String caFile = SystemBinding.getPropOrEnv("sso_ca_file")
        if (!caFile) return null
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType())
        store.load(null, null)
        new File(caFile).withInputStream { input ->
            int index = 0
            CertificateFactory.getInstance("X.509").generateCertificates(input).each { store.setCertificateEntry("sso-ca-" + (index++), it) }
        }
        TrustManagerFactory custom = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        custom.init(store)
        SSLContext context = SSLContext.getInstance("TLS")
        context.init(null, custom.trustManagers, null)
        return context
    }
}
