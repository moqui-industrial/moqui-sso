package org.moqui.sso

import org.moqui.context.ExecutionContext
import org.moqui.impl.context.UserFacadeImpl
import org.moqui.util.WebUtilities
import org.pac4j.core.client.Client
import org.pac4j.core.config.Config
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.DefaultCallbackLogic
import org.pac4j.core.engine.DefaultLogoutLogic
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.UserProfile
import org.pac4j.core.profile.factory.ProfileManagerFactory
import org.pac4j.jee.context.JEEContext
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.jee.context.session.JEESessionStoreFactory
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter
import org.pac4j.saml.state.SAML2StateGenerator

class AuthenticationFlow {

    static Config makeConfig(String callbackUrl, Client... clients) {
        return new Config(callbackUrl, clients)
                .setWebContextFactory(JEEContextFactory.INSTANCE)
                .setSessionStoreFactory(JEESessionStoreFactory.INSTANCE)
                .setProfileManagerFactory(ProfileManagerFactory.DEFAULT)
                .setHttpActionAdapter(JEEHttpActionAdapter.INSTANCE)
    }

    static Config makeConfig(String callbackUrl, List<Client> clients) {
        return makeConfig(callbackUrl, clients.toArray(new Client[0]))
    }

    static SessionStore sessionStoreFor(ExecutionContext ec) {
        return JEESessionStoreFactory.INSTANCE.newSessionStore(
                new JEEFrameworkParameters(ec.web.request, ec.web.response))
    }

    /** Same-origin only; absolute off-site URLs and schemes are dropped. */
    static String safeReturnTo(ExecutionContext ec, String url) {
        if (!url || ec.web?.request == null) return null
        return WebUtilities.isSameOriginRedirect(url, ec.web.request) ? url : null
    }

    /**
     * Performs a login operation.
     */
    static void loginUser(ExecutionContext ec) {
        String authFlowId = ec.context.get("authFlowId") as String
        String returnTo = safeReturnTo(ec, ec.context.get("returnTo") as String)
        String baseUrl = ec.web.getWebappRootUrl(true, false)
        String callbackUrl = baseUrl + "/sso/callback"
        String loginFallback = baseUrl + "/Login"

        try {
            JEEContext context = new JEEContext(ec.web.request, ec.web.response)
            SessionStore sessionStore = sessionStoreFor(ec)
            MoquiSecurityGrantedAccessAdapter securityGrantedAccessAdapter = new MoquiSecurityGrantedAccessAdapter(ec)

            if (returnTo) {
                ec.web.sessionAttributes.put("moquiAuthFlowReturnTo", returnTo)
                sessionStore.set(context, SAML2StateGenerator.SAML_RELAY_STATE_ATTRIBUTE, returnTo)
            }

            Client client = new AuthenticationClientFactory(ec).build(authFlowId)
            Config config = makeConfig(callbackUrl, client)

            DefaultSecurityLogic.INSTANCE.perform(
                    config,
                    securityGrantedAccessAdapter,
                    authFlowId,
                    null,
                    null,
                    new JEEFrameworkParameters(ec.web.request, ec.web.response)
            )
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while performing login action", e)
            ec.web.response.sendRedirect(loginFallback)
        }
    }

    /**
     * Handles the login callback.
     */
    static void handleCallback(ExecutionContext ec) {
        String baseUrl = ec.web.getWebappRootUrl(true, false)
        String loginFallback = baseUrl + "/Login"

        try {
            JEEContext context = new JEEContext(ec.web.request, ec.web.response)
            SessionStore sessionStore = sessionStoreFor(ec)
            MoquiSecurityGrantedAccessAdapter securityGrantedAccessAdapter = new MoquiSecurityGrantedAccessAdapter(ec)
            Config config = makeConfig(baseUrl + "/sso/callback", new AuthenticationClientFactory(ec).buildAll())

            String fromRelay = context.getRequestParameter("RelayState").orElse(null)
            String redirectTo = safeReturnTo(ec, fromRelay) ?:
                    safeReturnTo(ec, ec.web.sessionAttributes.moquiAuthFlowReturnTo as String)

            DefaultCallbackLogic.INSTANCE.perform(
                    config,
                    null,
                    false,
                    null,
                    new JEEFrameworkParameters(ec.web.request, ec.web.response)
            )

            ProfileManager profileManager = new ProfileManager(context, sessionStore)
            securityGrantedAccessAdapter.adapt(context, sessionStore, profileManager.getProfiles())

            Optional<UserProfile> optionalProfile = profileManager.getProfile()
            if (optionalProfile.isPresent()) {
                UserProfile profile = optionalProfile.get()
                ((UserFacadeImpl) ec.user).internalLoginUser(profile.username)
                ec.web.sessionAttributes.put("moquiAuthFlowExternalLogout", true)
                if (redirectTo) {
                    ec.web.sessionAttributes.put("moquiAuthFlowReturnTo", redirectTo)
                } else {
                    ec.web.sessionAttributes.remove("moquiAuthFlowReturnTo")
                }
            }
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while handling callback", e)
            ec.web.response.sendRedirect(loginFallback)
        }
    }

    /**
     * Performs a logout operation.
     */
    static void logoutUser(ExecutionContext ec) {
        String returnTo = safeReturnTo(ec, ec.context.get("returnTo") as String)
        String baseUrl = ec.web.getWebappRootUrl(true, false)
        String loginFallback = baseUrl + "/Login"
        String callbackUrl = returnTo ?: loginFallback

        try {
            Config config = makeConfig(baseUrl + "/sso/callback", new AuthenticationClientFactory(ec).buildAll())

            DefaultLogoutLogic.INSTANCE.perform(
                    config,
                    callbackUrl,
                    null,
                    false,
                    false,
                    true,
                    new JEEFrameworkParameters(ec.web.request, ec.web.response)
            )

            ec.user.logoutUser()
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while performing logout action", e)
            ec.web.response.sendRedirect(loginFallback)
        }
    }
}
