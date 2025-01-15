package spring_security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

    private static final Consumer<OAuth2AuthorizationRequest.Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
            .withPkce();

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final AntPathRequestMatcher authorizationRequestMatcher;

    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;

    public CustomOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {

        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");

        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = resolveRegistrationId(request);
        if (registrationId == null) {
            return null;
        }

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
        if(registrationId.equals("keycloakWithPKCE")) {
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = this.defaultResolver.resolve(request);
            return customResolve(oAuth2AuthorizationRequest, clientRegistration);
        }

        return this.defaultResolver.resolve(request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
        if(clientRegistrationId.equals("keycloakWithPKCE")) {
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = this.defaultResolver.resolve(request);
            return customResolve(oAuth2AuthorizationRequest, clientRegistration);
        }
        return this.defaultResolver.resolve(request, clientRegistrationId);
    }

    private OAuth2AuthorizationRequest customResolve(OAuth2AuthorizationRequest authorizationRequest, ClientRegistration clientRegistration) {
        Map<String,Object> extraParam = new HashMap<>();

        extraParam.put("customName1","customValue1");
        extraParam.put("customName2","customValue2");
        extraParam.put("customName3","customValue3");

        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest
                .from(authorizationRequest)
                .additionalParameters(extraParam);

        DEFAULT_PKCE_APPLIER.accept(builder);

        return builder.build();
    }
    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher.matcher(request)
                    .getVariables()
                    .get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }
}
