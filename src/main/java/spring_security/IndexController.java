package spring_security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

@RestController
public class IndexController {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    public OAuth2User user(String accessToken) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
        OAuth2AccessToken oAuth2AccessToken =
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,accessToken, Instant.now(),Instant.MAX);

        OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration,oAuth2AccessToken);
        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(oAuth2UserRequest);

        return oAuth2User;
    }

    @GetMapping("/oidc")
    public OAuth2User oidc(String accessToken, String idToken) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
        OAuth2AccessToken oAuth2AccessToken =
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,accessToken,Instant.now(),Instant.MAX, Set.of("openid"));

        Map<String,Object> idTokenClaims = Map.of(
                IdTokenClaimNames.ISS, "http://localhost:8080/realms/oauth2"
                ,IdTokenClaimNames.SUB, "OIDC0"
                ,"preferred_username","user"
        );

        OidcIdToken oidcIdToken = new OidcIdToken(idToken,Instant.now(),Instant.MAX,idTokenClaims);

        OidcUserRequest oidcUserRequest = new OidcUserRequest(clientRegistration,oAuth2AccessToken,oidcIdToken);
        OidcUserService oidcUserService = new OidcUserService();
        OAuth2User oAuth2User = oidcUserService.loadUser(oidcUserRequest);

        return oAuth2User;
    }
}
