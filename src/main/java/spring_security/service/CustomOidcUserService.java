package spring_security.service;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import spring_security.common.converters.ProviderUserRequest;
import spring_security.model.PrincipalUser;
import spring_security.model.ProviderUser;

@Service
public class CustomOidcUserService  extends AbstractOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(userRequest.getClientRegistration())
                .userNameAttributeName("sub")
                .build();

        OidcUserRequest oidcUserRequest = new OidcUserRequest(clientRegistration,
                                                    userRequest.getAccessToken(),
                                                    userRequest.getIdToken(),
                                                    userRequest.getAdditionalParameters());

        OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService = new OidcUserService();
        OidcUser oidcUser = oidcUserService.loadUser(oidcUserRequest);

        ProviderUserRequest providerUserRequest = new ProviderUserRequest(clientRegistration, oidcUser);

        ProviderUser providerUser = super.providerUser(providerUserRequest);
        //회원가입
        super.register(providerUser, userRequest);

        return new PrincipalUser(providerUser);
    }
}
