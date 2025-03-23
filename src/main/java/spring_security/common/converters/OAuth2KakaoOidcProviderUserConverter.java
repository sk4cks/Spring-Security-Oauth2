package spring_security.common.converters;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import spring_security.common.enums.OAuth2Config;
import spring_security.common.util.OAuth2Utils;
import spring_security.model.ProviderUser;
import spring_security.model.social.KakaoOidcUser;
import spring_security.model.social.KakaoUser;

public class OAuth2KakaoOidcProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {
    @Override
    public ProviderUser converter(ProviderUserRequest providerUserRequest) {

        if(!providerUserRequest.clientRegistration().getRegistrationId().equals(OAuth2Config.SocialType.KAKAO.getSocialName())) {
            return null;
        }

        if(!(providerUserRequest.oAuth2User() instanceof OidcUser)) {
            return null;
        }

        return new KakaoOidcUser(OAuth2Utils.getMainAttributes(providerUserRequest.oAuth2User()),
                providerUserRequest.oAuth2User(),
                providerUserRequest.clientRegistration());
    }
}
