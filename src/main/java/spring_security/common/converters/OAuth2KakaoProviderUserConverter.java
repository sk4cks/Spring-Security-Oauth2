package spring_security.common.converters;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import spring_security.common.enums.OAuth2Config;
import spring_security.common.util.OAuth2Utils;
import spring_security.model.ProviderUser;
import spring_security.model.social.KakaoUser;
import spring_security.model.social.NaverUser;

public class OAuth2KakaoProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {
    @Override
    public ProviderUser converter(ProviderUserRequest providerUserRequest) {

        if(!providerUserRequest.clientRegistration().getRegistrationId().equals(OAuth2Config.SocialType.KAKAO.getSocialName())) {
            return null;
        }

        if(providerUserRequest.oAuth2User() instanceof OidcUser) {
            return null;
        }

        return new KakaoUser(OAuth2Utils.getOtherAttributes(providerUserRequest.oAuth2User(), "kakao_account", "profile"),
                providerUserRequest.oAuth2User(),
                providerUserRequest.clientRegistration());
    }
}
