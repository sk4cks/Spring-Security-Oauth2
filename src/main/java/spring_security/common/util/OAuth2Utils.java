package spring_security.common.util;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import spring_security.common.enums.OAuth2Config;
import spring_security.model.Attributes;
import spring_security.model.PrincipalUser;

import java.util.Map;

public class OAuth2Utils {

    public static Attributes getMainAttributes(OAuth2User oAuth2User) {

        return Attributes.builder()
                .mainAttributes(oAuth2User.getAttributes())
                .build();
    }

    public static Attributes getSubAttributes(OAuth2User oAuth2User, String subAttributesKey) {
        Map<String, Object> subAttributes = (Map<String, Object>) oAuth2User.getAttributes().get(subAttributesKey);

        return Attributes.builder()
                .subAttributes(subAttributes)
                .build();
    }

    public static Attributes getOtherAttributes(OAuth2User oAuth2User, String subAttributesKey, String otherAttributesKey) {
        Map<String, Object> subAttributes = (Map<String, Object>) oAuth2User.getAttributes().get(subAttributesKey);
        Map<String, Object> otherAttributes = (Map<String, Object>) subAttributes.get(otherAttributesKey);

        return Attributes.builder()
                .subAttributes(subAttributes)
                .otherAttributes(otherAttributes)
                .build();
    }

    public static String oAuth2UserName(OAuth2AuthenticationToken authentication, PrincipalUser principalUser) {

        String userName;
        String registrationId = authentication.getAuthorizedClientRegistrationId();
        OAuth2User oAuth2User = principalUser.providerUser().getOAuth2User();

        // Google, Facebook, Apple
        Attributes attributes = OAuth2Utils.getMainAttributes(oAuth2User);
        userName = (String) attributes.getMainAttributes().get("name");

        //Naver
        if(registrationId.equals(OAuth2Config.SocialType.NAVER.getSocialName())) {
            attributes = OAuth2Utils.getSubAttributes(oAuth2User, "response");
            userName = (String) attributes.getSubAttributes().get("name");

        // Kakao
        } else if (registrationId.equals(OAuth2Config.SocialType.KAKAO.getSocialName())) {

            // OpenID Connect
            if(oAuth2User instanceof OidcUser) {
                attributes = OAuth2Utils.getMainAttributes(oAuth2User);
                userName = (String) attributes.getMainAttributes().get("nickname");

            } else {
                attributes = OAuth2Utils.getOtherAttributes(principalUser, "profile", null);
                userName = (String) attributes.getSubAttributes().get("nickname");
            }
        }

        return userName;
    }
}
