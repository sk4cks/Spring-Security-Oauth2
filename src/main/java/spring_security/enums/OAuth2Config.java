package spring_security.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

public class OAuth2Config {

    @Getter
    @AllArgsConstructor
    public enum SocialType{
        GOOGLE("google"),
        NAVER("naver"),
        KAKAO("kakao"),
        ;

        private String socialName;
    }
}
