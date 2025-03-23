package spring_security.common.converters;

import spring_security.common.enums.OAuth2Config;
import spring_security.common.util.OAuth2Utils;
import spring_security.model.ProviderUser;
import spring_security.model.social.NaverUser;
import spring_security.model.users.FormUser;
import spring_security.model.users.User;

public class UserDetailsProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {
    @Override
    public ProviderUser converter(ProviderUserRequest providerUserRequest) {

        if(providerUserRequest.user() == null) {
            return null;
        }

        User user = providerUserRequest.user();

        return FormUser.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .email(user.getEmail())
                .authorities(user.getAuthorities())
                .provider("none")
                .build();
    }
}
