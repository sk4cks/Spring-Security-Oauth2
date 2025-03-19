package spring_security.service;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import spring_security.converters.ProviderUserConverter;
import spring_security.converters.ProviderUserRequest;
import spring_security.model.*;
import spring_security.model.social.GoogleUser;
import spring_security.model.social.KeycloakUser;
import spring_security.model.social.NaverUser;
import spring_security.model.users.User;
import spring_security.repository.UserRepository;

@Service
@Getter
public abstract class AbstractOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private ProviderUserConverter<ProviderUserRequest, ProviderUser> providerUserConverter;

    public void register(ProviderUser providerUser, OAuth2UserRequest userRequest) {

        User user = this.userRepository.findByUsername(providerUser.getUsername());

        if(user == null) {
            String registrationId = userRequest.getClientRegistration().getRegistrationId();
            this.userService.register(registrationId, providerUser);
        }else{
            System.out.println("user = " + user);
        }

    }

    public ProviderUser providerUser(ProviderUserRequest providerUserRequest) {

        return this.providerUserConverter.converter(providerUserRequest);
    }


}
