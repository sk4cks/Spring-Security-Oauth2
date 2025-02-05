package spring_security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class OAuth2ClientConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> request
                .requestMatchers("/home","/client","/error").permitAll()
                .anyRequest().authenticated());

//        http.oauth2Login(authLogin ->
//                authLogin.authorizationEndpoint(authEndPoint ->
//                        authEndPoint.authorizationRequestResolver(customOAuth2AuthenticationRequestResolver())));
        http.oauth2Client(Customizer.withDefaults());

        http.logout(logout -> logout
                .logoutSuccessUrl("/home"));
        return http.build();
    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthenticationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }


}
