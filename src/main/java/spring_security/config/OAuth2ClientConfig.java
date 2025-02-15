package spring_security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import spring_security.CustomOAuth2AuthorizationRequestResolver;
import spring_security.filter.CustomOAuth2AuthenticationFilter;

@Configuration
@EnableWebSecurity
public class OAuth2ClientConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager;

    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> request
                .requestMatchers("/", "/oauth2Login", "/client").permitAll()
                .anyRequest().authenticated());

//        http.oauth2Login(authLogin ->
//                authLogin.authorizationEndpoint(authEndPoint ->
//                        authEndPoint.authorizationRequestResolver(customOAuth2AuthenticationRequestResolver())));
        http.oauth2Client(Customizer.withDefaults());
        http.addFilterBefore(customOAuth2AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private CustomOAuth2AuthenticationFilter customOAuth2AuthenticationFilter() {
        CustomOAuth2AuthenticationFilter auth2AuthenticationFilter
                 = new CustomOAuth2AuthenticationFilter(this.auth2AuthorizedClientManager, this.authorizedClientRepository);

        auth2AuthenticationFilter.setAuthenticationSuccessHandler(((request, response, authentication) -> {
            response.sendRedirect("/home");
        }));

        return auth2AuthenticationFilter;
    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthenticationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }


}
