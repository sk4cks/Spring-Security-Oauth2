package spring_security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import spring_security.common.authority.CustomAuthorityMapper;
import spring_security.service.CustomOAuth2UserService;
import spring_security.service.CustomOidcUserService;

@Configuration
@EnableWebSecurity
public class OAuth2ClientConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;
    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private CustomOidcUserService customOidcUserService;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/static/js/**", "/static/images/**", "/static/css/**","/static/scss/**");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> request
                .requestMatchers("/api/user").hasAnyRole("SCOPE_profile","SCOPE_email","OAUTH2_USER")
                .requestMatchers("/api/oide").hasAnyRole("SCOPE_openid")
                .requestMatchers("/").permitAll()
                .anyRequest().authenticated());

        http.formLogin(formLogin -> formLogin
                .loginPage("/login")
                .loginProcessingUrl("/loginProc")
                .defaultSuccessUrl("/",true)
                .permitAll());

        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfoEndpointConfig ->
                        userInfoEndpointConfig
                                .userService(this.customOAuth2UserService)
                                .oidcUserService(this.customOidcUserService))
                .defaultSuccessUrl("/",true));
//        http.logout(logout -> logout.logoutSuccessUrl("/"));

        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        return http.build();
    }

}
