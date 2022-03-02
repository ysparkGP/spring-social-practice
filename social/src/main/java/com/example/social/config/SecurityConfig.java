package com.example.social.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //yml 설정들을 읽어오기위한 객체
    private final Environment environment;
    private final String registration = "spring.security.oauth2.client.registration.";

    private final FacebookOAuth2UserService facebookOAuth2UserService;
    private final GoogleOAuth2UserService googleOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests(authorize -> authorize
                .antMatchers("/login", "/index").permitAll()
                .anyRequest().authenticated()
        )
                //.oauth2Login(Customizer.withDefaults());
                .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .authorizedClientService(authorizedClientService())
                        // OAuth2 로그인을 성공한 이후 사용자 정보를 가져오는 것을 담당하는 객체
                        .userInfoEndpoint(
                                user-> user
                                        .oidcUserService(googleOAuth2UserService) // google 인증, OpenID Connect 1.0
                                        .userService(facebookOAuth2UserService) // facebook 인증, OAuth2 통신
                        )
                );
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(){
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        final List<ClientRegistration> clientRegistrations = Arrays.asList(
                googleClientRegistration(),
                facebookClientRegistration()
        );

        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }

    // Provider 정의
    private ClientRegistration googleClientRegistration(){
        final String id = environment.getProperty(registration + "google.client-id");
        final String secret = environment.getProperty(registration + "google.client-secret");

        return CommonOAuth2Provider
                .GOOGLE
                .getBuilder("google")
                .clientId(id)
                .clientSecret(secret)
                .build();
    }

    private ClientRegistration facebookClientRegistration(){
        final String id = environment.getProperty(registration + "facebook.client-id");
        final String secret = environment.getProperty(registration + "facebook.client-secret");

        return CommonOAuth2Provider
                .FACEBOOK
                .getBuilder("facebook")
                .clientId(id)
                .clientSecret(secret)
                .scope(
                        "public_profile",
                        "email",
                        "user_birthday",
                        "user_gender"
                )
                .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,picture,gender,birthday")
                .build();
    }
}
