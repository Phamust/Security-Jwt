package io.phamust.securityjwt.security.config;

import io.phamust.securityjwt.appuser.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

        private final AppUserRepository appUserRepository;

    @Bean
    public UserDetailsService userDetailsService(){
        return username -> appUserRepository.findByEmail(username)
                .orElseThrow(()-> new UsernameNotFoundException("username not found"));
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    //Authentication manager is responsible to manage authentication,
    // Helping authenticate user using password and username,
    //Getting the default authentication provider from AuthenticationConfiguration by spring security.
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    //Data access object responsible to fetch user details and encode password ... here we used DaoAuthenticationProvider
   @Bean
    public AuthenticationProvider authenticationProvider(){
       DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
       authenticationProvider.setUserDetailsService(userDetailsService());
       authenticationProvider.setPasswordEncoder(passwordEncoder());
       return authenticationProvider;
   }


}
