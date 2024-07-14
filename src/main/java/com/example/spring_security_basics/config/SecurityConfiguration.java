package com.example.spring_security_basics.config;

import com.example.spring_security_basics.service.MyUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {

    MyUserDetailService myUserDetailService;

    public SecurityConfiguration(MyUserDetailService myUserDetailService) {
        this.myUserDetailService = myUserDetailService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.authorizeHttpRequests(
                        authorize -> {
                            authorize.requestMatchers("/css/**", "/js/**", "/images/**").permitAll();
                            authorize.requestMatchers("/login", "/error/**", "/logout", "/", "/home").permitAll();
                            authorize.requestMatchers("/admin/**").hasRole("ADMIN");
                            authorize.requestMatchers("/user/**").hasRole("USER");
                            authorize.anyRequest().authenticated();
                        }
                ).formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .permitAll())
                .logout(logout -> logout.logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .csrf(AbstractHttpConfigurer::disable).build();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails normalUser = User
//                .builder()
//                .username("patzu")
//                .password("$2a$12$JRP8vS.dBHiGYBAkT69K9.UEt/F1P09jYVhUAAfwTJMhiKK8HjLxu")
//                .roles("USER")
//                .build();
//        UserDetails adminUser = User
//                .builder()
//                .username("davoud")
//                .password("$2a$12$JRP8vS.dBHiGYBAkT69K9.UEt/F1P09jYVhUAAfwTJMhiKK8HjLxu")
//                .roles("ADMIN", "USER")
//                .build();
//        return new InMemoryUserDetailsManager(normalUser, adminUser);
//    }

    @Bean
    public UserDetailsService userDetailService() {
        return myUserDetailService;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(myUserDetailService);
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
