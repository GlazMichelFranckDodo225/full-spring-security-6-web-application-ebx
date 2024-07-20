package com.dgmf.config.security;

import com.dgmf.jwt.AuthEntryPointJwt;
import com.dgmf.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

// Provide Configurations for Spring IoC Container (ApplicationContext)
@Configuration
// Enable Web Security Features and Allows Customization
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    // With AutoConfiguration (H2 in application.properties File), Spring
    // will Automatically Inject the Datasource (H2)
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    // Tells Spring IoC Container (ApplicationContext) to Hold a Bean Based
    // the Below Configurations
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // Any Request Should Be Authenticated
        http.authorizeHttpRequests(
                requests -> requests
                        // Disable Spring Security for H2 InMemory DB
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/signin", "/login").permitAll()
                        .anyRequest().authenticated()
        );
        // To Disable Cookies Management and Make API Stateless
        http.sessionManagement(
                session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        // We have Disabled Form-Based Authentication
        // http.formLogin(withDefaults());
        // Tells Spring Security to Use Basic Authentication (Alert Box)
        // with Username and Password
        // http.httpBasic(withDefaults());
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        // For Http Headers, allows Frame Options for the Same Origins
        http.headers(headers -> headers.frameOptions(
                HeadersConfigurer.FrameOptionsConfig::sameOrigin
            )
        );
        http.csrf(AbstractHttpConfigurer::disable);
        http.addFilterBefore(
                authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class
        );
        // Returns an Object of SecurityFilterChain Type
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            UserDetails user = User.withUsername("user")
                    // .password("{noop}user") ==> Plain Text Storage
                    .password(passwordEncoder().encode("user"))
                    .roles("USER")
                    .build();

            UserDetails admin = User.withUsername("admin")
                    // .password("{noop}admin") ==> Plain Text Storage
                    .password(passwordEncoder().encode("admin"))
                    .roles("ADMIN")
                    .build();

            // Set up the Datasource
            JdbcUserDetailsManager jdbcUserDetailsManager =
                    new JdbcUserDetailsManager(dataSource);
            jdbcUserDetailsManager.createUser(user);
            jdbcUserDetailsManager.createUser(admin);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration builder
    ) throws Exception {
        return builder.getAuthenticationManager();
    }
}
