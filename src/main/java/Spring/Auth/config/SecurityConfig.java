package Spring.Auth.config;

import Spring.Auth.filter.JwtAuthFilter;
import Spring.Auth.service.UserService;
import Spring.Auth.util.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    private final JwtAuthFilter jwtAuthFilter;
    private final JwtUtil jwtUtil;
    private final UserService userService;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, JwtUtil jwtUtil, UserService userService) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/auth/**",
                                "/login/**",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/login/oauth2/code/**",
                                "/",
                                "/index.html"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login(oauth -> oauth
                        .successHandler((request, response, authentication) -> {
                            var principal = (DefaultOAuth2User) authentication.getPrincipal();
                            String email = principal.getAttribute("email");

                            // generate JWT using your JwtService
                            String jwtToken = jwtUtil.generateJwtToken(email, 5);
                            System.out.println("TOKEN : "+jwtToken);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"token\": \"" + jwtToken + "\"}");
                        })
                        .failureHandler((request, response, exception) -> {
                            response.setContentType("application/json");
                            response.getWriter().write("{\"error\": \"" + exception.getMessage() + "\"}");
                        })
                );
        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
