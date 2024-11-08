package io.booksan.booksan_users.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.booksan.booksan_users.config.auth.PrincipalDetailsService;
import io.booksan.booksan_users.config.filter.TokenCheckFilter;
import io.booksan.booksan_users.config.jwt.JWTUtil;
import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
	
	private final JWTUtil jwtUtil;
    private final PrincipalDetailsService principalDetailsService;
    
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(matchers -> matchers
                .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                .requestMatchers(
                    "/",
                    "/api/users/auth/**",  // 소셜 로그인 관련
                    "/api/users/signup",   // 회원가입
                    "/js/**",
                    "/css/**",
                    "/images/**"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(
                new TokenCheckFilter(jwtUtil, principalDetailsService),
                UsernamePasswordAuthenticationFilter.class
            );
        
        return http.build();
    }
	
	
}
