package io.booksan.booksan_users.config.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    @Value("${booksan.front}")
    private String frontUrl;
    @Value("${booksan.chat}")
    private String chatUrl;
    @Value("${booksan.board}")
    private String boardUrl;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // preflight 요청은 인증을 타지 않도록 먼저 설정
                .authorizeHttpRequests(matchers -> matchers
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // OPTIONS 요청 먼저 허용
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll() // 여기로 옮김
                .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                .requestMatchers("/", "/api/**", "/js/**", "/css/**", "/images/**").permitAll()
                .anyRequest().authenticated() // anyRequest는 마지막에 한 번만
                )
                .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors
                .configurationSource(corsConfigurationSource())
                )
                .exceptionHandling(handling -> handling
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Unauthorized: " + authException.getMessage());
                })
                );
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // allowedOriginPatterns 대신 구체적인 origin 설정 시도
        configuration.setAllowedOrigins(Arrays.asList(frontUrl, boardUrl, chatUrl));

        // OPTIONS 메서드가 확실히 포함되도록
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // 현재 설정된 헤더는 유지
        configuration.setAllowedHeaders(Arrays.asList(
                "Origin",
                "Accept",
                "X-Requested-With",
                "Content-Type",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "Authorization"
        ));

        configuration.setExposedHeaders(Arrays.asList(
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials",
                "Authorization"
        ));

        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
