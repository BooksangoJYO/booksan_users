package io.booksan.booksan_users.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import io.booksan.booksan_users.config.auth.AuthFailureHandler;
import io.booksan.booksan_users.config.auth.AuthSucessHandler;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
@EnableWebSecurity
@Slf4j
public class SecurityConfig {
	
	final private AuthSucessHandler authSucessHandler;
	
	final private AuthFailureHandler authFailureHandler;
	
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // CSRF 비활성화
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", 
                				 "/api/**",
                				 "/auth/**", 
                				 "/api/auth/**", 
                				 "/js/**",
                				 "/css/**",
                				 "/images/**"
                				 ).permitAll() // 소셜 로그인 관련 경로 공개
                .requestMatchers("/refreshToken").authenticated() // 리프레시 토큰은 인증된 사용자만 접근 가능
                .anyRequest().authenticated() // 나머지 요청은 인증 필요
            )
//            .formLogin(loginForm -> loginForm // 로그인 폼 설정
//                .loginPage("/auth/loginForm.do") // 로그인 페이지 URL
//                .loginProcessingUrl("/auth/login.do") // 로그인 처리 URL
//                .successHandler(authSucessHandler) // 성공시 처리 핸들러
//                .failureHandler(authFailureHandler) // 실패시 처리 핸들러
//            )
            .logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // 로그아웃 URL
                .logoutSuccessUrl("/") // 성공시 리턴 URL
                .invalidateHttpSession(true) // 인증 정보 삭제 및 세션 무효화
                .deleteCookies("JSESSIONID") // JSESSIONID 쿠키 삭제
                .permitAll()
            )
            .sessionManagement(session -> session
                .maximumSessions(1) // 최대 세션 수 설정
                .maxSessionsPreventsLogin(false) // 중복 로그인 설정
                .expiredUrl("/") // 세션 만료시 이동 URL
            )
            .addFilterBefore(new OncePerRequestFilter() {
                @Override
                protected void doFilterInternal(HttpServletRequest request, 
                    HttpServletResponse response, 
                    FilterChain filterChain) throws ServletException, IOException {
                    log.info("Request URL: " + request.getRequestURL());
                    log.info("Request Method: " + request.getMethod());
                    try {
						filterChain.doFilter(request, response);
					} catch (java.io.IOException e) {
						e.printStackTrace();
					} catch (ServletException e) {
						e.printStackTrace();
					}
                }
            }, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
	
	
}
