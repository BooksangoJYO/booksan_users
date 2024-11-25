package io.booksan.booksan_users.config.filter;

import java.io.IOException;
import java.util.Map;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.booksan.booksan_users.config.auth.PrincipalDetailsService;
import io.booksan.booksan_users.config.jwt.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

//요청을 받을 때마다 한번만 실행되는 필터(서블릿 필터와 같음)
@Component
@Slf4j
@RequiredArgsConstructor
public class TokenCheckFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final PrincipalDetailsService principalDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        //요청 URL을 얻는다
        final String path = request.getRequestURI();
        log.info("***필터실행***" + path);
        log.info("***필터 확인 **" + request.getHeader("accessToken"));
        String accessToken = request.getHeader("accessToken");

        //API 아니면 본래 처리를 할 수 있게 진행한다  
        if (!path.startsWith("/api/")
                || path.startsWith("/api/users/auth/")
                || path.equals("/api/users/signup")
                || path.equals("/api/users/logout")
                || path.equals("/api/users/checkNickname")
                || path.equals("/api/users/refresh")
                || path.startsWith("/api/users/read/download")
                || path.equals("/api/users/checkToken")
                || path.startsWith("/api/users/userInfoBy")) {
            filterChain.doFilter(request, response);
            return;
        }

        log.info("JWT 토큰이 존재하고 유효한지 확인한다");
        log.info("jwtUtil = {}", jwtUtil);

        // JWT 토큰 검증
        if (accessToken == null) {
            // 토큰이 없으면 오류 처리
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Access token is missing");
            return;
        }

        try {
            // 토큰 검증 후 클레임 추출
            Map<String, Object> claims = jwtUtil.validateToken(accessToken); // 유효성만 확인
            String email = (String) claims.get("email");
            // 정상적인 경우, 요청을 계속 진행
            log.info("***이메일" + email);
            if (email != null) {
                UserDetails userDetails = principalDetailsService.loadUserByUsername(email);
                // userDetails 객체를 사용하여 인증객체로 생성한다  
                UsernamePasswordAuthenticationToken authentication
                        = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                // 스프링 시큐리티에 인증객체를 설정한다 
                SecurityContextHolder.getContext().setAuthentication(authentication);
                filterChain.doFilter(request, response);
                return;
            }
            log.info("잘못된 토큰 요청");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (Exception e) {
            // 토큰이 유효하지 않으면 오류 응답
            log.info("잘못된 토큰 요청" + e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
        log.info(path + " 요청 처리 완료");
    }
}
