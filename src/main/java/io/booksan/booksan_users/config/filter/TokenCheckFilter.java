package io.booksan.booksan_users.config.filter;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import io.booksan.booksan_users.config.auth.PrincipalDetailsService;
import io.booksan.booksan_users.config.jwt.JWTUtil;
import io.booksan.booksan_users.exception.AccessTokenException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

//요청을 받을 때마다 한번만 실행되는 필터(서블릿 필터와 같음)
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
		
	    String accessToken = request.getHeader("accessToken");
		
		//API 아니면 본래 처리를 할 수 있게 진행한다  
		if (!path.startsWith("/api/") || 
			path.startsWith("/api/users/auth/")|| 
		    path.equals("/api/users/signup") ||
		    path.equals("/api/users/logout") ||
		    path.equals("/api/users/checkNickname")
//		    path.equals("토큰체커나 리프레시토큰 체크부분 2개")
		    ){
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
	        jwtUtil.validateToken(accessToken); // 유효성만 확인
	        // 정상적인 경우, 요청을 계속 진행
	        filterChain.doFilter(request, response);
	    } catch (AccessTokenException e) {
	        // 토큰이 유효하지 않으면 오류 응답
	    	log.info("잘못된 토큰 요청" + e);
	        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	    }
	}
	
//    private Map<String, Object> validateAccessToken(String accessToken, String refreshToken, HttpServletResponse response) throws AccessTokenException {
//        // 쿠키에서 토큰 확인
////        String accessToken = headers.get("accessToken");
////        String refreshToken = headers.get("refreshToken");
//
//        if (accessToken == null) {
//            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.UNACCEPT);
//        }
//
//        try {
//            return jwtUtil.validateToken(accessToken);
//        } catch(MalformedJwtException malformedJwtException) {
//            log.error("MalformedJwtException----------------------");
//            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.MALFORM);
//        } catch(SignatureException signatureException) {
//            log.error("SignatureException----------------------");
//            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADSIGN);
//        } catch(ExpiredJwtException expiredJwtException) {
//        	// accessToken이 만료된 경우 refreshToken 확인
//            log.error("ExpiredJwtException----------------------");
//            if (refreshToken != null) {
//                try {
//                    // refresh token 유효성 검증
//                    Map<String, Object> refreshClaims = jwtUtil.validateToken(refreshToken);
//                    
//                    // access token 재발급
//                    String newAccessToken = jwtUtil.regenerateAccessToken(refreshClaims);
//                    
//                    // 새로운 access token을 쿠키에 설정 프론트에서 만들고있기 때문에 필요X
////                    Cookie newAccessTokenCookie = new Cookie("accessToken", newAccessToken);
////                    newAccessTokenCookie.setHttpOnly(true);
////                    newAccessTokenCookie.setSecure(true);
////                    newAccessTokenCookie.setPath("/");
////                    newAccessTokenCookie.setMaxAge(1800); // 30분
//                    
//                    // 새로운 토큰으로 검증 진행
//                    return jwtUtil.validateToken(newAccessToken);
//                } catch (Exception e) {
//                    throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.EXPIRED);
//                }
//            }
//            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.EXPIRED);
//        }
//    }
//    
//    private void setAuthentication(Map<String, Object> claims) throws AccessTokenException {
//    	
//        String email = (String)claims.get("email");
//        log.info("==== email정보 ====: " + email);
//        
//        // email에 대한 시큐리티 로그인 객체를 얻는다 
//        UserDetails userDetails = principalDetailsService.loadUserByUsername(email);
//        // userDetails 객체를 사용하여 인증객체로 생성한다  
//        UsernamePasswordAuthenticationToken authentication =
//                new UsernamePasswordAuthenticationToken(
//                    userDetails, null, userDetails.getAuthorities());
//        // 스프링 시큐리티에 인증객체를 설정한다 
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//    }
	

}
