//package io.booksan.booksan_users.config.filter;
//
//import java.io.IOException;
//import java.util.Map;
//
//import org.springframework.http.HttpHeaders;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.web.bind.annotation.RequestHeader;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import io.booksan.booksan_users.config.auth.PrincipalDetailsService;
//import io.booksan.booksan_users.config.jwt.JWTUtil;
//import io.booksan.booksan_users.exception.AccessTokenException;
//import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.MalformedJwtException;
//import io.jsonwebtoken.security.SignatureException;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//
////요청을 받을 때마다 한번만 실행되는 필터(서블릿 필터와 같음)
//@Slf4j
//@RequiredArgsConstructor
//public class TokenCheckFilter extends OncePerRequestFilter {
//
//	private final JWTUtil jwtUtil;
//	private final PrincipalDetailsService principalDetailsService;
//	
//	@Override
//	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//			throws ServletException, IOException {
//		//요청 URL을 얻는다
//		final String path = request.getRequestURI();
//		
//		//API 아니면 본래 처리를 할 수 있게 진행한다  
//		if (!path.startsWith("/api/") || 
//			path.startsWith("/api/users/auth/")|| 
//		    path.equals("/api/users/signup") ||
//		    path.equals("/api/users/logout") ||
//		    path.equals("/api/users/checkNickname")){
//			filterChain.doFilter(request, response);
//			return;
//		}
//
//		log.info("JWT 토큰이 존재하고 유효한지 확인한다");
//		log.info("jwtUtil = {}", jwtUtil);
//		
//        try {
//        	//JWT 검증 및 인증 처리를 한다 
//            setAuthentication(request, response);
//            
//            //요청한 부분으로 이동한다 
//            filterChain.doFilter(request,response);
//        } catch(AccessTokenException accessTokenException){
//        	//응답으로 토큰 예외 발생시 오류를 전달한다 
//            accessTokenException.sendResponseError(response);
//        }
//	}
//	
//    private Map<String, Object> validateAccessToken(@RequestHeader Map<String,String> headers) throws AccessTokenException {
//        // 쿠키에서 토큰 확인
//        String accessToken = headers.get("accessToken");
//        String refreshToken = headers.get("refreshToken");
//
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
//                    // 새로운 access token을 쿠키에 설정
//                    Cookie newAccessTokenCookie = new Cookie("accessToken", newAccessToken);
//                    newAccessTokenCookie.setHttpOnly(true);
//                    newAccessTokenCookie.setSecure(true);
//                    newAccessTokenCookie.setPath("/");
//                    newAccessTokenCookie.setMaxAge(1800); // 30분
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
//    private void setAuthentication(@RequestHeader Map<String,String> headers) throws AccessTokenException {
//    	Map<String, Object> payload = validateAccessToken(headers);
//    	
//        String email = (String)payload.get("email");
//        log.info("email: " + email);
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
//	
//
//}
