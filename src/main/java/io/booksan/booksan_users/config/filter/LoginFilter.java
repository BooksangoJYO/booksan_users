package io.booksan.booksan_users.config.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StreamUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.booksan.booksan_users.config.jwt.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class LoginFilter extends AbstractAuthenticationProcessingFilter {
	private static final String CONTENT_TYPE = "application/json";//json 타입의 데이터로만 로그인을 진행한다.
	private final ObjectMapper objectMapper;
	private final JWTUtil jwtUtil;
	
	public LoginFilter(String defaultFilterPrrocessingUrl, ObjectMapper objectMapper, JWTUtil jwtUtil) {
		super(defaultFilterPrrocessingUrl);
		this.objectMapper = objectMapper;
		this.jwtUtil = jwtUtil;

		//로그인 성공시 처리 핸들러 등록  
		this.setAuthenticationSuccessHandler((request, response, authentication) -> {
			//authentication : 인증된 로그인 정보 
			log.info("로그인 성공시 처리 핸들러 ............." );
			log.info("인증된 로그인 정보 : {}", authentication);
			log.info("인증된 로그인 아이디 : {}", authentication.getName());
			
			// JWT claim 생성
            Map<String, Object> claim = Map.of("uid", authentication.getName());
            
            // generateTokenSet 사용
            Map<String, String> tokens = jwtUtil.generateTokenSet(claim);
            
            // json 응답
            objectMapper.writeValue(response.getWriter(), tokens);
		});
		
		//로그인 실패시 처리 핸들러 등록  
		this.setAuthenticationFailureHandler((request, response, exception) -> {
			log.info("로그인 실패시 처리 핸들러 등록 ............." );
		});
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		// TODO Auto-generated method stub
		log.info("LoginFilter ----------------------------- ");
		
		log.info("ContentType = {}", request.getContentType());
		if(request.getContentType() == null || !request.getContentType().startsWith(CONTENT_TYPE)  ) {
			log.info("Authentication Content-Type not supported: " + request.getContentType());
			return null;
		}

		//json으로 요청한 문자열을 얻는다
		String jsonText = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);

		//JSON 문자열을 Map 객체로 변환 한다
		Map<String, String> jsonData = objectMapper.readValue(jsonText, Map.class);
		log.info("jsonData = {}", jsonData);

		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(jsonData.get("uid"), jsonData.get("pwd"));
		return getAuthenticationManager().authenticate(authenticationToken);
	}
	
	
}
