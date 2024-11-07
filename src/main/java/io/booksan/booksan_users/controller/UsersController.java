package io.booksan.booksan_users.controller;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.booksan.booksan_users.config.auth.PrincipalDetails;
import io.booksan.booksan_users.config.jwt.JWTUtil;
import io.booksan.booksan_users.dto.UsersDTO;
import io.booksan.booksan_users.service.UsersService;
import io.booksan.booksan_users.vo.UsersVO;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UsersController {
	
	private final UsersService usersService;
	private final JWTUtil jwtUtil;
	
	@GetMapping("/auth/kakao/login")
	public void kakaoLogin(HttpServletResponse response) throws IOException {
	    String kakaoAuthUrl = String.format("https://kauth.kakao.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code",
	        "cedf95693b178edc09b8aa5db5774ee1", // 카카오 앱 키
	        URLEncoder.encode("http://localhost:8081/api/users/auth/kakao/callback", "UTF-8")
	    );
	    response.sendRedirect(kakaoAuthUrl);
	}
	
	// 카카오 콜백 - 액세스 토큰으로 사용자 정보를 요청하고 처리
    @GetMapping("/auth/kakao/callback")
    public void kakaoCallback(@RequestParam("code") String code, HttpServletResponse response) throws IOException {
        log.info("Kakao 코드받음: " + code);
        
        try {
            //RestTemplate 설정
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
            
            // 액세스 토큰 요청
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "authorization_code");
            params.add("client_id", "cedf95693b178edc09b8aa5db5774ee1");
            params.add("redirect_uri", "http://localhost:8081/api/users/auth/kakao/callback");
            params.add("code", code);
            
            HttpEntity<MultiValueMap<String, String>> kakaoTokenRequest = 
                new HttpEntity<>(params, headers);
            
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                "https://kauth.kakao.com/oauth/token",
                HttpMethod.POST,
                kakaoTokenRequest,
                String.class
            );
            
            // 액세스 토큰 추출
            Map<String, Object> tokenInfo = new ObjectMapper().readValue(tokenResponse.getBody(), Map.class);
            String accessToken = (String) tokenInfo.get("access_token");
            
            // 사용자 정보 요청
            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.add("Authorization", "Bearer " + accessToken);
            userInfoHeaders.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
            
            HttpEntity<MultiValueMap<String, String>> kakaoProfileRequest = 
                new HttpEntity<>(userInfoHeaders);
            
            ResponseEntity<String> profileResponse = restTemplate.exchange(
                "https://kapi.kakao.com/v2/user/me",
                HttpMethod.POST,
                kakaoProfileRequest,
                String.class
            );
            
            log.info("카카오 사용자 정보: " + profileResponse.getBody());
            
            // 이메일 추출
            String email = usersService.extractUserEmail(profileResponse.getBody());
            if (email == null) {
                response.sendRedirect("http://localhost:5173/login?error=email_not_found");
                return;
            }
            
            try {
                // 기존 회원인지 확인
                UsersVO existingUser = usersService.findByEmail(email);
                
                // 기존 회원이면 JWT 토큰 발급 후 메인으로
                Map<String, String> tokens = jwtUtil.generateTokenSet(Map.of(
                        "email", existingUser.getEmail(),
                        "nickname", existingUser.getNickname()
                ));
                log.info("JWT 토큰 생성을 위한 tokens: {}", tokens);
                
                
                response.sendRedirect("http://localhost:5173/chat/roomList?token=" + 
                	"accessToken=" + URLEncoder.encode(tokens.get("accessToken"), "UTF-8") +
                    "&refreshToken=" + URLEncoder.encode(tokens.get("refreshToken"), "UTF-8"));
                
                log.info("생성된 JWT 토큰들: accessToken={}, refreshToken={}", 
                		tokens.get("accessToken"), 
                		tokens.get("refreshToken")
                		);
            } catch (NoSuchElementException e) {
                // 신규 회원이면 회원가입 페이지로
                response.sendRedirect("http://localhost:5173/signup?email=" + 
                    URLEncoder.encode(email, "UTF-8") + "&code=" +
                    URLEncoder.encode(code, "UTF-8"));
            }
            
        } catch (Exception e) {
            log.error("카카오 로그인 처리 중 오류", e);
            response.sendRedirect("http://localhost:5173/login?error=auth_failed");
        }
    }
    
    // 회원 로그아웃
	@PostMapping("/logout")
	public ResponseEntity<Map<String, Object>> logout() {
		SecurityContextHolder.clearContext();
	    Map<String, Object> response = new HashMap<>();
	    response.put("status", "success");
	    response.put("message", "Logout successful");
	    return ResponseEntity.ok(response);
	}
	
	// 회원가입 폼
	@PostMapping("/signup")
    public ResponseEntity<Map<String, Object>> signupForm(@RequestBody UsersDTO usersDTO) {
		 log.info("회원가입 요청 - email: {}, uid: {}, nickname: {}", 
			        usersDTO.getEmail(), usersDTO.getUid(), usersDTO.getNickname());
        
        try {
            // 닉네임을 포함한 사용자 정보 저장
            if (usersDTO.getNickname() == null || usersDTO.getNickname().isEmpty()) {
                throw new IllegalArgumentException("닉네임은 필수입니다.");
            }

            // UsersVO 객체 생성
            UsersVO newUser = UsersVO.builder()
                    .email(usersDTO.getEmail()) // 이메일 설정
                    .uid(usersDTO.getUid())     // UID 설정
                    .nickname(usersDTO.getNickname()) // 닉네임 설정
                    .roleId(1)                  // 기본 역할 ID
                    .build();
            
            
            // 사용자 정보 삽입
            usersService.insertUser(newUser, usersDTO.getUid());
            
            // JWT 토큰 생성
            Map<String, String> tokens = jwtUtil.generateTokenSet(Map.of(
                "email", newUser.getEmail(),
                "nickname", newUser.getNickname()
            ));
            
            log.info("생성된 JWT 토큰들: accessToken={}, refreshToken={}", 
                    tokens.get("accessToken"), 
                    tokens.get("refreshToken")
            );
            
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "accessToken", tokens.get("accessToken"),
                    "refreshToken", tokens.get("refreshToken"),
                    "message", "회원가입 성공"
                ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "status", "error",
                    "message", e.getMessage()
                ));
        }
	}
}
