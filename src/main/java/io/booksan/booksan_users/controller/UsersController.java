package io.booksan.booksan_users.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
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
import io.booksan.booksan_users.dto.UsersDTO;
import io.booksan.booksan_users.exception.ExistMemberException;
import io.booksan.booksan_users.service.UsersService;
import io.booksan.booksan_users.vo.UsersVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UsersController {
	
	private final UsersService usersService;
	
	//회원 소셜 로그인
	@PostMapping("/auth/socialLogin")
	public Map<String, String> socialLogin(@RequestBody UsersDTO usersDTO) {
        Map<String, String> loginResponse = new HashMap<>();
        String code = usersDTO.getUid(); // 클라이언트에서 전달된 카카오 코드
        log.info("Received Kakao code from client: " + code);
        // 유효성 검사
        if (code == null || code.isEmpty()) {
            loginResponse.put("status", "error");
            loginResponse.put("message", "유효하지 않은 카카오 코드입니다.");
            return loginResponse;
        }
        log.info("Received Kakao code from client: " + code);
        // 카카오 콜백 URI로 리다이렉트 (code를 통해 토큰 요청)
        loginResponse.put("redirect_uri", "/auth/kakao/callback?code=" + code);
        return loginResponse;
    }
	
	// 카카오 콜백 - 액세스 토큰으로 사용자 정보를 요청하고 처리하는 메소드
    @GetMapping("/auth/kakao/callback")
    public String kakaoCallback(@RequestParam("code")String code) {
    	
    	log.info("Received code from Kakao 코드받음: " + code);
    	//RestTemplate
        RestTemplate restTemplate = new RestTemplate();
        // HttpHeader 오브젝트 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
        
        // 액세스 토큰 요청 (HttpBody 오브젝트 생성)
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", "cedf95693b178edc09b8aa5db5774ee1"); // 실제 카카오 앱 키 입력
        params.add("redirect_uri", "http://localhost:8081/api/users/auth/kakao/callback"); // 실제 리다이렉트 URI 입력
        params.add("code", code);
        log.info("Requesting access token with code: " + code);
        // HttpHeader와 HttpBody를 하나의 오브젝트에 담기
        HttpEntity<MultiValueMap<String, String>> kakaoTokenRequest = new HttpEntity<>(params, headers);
        
        
        ResponseEntity<String> tokenResponse = restTemplate.exchange(
                "https://kauth.kakao.com/oauth/token",
                HttpMethod.POST,
                kakaoTokenRequest,
                String.class
        );
        
        log.info("https://kauth.kakao.com/oauth/token의 body = " + tokenResponse.getBody());
        log.info("Requesting access token with code: " + code);
        // 응답 결과에서 액세스 토큰 추출
        String accessToken = null;
        try {
        	Map<String, Object> tokenInfo = new ObjectMapper().readValue(tokenResponse.getBody(), Map.class);
        	accessToken = (String) tokenInfo.get("access_token");
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        log.info("Requesting access token with code: " + code);
        RestTemplate rt2 = new RestTemplate();
        
        // 사용자 정보 요청
        HttpHeaders userInfoHeaders = new HttpHeaders();
        userInfoHeaders.add("Authorization", "Bearer " + accessToken);
        userInfoHeaders.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
        
        HttpEntity<MultiValueMap<String, String>> kakaoProfileRequest = new HttpEntity<>(userInfoHeaders);
        
        // Http 요청하기 - Post방식으로 - 그리고 response 변수의 응답 받음.
        ResponseEntity<String> profileResponse = rt2.exchange(
                "https://kapi.kakao.com/v2/user/me",
                HttpMethod.POST,
                kakaoProfileRequest,
                String.class
        );
        log.info("카카오 정보:" , profileResponse.getBody());
        
        // 이메일 추출
        String email = usersService.extractUserEmail(profileResponse.getBody());
        if (email == null) {
        	log.error("Email extraction failed from profile response.");
            return "redirect:/error"; // 이메일 추출 실패 시 오류 처리
        }
        
        // 사용자 정보를 기반으로 회원가입 또는 로그인 처리
        UsersVO kakaoUser = UsersVO.builder()
                .email(email)
                .roleId(1)
                .uid(code)
                .build();

        //가입자 비가입자 체크 처리
        try {
            usersService.insertUser(kakaoUser, code);
            log.info("기존 회원이 아니기에 자동 회원가입을 진행함");
        } catch (ExistMemberException e) {
        	log.info("기존에 회원 가입된 경우 다음으로 진행함");
        } catch (Exception e) {
            e.printStackTrace();
        }
        log.info("자동 로그인을 진행합니다.");
        
        // 로그인 처리
        PrincipalDetails principalDetails = new PrincipalDetails(kakaoUser);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
        		principalDetails, 
        		null, // 토큰 인증시 패스워드는 알수 없어 null 값을 전달하는 것임 
        		principalDetails.getAuthorities()); //사용자가 소유한 역할 권한을 전달한다
        // 강제로 시큐리티의 세션에 접근하여 값 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        return "로그인 성공";

    }
	

	@PostMapping("/logout")
	public String logout() {
	    SecurityContextHolder.clearContext(); // 세션 초기화
	    return "redirect:/home"; // 홈페이지로 리다이렉트
	}
	
	public String jwtAuth() {
		return "미구현";
	}
	
	@GetMapping("/test")
    public String testConnection() {
        log.info("Test connection endpoint called");
        return "Connection successful";
    }
	
}
