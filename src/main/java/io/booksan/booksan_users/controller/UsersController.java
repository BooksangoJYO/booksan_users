package io.booksan.booksan_users.controller;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.booksan.booksan_users.config.auth.PrincipalDetails;
import io.booksan.booksan_users.config.auth.PrincipalDetailsService;
import io.booksan.booksan_users.config.jwt.JWTUtil;
import io.booksan.booksan_users.dto.UsersDTO;
import io.booksan.booksan_users.exception.AccessTokenException;
import io.booksan.booksan_users.service.UsersService;
import io.booksan.booksan_users.vo.UsersVO;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UsersController {

	private final UsersService usersService;
	private final JWTUtil jwtUtil;
	private final PrincipalDetailsService principalDetailsService;
	
	@GetMapping("/auth/kakao/login")
	public ResponseEntity<String> kakaoLogin() throws IOException {
		String kakaoAuthUrl = String.format(
				"https://kauth.kakao.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&prompt=login",
				"cedf95693b178edc09b8aa5db5774ee1", // 카카오 앱 키
				URLEncoder.encode("http://localhost:5173/auth/kakao/callback", "UTF-8"));
		return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT).header("Access-Control-Expose-Headers", "Location")
				.header("Location", kakaoAuthUrl).build();
	}

	@GetMapping("/auth/kakao/callback")
	public ResponseEntity<Map<String, Object>> kakaoCallback(@RequestParam("code") String code,
			HttpServletResponse response) {
		log.info("Kakao 코드받음: " + code);

		try {
			// 카카오 액세스 토큰 발급
			String kakaoAccessToken = getKakaoAccessToken(code);
			log.info("Kakao access token: " + kakaoAccessToken);
			// 카카오 사용자 정보 받기
			Map<String, Object> userInfo = getKakaoUserInfo(kakaoAccessToken);
			String email = (String) ((Map<String, Object>) userInfo.get("kakao_account")).get("email");
			String kakaoId = String.valueOf(userInfo.get("id"));
			log.info("Kakao user info: " + userInfo);

			if (email == null) {
				return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "email_not_found"));
			}

			// 기존 회원 확인
			UsersVO existingUser = usersService.findByEmail(email);

			if (existingUser != null) {
				// 기존 회원인 경우 JWT 토큰 발급
				Map<String, String> tokens = jwtUtil.createLoginTokens(
						Map.of("email", existingUser.getEmail(), "nickname", existingUser.getNickname()));
				// 프론트엔드로 필요한 정보 반환
				return ResponseEntity.ok(Map.of("status", "success", "type", "existing", "accessToken",
						tokens.get("accessToken"), "refreshToken", tokens.get("refreshToken")));
			} else {
				// 신규 회원인 경우 필요한 정보 반환
				return ResponseEntity
						.ok(Map.of("status", "success", "type", "new", "email", email, "kakaoId", kakaoId));
			}
		} catch (Exception e) {
			log.error("카카오 로그인 처리 중 오류", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("status", "error", "message", e.getMessage()));
		}
	}

	// 카카오 액세스 토큰 받기
	private String getKakaoAccessToken(String code) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "authorization_code");
		params.add("client_id", "cedf95693b178edc09b8aa5db5774ee1");
		params.add("redirect_uri", "http://localhost:5173/auth/kakao/callback");
		params.add("code", code);

		ResponseEntity<Map> tokenResponse = restTemplate.postForEntity("https://kauth.kakao.com/oauth/token",
				new HttpEntity<>(params, headers), Map.class);

		return (String) tokenResponse.getBody().get("access_token");
	}

	// 카카오 사용자 정보 받기
	private Map<String, Object> getKakaoUserInfo(String accessToken) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer " + accessToken);
		headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

		ResponseEntity<Map> userInfoResponse = restTemplate.postForEntity("https://kapi.kakao.com/v2/user/me",
				new HttpEntity<>(headers), Map.class);

		return userInfoResponse.getBody();
	}
	
	@PostMapping("/logout")  
	public ResponseEntity<?> logout() {
	    try {
	        
	        return ResponseEntity.ok(Map.of(
	            "status", "success",
	            "message", "로그아웃 성공"
	        ));
	    } catch (Exception e) {
	        log.error("로그아웃 처리 중 오류", e);
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(Map.of("status", "error"));
	    }
	}
	
	
	// 회원 탈퇴
	@PostMapping("/exitexitextiexti")
	public ResponseEntity<?> kakaoLogout(HttpSession session) {
	    try {
	        // 세션에서 카카오 ID 가져오기 (로그인할 때 저장했다고 가정)
	        String kakaoId = "3775236163";
	        // 또는 DB에서 가져오기
	        // String kakaoId = userService.getKakaoId(userId);
	        
	        String reqURL = "https://kapi.kakao.com/v1/user/unlink";
	        URL url = new URL(reqURL);
	        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	        conn.setRequestMethod("POST");
	        conn.setDoOutput(true);
	        conn.setRequestProperty("Authorization", "KakaoAK " + "369eb7a2c20b2d6b1238f6e9a83ac993");

	        // target_id 파라미터 추가
	        String parameters = "target_id_type=user_id&target_id=" + kakaoId;
	        try (DataOutputStream out = new DataOutputStream(conn.getOutputStream())) {
	            out.writeBytes(parameters);
	            out.flush();
	        }

	        int responseCode = conn.getResponseCode();
	        log.info("카카오 연결끊기 응답코드: " + responseCode);

	        session.invalidate();
	        return ResponseEntity.ok(Map.of("status", "success"));

	    } catch (Exception e) {
	        log.error("카카오 로그아웃 처리 중 오류", e);
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(Map.of("status", "error"));
	    }
	}
	// 회원가입 폼
	@PostMapping("/signup")
	public ResponseEntity<Map<String, Object>> signupForm(@RequestBody UsersDTO usersDTO,
			HttpServletResponse response) {
		log.info("회원가입 요청 - email: {}, uid: {}, nickname: {}", usersDTO.getEmail(), usersDTO.getUid(),
				usersDTO.getNickname());

		try {
			// 닉네임을 포함한 사용자 정보 저장
			if (usersDTO.getNickname() == null || usersDTO.getNickname().isEmpty()) {
				throw new IllegalArgumentException("닉네임은 필수입니다.");
			}

			// UsersVO 객체 생성
			UsersVO newUser = UsersVO.builder().email(usersDTO.getEmail()) // 이메일 설정
					.uid(usersDTO.getUid()) // UID 설정
					.nickname(usersDTO.getNickname()) // 닉네임 설정
					.roleId(1) // 역할(롤) 설정
					.build();

			// 사용자 정보 삽입
			usersService.insertUser(newUser, usersDTO.getUid());

			// JWT 토큰 생성
			Map<String, String> tokens = jwtUtil
					.createLoginTokens(Map.of("email", newUser.getEmail(), "nickname", newUser.getNickname()));

//			// 쿠키 설정
//			Cookie accessTokenCookie = new Cookie("accessToken", tokens.get("accessToken"));
//			Cookie refreshTokenCookie = new Cookie("refreshToken", tokens.get("refreshToken"));
//
//			accessTokenCookie.setHttpOnly(true);
//			accessTokenCookie.setSecure(true);
//			accessTokenCookie.setPath("/");
//			accessTokenCookie.setMaxAge(1800);
//
//			refreshTokenCookie.setHttpOnly(true);
//			refreshTokenCookie.setSecure(true);
//			refreshTokenCookie.setPath("/");
//			refreshTokenCookie.setMaxAge(604800);
//
//			response.addCookie(accessTokenCookie);
//			response.addCookie(refreshTokenCookie);

			return ResponseEntity.ok(Map.of("status", "success", "accessToken", tokens.get("accessToken"),
					"refreshToken", tokens.get("refreshToken"), "message", "회원가입 성공"));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("status", "error", "message", e.getMessage()));
		}
	}

	// 마이페이지
	@GetMapping("/mypage")
	public ResponseEntity<Map<String, Object>> getProfile(Authentication authentication) {
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

		UsersVO user = principalDetails.getUser();

		return ResponseEntity.ok(Map.of("email", user.getEmail(), "nickname", user.getNickname(), "uid", user.getUid()
//	        "signupDate", user.getSignupDate()
//	        "roleId", user.getRoleId()
//	        "imgId", user.getImgId()

		// "bookmarks", bookmarkService.getUserBookmarks(user.getUid()), // 찜 목록
		));
	}

	// 회원 가입 닉네임 중복검사
	@GetMapping("/checkNickname")
	public ResponseEntity<Map<String, Object>> checkNickname(@RequestParam("nickname") String nickname) {
		try {
			boolean exists = usersService.isNicknameUsed(nickname);
			return ResponseEntity
					.ok(Map.of("available", !exists, "message", exists ? "이미 사용 중인 닉네임입니다." : "사용 가능한 닉네임입니다."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("available", false, "message", "닉네임 확인 중 오류가 발생했습니다."));
		}
	}

	// 회원 탈퇴 (비활성화)
	@PostMapping("/delete")
	public ResponseEntity<Map<String, Object>> withdraw(@RequestBody Map<String, String> request) {
		try {
			String email = request.get("email");
			// 유저 비활성화 처리
			usersService.disableUser(email);
			// 로그아웃 (토큰 제거)
			SecurityContextHolder.clearContext();

			return ResponseEntity.ok(Map.of("status", "success", "message", "회원 탈퇴가 완료되었습니다."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("status", "error", "message", e.getMessage()));
		}
	}

	// 회원 개인정보수정
	@PostMapping("/update")
	public ResponseEntity<Map<String, Object>> update(@RequestBody UsersVO usersVO, Authentication authentication) {

		try {
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			String uid = principalDetails.getUser().getUid(); // 현재 로그인한 사용자의 uid

			// 현재 로그인한 사용자의 uid로 설정
			usersVO.setUid(uid);

			usersService.updateUser(usersVO);

			return ResponseEntity.ok(Map.of("status", "success", "message", "정보가 수정되었습니다"));
		} catch (Exception e) {
			log.error("사용자 정보 수정 실패", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "정보 수정 실패"));
		}
	}
	
	
//	private Map<String, Object> validateAccessToken(@RequestHeader Map<String,String> headers) throws AccessTokenException {
//        // 쿠키에서 토큰 확인
//		log.info("***access token check***" + headers.toString());
//        String accessToken = headers.get("accesstoken");
//        String refreshToken = headers.get("refreshtoken");
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
//	@PostMapping("/checkToken")
//    public ResponseEntity<String> setAuthentication(@RequestHeader Map<String,String> headers){
//		try {
//	    	Map<String, Object> payload = validateAccessToken(headers);
//	        String email = (String)payload.get("email");
//	        log.info("***email은***"+email);
//	        if(email != null) {
//	        	// email에 대한 시큐리티 로그인 객체를 얻는다 
//	            UserDetails userDetails = principalDetailsService.loadUserByUsername(email);
//	            // userDetails 객체를 사용하여 인증객체로 생성한다  
//	            UsernamePasswordAuthenticationToken authentication =
//	                    new UsernamePasswordAuthenticationToken(
//	                        userDetails, null, userDetails.getAuthorities());
//	            // 스프링 시큐리티에 인증객체를 설정한다 
//	            SecurityContextHolder.getContext().setAuthentication(authentication);
//	            return ResponseEntity.ok(email);
//	        }
//	        else return ResponseEntity.ok(null);
//		}catch(Exception e) {
//			e.printStackTrace();
//			return ResponseEntity.ok(null);
//		}
//  
//    }

}
