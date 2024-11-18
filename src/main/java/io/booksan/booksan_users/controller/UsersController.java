package io.booksan.booksan_users.controller;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.web.bind.annotation.DeleteMapping;
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

	@Value("${kakao.app.key}")
	private String kakaoAppKey;
	@Value("${kakao.kauth.http}")
	private String kakaoHttp;
	@Value("${kakao.redirect.callback}")
	private String kakaoCallback;
	@Value("${kakao.kapi.v2}")
	private String kakaoKapiV2;
	@Value("${kakao.kapi.v1}")
	private String kakaoKapiV1;
	@Value("${kakao.admin.key}")
	private String kakaoAdminKey;
	@Value("${kakao.oauth.token}")
	private String kakaoOauthToken;

	@GetMapping("/auth/kakao/login")
	public ResponseEntity<String> kakaoLogin() throws IOException {
		String kakaoAuthUrl = String.format(kakaoHttp, kakaoAppKey, // 카카오 앱 키
				URLEncoder.encode(kakaoCallback, "UTF-8"));
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
			log.info("카카오 유저 정보: " + userInfo);

			if (email == null) {
				return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "email_not_found"));
			}

			// 기존 회원 확인
			UsersVO existingUser = usersService.findByEmail(email);
			// 디버깅을 위한 로그 추가
			if (existingUser != null) {
				log.info("Found user: {}", existingUser);
				log.info("Disabled status: {}", existingUser.getDisabled());
			}

			if (existingUser != null) {
				// char 타입 비교
				if (existingUser.getDisabled() == 'Y') { // String 비교 대신 char 비교
					log.info("탈퇴한 회원, 회원가입으로 리다이렉트");
					return ResponseEntity
							.ok(Map.of("status", "success", "type", "new", "email", email, "kakaoId", kakaoId));
				}

				// 기존(탈퇴하지않은) 회원인 경우 JWT 토큰 발급
				Map<String, String> tokens = jwtUtil.createLoginTokens(
						Map.of("email", existingUser.getEmail(), "nickname", existingUser.getNickname()));
				// 프론트엔드로 필요한 정보 반환
				return ResponseEntity
						.ok(Map.of("status", "success", "type", "existing", "accessToken", tokens.get("accessToken"),
								"refreshToken", tokens.get("refreshToken"), "userEmail", existingUser.getEmail()));
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
		params.add("client_id", kakaoAppKey);
		params.add("redirect_uri", kakaoCallback);
		params.add("code", code);

		ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(kakaoOauthToken,
				new HttpEntity<>(params, headers), Map.class);

		return (String) tokenResponse.getBody().get("access_token");
	}

	// 카카오 사용자 정보 받기
	private Map<String, Object> getKakaoUserInfo(String accessToken) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Bearer " + accessToken);
		headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

		ResponseEntity<Map> userInfoResponse = restTemplate.postForEntity(kakaoKapiV2, new HttpEntity<>(headers),
				Map.class);

		return userInfoResponse.getBody();
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

			return ResponseEntity.ok(Map.of("status", "success", "accessToken", tokens.get("accessToken"),
					"refreshToken", tokens.get("refreshToken"), "message", "회원가입 성공"));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("status", "error", "message", e.getMessage()));
		}
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

	// 회원 로그아웃
	@PostMapping("/logout")
	public ResponseEntity<Map<String, Object>> logout() {
		try {
			// 사용자 세션 정보 제거
			SecurityContextHolder.clearContext();
			return ResponseEntity.ok(Map.of("status", "success", "message", "로그아웃 성공"));
		} catch (Exception e) {
			log.error("로그아웃 처리 중 오류", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("status", "error"));
		}
	}

	// 회원 탈퇴 (비활성화)
	@DeleteMapping("/delete")
	public ResponseEntity<Map<String, Object>> withdraw(@RequestHeader Map<String, String> headers) {
		log.info("회원탈퇴 요청 받음");
		try {
			// 토큰 검증 및 이메일 추출
			Map<String, Object> claims = validateAccessToken(headers);
			String email = (String) claims.get("email");

			if (email == null) {
				log.error("회원탈퇴 실패 - 인증 정보 없음");
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
						.body(Map.of("status", "error", "message", "인증 실패"));
			}

			// 유저 비활성화 처리
			usersService.disableUser(email);
			log.info("회원 비활성화 처리 완료 - email: {}", email);

			// 로그아웃 (토큰 제거)
			SecurityContextHolder.clearContext();

			return ResponseEntity.ok(Map.of("status", "success", "message", "회원 탈퇴가 완료되었습니다."));
		} catch (Exception e) {
			log.error("회원탈퇴 처리 중 오류", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("status", "error", "message", e.getMessage()));
		}
	}

	// 마이페이지 정보
	@GetMapping("/mypage")
	public ResponseEntity<Map<String, Object>> getProfile(@RequestHeader Map<String, String> headers) {
		log.info("마이페이지 API 호출");

		try {
			// 토큰 검증 및 인증 객체 생성
			Map<String, Object> claims = validateAccessToken(headers);
			String email = (String) claims.get("email");

			if (email != null) {
				// UserDetails 생성 및 인증 객체 설정
				UserDetails userDetails = principalDetailsService.loadUserByUsername(email);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication);

				// 사용자 정보 반환
				Map<String, Object> response = new HashMap<>();
				PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
				UsersVO user = principalDetails.getUser();

				response.put("email", user.getEmail());
				response.put("nickname", user.getNickname());

				return ResponseEntity.ok(response);
			}

			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		} catch (Exception e) {
			log.error("마이페이지 처리 중 에러", e);
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		}
	}

	// 회원 개인정보수정
	@PostMapping("/update")
	public ResponseEntity<Map<String, Object>> update(@RequestBody UsersVO usersVO,
			@RequestHeader Map<String, String> headers) {
		log.info("회원정보 수정 API 호출");

		try {
			// 토큰 검증 및 이메일 추출
			Map<String, Object> claims = validateAccessToken(headers);
			String email = (String) claims.get("email");
			log.info("토큰에서 추출한 이메일: {}", email);

			if (email != null) {
				// 이메일로 현재 사용자 정보 조회
				UsersVO currentUser = usersService.findByEmail(email);

				// uid와 이메일 설정
				usersVO.setUid(currentUser.getUid()); // 기존 사용자의 uid 설정
				usersVO.setEmail(email);

				log.info("최종 업데이트 데이터: {}", usersVO);
				usersService.updateUser(usersVO);

				return ResponseEntity.ok(Map.of("status", "success", "message", "정보가 수정되었습니다"));
			}

			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		} catch (Exception e) {
			log.error("사용자 정보 수정 실패", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("error", "정보 수정 실패: " + e.getMessage()));
		}
	}

	// 1. 액세스 토큰 검증
	private Map<String, Object> validateAccessToken(@RequestHeader Map<String, String> headers) {
		log.info("access token check: " + headers.toString());
		String accessToken = headers.get("accesstoken");

		if (accessToken == null) {
			throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.UNACCEPT);
		}

		try {
			return jwtUtil.validateToken(accessToken);
		} catch (MalformedJwtException e) {
			log.error("MalformedJwtException");
			throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.MALFORM);
		} catch (SignatureException e) {
			log.error("SignatureException");
			throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADSIGN);
		} catch (ExpiredJwtException e) {
			log.error("ExpiredJwtException");
			throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.EXPIRED);
		}
	}

	// 2. 리프레시 토큰으로 새 액세스 토큰 발급
	@PostMapping("/refresh")
	public ResponseEntity<Map<String, Object>> refreshAccessToken(@RequestBody UsersVO usersVO,
			@RequestHeader Map<String, String> headers) {
		log.info("회원정보 수정 API 호출");

		try {
			Map<String, Object> claims = validateAccessToken(headers);
			String email = (String) claims.get("email");
			log.info("토큰에서 추출한 이메일: {}", email);

			if (email != null) {
				// findByEmail로 수정
				UsersVO currentUser = usersService.findByEmail(email);

				usersVO.setUid(currentUser.getUid());
				usersVO.setEmail(email);

				log.info("최종 업데이트 데이터: {}", usersVO);
				usersService.updateUser(usersVO);

				return ResponseEntity.ok(Map.of("status", "success", "message", "정보가 수정되었습니다"));
			}

			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		} catch (Exception e) {
			log.error("사용자 정보 수정 실패", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("error", "정보 수정 실패: " + e.getMessage()));
		}
	}

	// 3. 인증 체크
	@PostMapping("/checkToken")
	public ResponseEntity<String> checkAuthentication(@RequestHeader Map<String, String> headers) {
		try {
			Map<String, Object> payload = validateAccessToken(headers);
			String email = (String) payload.get("email");
			log.info("****email: " + email);

			if (email != null) {
				UserDetails userDetails = principalDetailsService.loadUserByUsername(email);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());

				SecurityContextHolder.getContext().setAuthentication(authentication);
				return ResponseEntity.ok(email);
			}

			return ResponseEntity.ok(null);
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.ok(null);
		}
	}

}
