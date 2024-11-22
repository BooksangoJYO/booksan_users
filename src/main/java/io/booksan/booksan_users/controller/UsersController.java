package io.booksan.booksan_users.controller;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import io.booksan.booksan_users.config.jwt.JWTUtil;
import io.booksan.booksan_users.dto.ImageFileDTO;
import io.booksan.booksan_users.dto.UsersDTO;
import io.booksan.booksan_users.service.UsersService;
import io.booksan.booksan_users.util.MapperUtil;
import io.booksan.booksan_users.vo.UsersVO;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UsersController {

    private final MapperUtil mapperUtil;
    private final UsersService usersService;
    private final JWTUtil jwtUtil;

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
            UsersDTO existingUser = usersService.findByEmail(email);
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
                usersService.insertLoginLog(email);
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
            usersService.insertLoginLog(newUser.getEmail());
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

    // 회원 탈퇴 (비활성화)
    @DeleteMapping("/delete")
    public ResponseEntity<Map<String, Object>> withdraw(@AuthenticationPrincipal UserDetails userDetails) {
        log.info("회원탈퇴 요청 받음");
        try {
            // 토큰 검증 및 이메일 추출
            String email = userDetails.getUsername();

            if (email == null) {
                log.error("회원탈퇴 실패 - 인증 정보 없음");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("status", "error", "message", "인증 실패"));
            }

            // 유저 비활성화 처리
            usersService.disableUser(email);
            log.info("회원 비활성화 처리 완료 - email: {}", email);
            return ResponseEntity.ok(Map.of("status", "success", "message", "회원 탈퇴가 완료되었습니다."));
        } catch (Exception e) {
            log.error("회원탈퇴 처리 중 오류", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // 유저정보얻기
    @GetMapping("/loginInfo")
    public ResponseEntity<Map<String, Object>> getLoginInfo(@AuthenticationPrincipal UserDetails userDetails) {
        log.info("내 정보 API 호출");
        String email = userDetails.getUsername();
        try {
            // 토큰 검증 및 인증 객체 생성

            if (email != null) {
                // 사용자 정보 반환
                UsersDTO usersDTO = usersService.findByEmail(email);
                Map<String, Object> response = new HashMap<>();
                response.put("email", usersDTO.getEmail());
                response.put("nickname", usersDTO.getNickname());
                response.put("bookAlert", usersDTO.getBookAlert());
                response.put("chatAlert", usersDTO.getChatAlert());
                response.put("imgId", usersDTO.getImgId());
                log.info(response.toString());

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
    public ResponseEntity<Map<String, Object>> update(@RequestBody UsersDTO usersDTO,
            @AuthenticationPrincipal UserDetails userDetails) {
        log.info("회원정보 수정 API 호출");
        String email = userDetails.getUsername();
        try {
            // 토큰 검증 및 이메일 추출
            log.info("토큰에서 추출한 이메일: {}", email);

            if (email != null && usersDTO.getEmail().equals(email)) {

                usersService.updateUser(mapperUtil.map(usersDTO, UsersVO.class));

                return ResponseEntity.ok(Map.of("status", "success", "message", "정보가 수정되었습니다"));
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            log.error("사용자 정보 수정 실패", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "정보 수정 실패: " + e.getMessage()));
        }
    }

    @PutMapping("/update/image")
    public ResponseEntity<?> updateImage(@ModelAttribute UsersDTO usersDTO, @AuthenticationPrincipal UserDetails userDetails) {
        String email = userDetails.getUsername();
        //응답 데이터를 저장할 response
        Map<String, Object> response = new HashMap<>();

        if (email != null) {
            
            int result = usersService.updateUserImage(usersDTO, email);
            
            if (result == 1) {
                response.put("status", "success");
                response.put("message", "프사 수정 성공");
                return ResponseEntity.ok(response);
            }

        }
        response.put("status", "fail");
        response.put("message", "프사 수정 실패");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);

    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshAccessToken(
            @RequestHeader Map<String, String> headers) {
        log.info("리프레시 토큰 발급");
        log.info(headers.toString());
        String refreshToken = headers.get("refreshtoken");
        log.info("**리프레쉬 토큰 확인" + refreshToken);
        if (refreshToken == null) {
            return ResponseEntity.status(419)
                    .body(Map.of("error", "Refresh token expired", "statusCode", 419));

        }
        try {
            Map<String, Object> claims = jwtUtil.validateToken(refreshToken);
            String newAccessToken = jwtUtil.regenerateAccessToken(claims);
            String newRefreshToken = jwtUtil.regenerateRefreshToken(refreshToken);
            if (newAccessToken != null) {
                if (newRefreshToken != null) {
                    return ResponseEntity.ok(Map.of("status", "success", "accessToken", newAccessToken, "refreshToken", newRefreshToken));
                }
                return ResponseEntity.ok(Map.of("status", "success", "accessToken", newAccessToken));
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            log.error("리프레쉬 토큰 만료", e);
            return ResponseEntity.status(419)
                    .body(Map.of("error", "Refresh token expired", "statusCode", 419));
        }
    }

    @PostMapping("/checkToken")
    public ResponseEntity<String> checkAuthentication(@RequestHeader Map<String, String> headers) {
        try {
            String accessToken = headers.get("accesstoken");
            Map<String, Object> payload = jwtUtil.validateToken(accessToken);
            String email = (String) payload.get("email");
            log.info("****email: " + email);

            if (email != null) {
                return ResponseEntity.ok(email);
            }

            return ResponseEntity.ok(null);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.ok(null);
        }
    }

    @GetMapping("/read/download/{imgId}")
    public ResponseEntity<?> downloadFile(@PathVariable("imgId") String imgId, HttpServletResponse response) throws IOException {
        ImageFileDTO imageFileDTO = usersService.readImageFile(imgId);
        if (imageFileDTO == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        } else {
            String imgName = imageFileDTO.getImgName();
            imgName = URLEncoder.encode(imgName, "UTF-8");

            response.setHeader("Cache-Control", "no-cache");		// 캐시x, 최신화된 데이터
            response.setHeader("Content-Disposition", "inline; filename=\"" + imgName + "\"");	// inline : 화면에 바로 렌더링, attachment : 첨부파일 다운로드
            response.setContentType(imageFileDTO.getImgType());
            response.setContentLength(imageFileDTO.getImgSize());

            InputStream is = new FileInputStream("/Users/Public/download/" + imageFileDTO.getImgUuid());		// 파일 입력 스트림에 파일 데이터 전송
            is.transferTo(response.getOutputStream());		// 파일 출력 스트림에 파일 데이터 전송
            is.close();

            return ResponseEntity.ok(response);
        }
    }
}
