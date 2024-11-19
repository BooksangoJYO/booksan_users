package io.booksan.booksan_users.config.jwt;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JWTUtil {

    @Value("${jwt.secret}")
    private String key; // 서버만 알고 있는 비밀키값

    public byte[] createSecretKey() {
        try {
            log.info("key = {}", key);
            return Base64.getEncoder().encode(key.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public Map<String, String> createLoginTokens(Map<String, Object> valueMap) {
        log.info("토큰 생성 시작 - valueMap: {}", valueMap);

        // Access Token: 1분 유효
        String accessToken = createToken(valueMap, 60, "ACCESS");
        log.info("ACCESS 토큰 생성 완료: {}", accessToken);

        // Refresh Token: 2주유효
        String refreshToken = createToken(valueMap, 60 * 24 * 14, "REFRESH");
        log.info("REFRESH 토큰 생성 완료: {}", refreshToken);

        Map<String, String> tokens = Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken
        );
        log.info("생성된 토큰들: {}", tokens);

        return tokens;
    }

    public String createToken(Map<String, Object> valueMap, int minutes, String type) {
        log.info("개별 토큰 생성 시작 - type: {}, days: {}", type, minutes);

        //payload 부분 설정
        Map<String, Object> payloads = new HashMap<>();
        payloads.putAll(valueMap);
        payloads.put("type", type); // type 추가

        log.info("토큰 페이로드 설정: {}", payloads);
        log.info("토큰 만료 시간 (분): {}", minutes);

        try {
            String jwtStr = Jwts.builder()
                    .header()
                    .empty()
                    .add("typ", "JWT")
                    .and()
                    .claims(payloads)
                    .issuedAt(Date.from(ZonedDateTime.now().toInstant()))
                    .expiration(Date.from(ZonedDateTime.now().plusMinutes(minutes).toInstant()))
                    .signWith(Keys.hmacShaKeyFor(createSecretKey()), Jwts.SIG.HS256)
                    .compact();

            // 생성된 토큰 검증
            Map<String, Object> verifiedClaims = validateToken(jwtStr);
            log.info("토큰 생성 후 검증 - type: {}, claims: {}", verifiedClaims.get("type"), verifiedClaims);

            return jwtStr;
        } catch (Exception e) {
            log.error("JWT 생성 중 오류", e);
            throw new RuntimeException("Failed to generate JWT", e);
        }
    }

    public Map<String, Object> validateToken(String token) throws JwtException {

        Map<String, Object> claim = null;
        log.info("***** 엑세스토큰 검증 진행" + token);
        //인증 토큰 문자열을 이용하여 클래임 객체를 얻는다
        claim = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(createSecretKey()))
                .build()
                .parseSignedClaims(token)
                .getPayload();
        log.info("토큰 객체?:" + claim.toString());
        // 토큰 타입 확인
        String tokenType = (String) claim.get("type");
        log.info("Token type: {}", tokenType);

        return claim;
    }

    // Access Token 재발급
    public String regenerateAccessToken(Map<String, Object> refreshToken) {
        try {
            // 리프레시 토큰 타입 검증
            String tokenType = (String) refreshToken.get("type");
            if (!"REFRESH".equals(tokenType)) {
                throw new JwtException("리프레시 토큰이 아닙니다");
            }

            // 필수 정보 존재 확인
            if (!refreshToken.containsKey("email") || !refreshToken.containsKey("nickname")) {
                throw new JwtException("토큰에 필수 정보가 없습니다");
            }

            // 새로운 액세스 토큰용 데이터 준비
            Map<String, Object> userData = new HashMap<>();
            userData.put("email", refreshToken.get("email"));
            userData.put("nickname", refreshToken.get("nickname"));

            // 액세스 토큰 재발급 (60분)
            String newAccessToken = createToken(userData, 60, "ACCESS");

            log.info("액세스 토큰 재발급 완료: {}", refreshToken.get("email"));
            return newAccessToken;

        } catch (Exception e) {
            log.error("액세스 토큰 재발급 실패", e);
            throw new JwtException("액세스 토큰 재발급 실패", e);
        }
    }

    public String regenerateRefreshToken(String refreshToken) {
        Map<String, Object> claims = validateToken(refreshToken);
        Long exp = (Long) claims.get("exp");
        Date expTime = new Date(Instant.ofEpochMilli(exp).toEpochMilli() * 1000);
        Date current = new Date(System.currentTimeMillis());
        long gapTime = (expTime.getTime() - current.getTime());
        if (gapTime < (1000 * 60 * 60 * 24)) {
            String email = (String) claims.get("email");
            String nickname = (String) claims.get("nickname");
            return createToken(Map.of("email", email, "nickname", nickname), 60 * 24 * 14, "REFRESH");
        } else {
            return null;
        }
    }

}
