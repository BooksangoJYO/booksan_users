package io.booksan.booksan_users.config.jwt;

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
    
	public byte[] getSecretKey() {
		try {
			log.info("key = {}", key);
			return Base64.getEncoder().encode(key.getBytes("UTF-8"));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public Map<String, String> generateTokenSet(Map<String,Object> valueMap) {
		// Access Token: 60분 유효
        String accessToken = generateToken(valueMap, 60, "ACCESS");
        // Refresh Token: 1일 유효
        String refreshToken = generateToken(valueMap, 60 * 24 * 1, "REFRESH");
        
        return Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken
        );
	}
	
    public String generateToken(Map<String, Object> valueMap, int days, String type){

        log.info("generateKey...  : " + key);

        //헤더 부분
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ","JWT");
        headers.put("alg","HS256");

        //payload 부분 설정
        Map<String, Object> payloads = new HashMap<>();
        payloads.putAll(valueMap);
        payloads.put("type", type);

        //테스트 시에는 짧은 유효 기간
        int time = (1) * days; //테스트는 분단위로 나중에 60*24 (일)단위변경

        //10분 단위로 조정
        //int time = (10) * days; //테스트는 분단위로 나중에 60*24 (일)단위변경
        
        try {
		        String jwtStr = Jwts.builder()
		                .header() //헤더 부분
		                .and()
		                .claims(valueMap)
		                .issuedAt(Date.from(ZonedDateTime.now().toInstant())) //JWT 발급시간 설정 
		                .expiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant())) //만료기간 설정 
		                .signWith(Keys.hmacShaKeyFor(getSecretKey()), Jwts.SIG.HS256)
		                .compact();
		
		        log.info("생성된 JWT ({}): " , type , jwtStr);
		        return jwtStr;
        } catch (Exception e) {
        	log.error("JWT 생성 중 오류", e);
        	throw new RuntimeException("Failed to generate JWT", e);
        }
    }


    public Map<String, Object> validateToken(String token)throws JwtException {

        Map<String, Object> claim = null;

        //인증 토큰 문자열을 이용하여 클래임 객체를 얻는다
        claim = Jwts.parser()
        		.verifyWith(Keys.hmacShaKeyFor(getSecretKey()))
  				.build()
  				.parseSignedClaims(token)
  				.getPayload();
      		
        // 토큰 타입 확인
        String tokenType = (String) claim.get("type");
        log.info("Token type: {}", tokenType);
        
        return claim;
    }

    // Access Token 재발급
    public String regenerateAccessToken(Map<String, Object> valueMap) {
        return generateToken(valueMap, 60, "ACCESS");
    }
}
