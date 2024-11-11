package io.booksan.booksan_users.service;

import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Objects;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.booksan.booksan_users.dao.UsersDAO;
import io.booksan.booksan_users.dto.UsersDTO;
import io.booksan.booksan_users.exception.ExistMemberException;
import io.booksan.booksan_users.vo.UsersVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class UsersService {
	
	final private UsersDAO usersDAO;
	private final ObjectMapper objectMapper; // ObjectMapper 주입
	
	public void insertUser(UsersVO usersVO, String code) throws Exception {
        try {
            if (usersVO == null || Objects.isNull(usersVO.getEmail())) {
                throw new Exception("이메일은 필수 정보입니다");
            }
            UsersVO existUser = usersDAO.findByEmail(usersVO.getEmail());
            if (existUser != null && existUser.getNickname() != null && !existUser.getNickname().isEmpty()) {
                throw new ExistMemberException(usersVO.getEmail());
            }
            // uid에 카카오 코드 저장
            usersVO.setUid(code);
            
            if (existUser == null) {
                // 새 회원 등록
                usersDAO.insertUser(usersVO);
                log.info("새 사용자 등록 완료: {}", usersVO);
            } else {
                // 기존 회원이지만 nickname이 없는 경우는 회원가입이 필요한 상태
                log.info("기존 회원이지만 닉네임 미설정: {}", existUser.getEmail());
            }
            
        } catch (ExistMemberException ex) {
            log.info("완전한 회원가입이 완료된 기존 회원: {}", usersVO.getEmail());
            throw ex;
        } catch (Exception ex) {
            log.error("사용자 등록 중 오류 발생", ex);
            throw ex;
        }
    }
	
	// 사용자 이메일을 추출하는 메소드 (JSON 응답을 파싱)
    public String extractUserEmail(String responseBody) {
        try {
            JsonNode jsonNode = objectMapper.readTree(responseBody);
            return jsonNode.get("kakao_account").get("email").asText();
        } catch (Exception e) {
            log.error("이메일 추출 중 오류 발생", e);
            return null;
        }
    }
    
    public UsersVO findByEmail(String email) {
    	return usersDAO.findByEmail(email);
    }
    
    public int updateUser(UsersVO user) {
        return usersDAO.updateUser(user);
    }
    
	public int disableUser(String email) {
	    UsersVO user = findByEmail(email);
	    user.setDisabled('Y');  // 비활성화 
	    user.setSignoutDate(new Date()); // 탈퇴일자 설정
	    return usersDAO.updateUser(user);
	}

	public boolean isNicknameUsed(String nickname) {
		return usersDAO.findByNickname(nickname) != null;
	}

	
}
