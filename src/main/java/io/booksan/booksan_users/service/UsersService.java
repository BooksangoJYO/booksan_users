package io.booksan.booksan_users.service;

import java.util.Date;
import java.util.Objects;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.booksan.booksan_users.dao.UsersDAO;
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

            if (existUser == null) {
                // 새로운 신규 회원 등록
                usersDAO.insertUser(usersVO);
                log.info("새 사용자 등록 완료: {}", usersVO);
            } else if (existUser.getDisabled() == 'Y') {
                // 탈퇴했던 회원인 경우 정보 업데이트
                usersDAO.updateUser(usersVO);
                log.info("탈퇴 회원 재가입 완료: {}", usersVO);
            } else if (existUser.getNickname() != null && !existUser.getNickname().isEmpty()) {
                // 이미 가입된 활성화 되어있는 회원
                throw new ExistMemberException(usersVO.getEmail());
            } else {
                // 기존 회원이지만 닉네임이 없는 경우는 회원가입이 필요한 상태
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
        return usersDAO.disableUser(user);
    }

    public boolean isNicknameUsed(String nickname) {
        return usersDAO.findByNickname(nickname) != null;
    }

    public void insertLoginLog(String email) {
        usersDAO.insertLoginLog(email);
    }

}
