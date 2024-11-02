package io.booksan.booksan_users.service;

import java.util.Objects;

import org.springframework.stereotype.Service;

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
	
	public void insertUser(UsersVO usersVO, String code) throws Exception {
        try {
            if (usersVO == null || Objects.isNull(usersVO.getEmail())) {
                throw new Exception("이메일은 필수 정보입니다");
            }
            UsersVO existUser = usersDAO.findByEmail(usersVO.getEmail());
            if (existUser != null) {
                throw new ExistMemberException(usersVO.getEmail());
            }
            // uid에 카카오 코드 저장
            usersVO.setUid(code);
            
            usersDAO.insertUser(usersVO);
            System.out.println(usersVO);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }
	
	// 사용자 이메일을 추출하는 메소드 (JSON 응답을 파싱)
	public String extractUserEmail(String responseBody) {
	    // JSON 파싱 로직을 구현하여 사용자 이메일을 db에 저장
	    // ObjectMapper를 사용
	    // return parsedEmail;
		return "아직 미구현함";
	}
	
	
	
}
