package io.booksan.booksan_users.dao;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import io.booksan.booksan_users.vo.UsersVO;

@Mapper
public interface UsersDAO {
	
	// 이메일로 사용자 조회
    UsersVO findByEmail(@Param("email") String email);
    // 사용자 정보 삽입
    int insertUser(UsersVO usersVO);
    // 사용자 정보 업데이트
    int updateUser(UsersVO usersVO);
    // 마지막 로그인 시간 업데이트
    int updateMemberLastLogin(@Param("uid") String uid);
    // 로그인 카운트 초기화
    int loginCountClear(@Param("uid") String uid);
    // 닉네임 중복검사
    UsersVO findByNickname(String nickname);
    // 사용자 회원 탈퇴(비활성화)
    int disableUser(UsersVO usersVO);
}
