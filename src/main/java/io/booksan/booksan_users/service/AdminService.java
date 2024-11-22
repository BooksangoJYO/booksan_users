package io.booksan.booksan_users.service;

import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import io.booksan.booksan_users.dao.AdminDAO;
import io.booksan.booksan_users.dao.UsersDAO;
import io.booksan.booksan_users.exception.UnauthorizedException;
import io.booksan.booksan_users.vo.UsersVO;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class AdminService {

    private final AdminDAO adminDAO;
    private final UsersDAO userDAO;

    public List<Map<String, Object>> getWeeklyStats(String email) {
        UsersVO userInfo = userDAO.findByEmail(email);
        if (userInfo.getRoleId() == 99) {
            return adminDAO.getWeeklyStats();
        } else {
            throw new UnauthorizedException("관리자 권한이 없습니다.");
        }
    }
}
