package io.booksan.booksan_users.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.booksan.booksan_users.service.AdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/admin")
@RestController
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/dashboard/data")
    public ResponseEntity<Map<String, Object>> getWeeklyStats(@AuthenticationPrincipal UserDetails userDetails) {
        log.info("대쉬보드 데이터 호출");
        if (userDetails != null) {
            String email = userDetails.getUsername();
            List<Map<String, Object>> weeklyStats = adminService.getWeeklyStats(email);
            Map<String, Object> response = new HashMap<>();
            response.put("weeklyData", weeklyStats);
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
