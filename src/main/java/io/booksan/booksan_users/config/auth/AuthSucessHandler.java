package io.booksan.booksan_users.config.auth;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import io.booksan.booksan_users.dao.UsersDAO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthSucessHandler extends SimpleUrlAuthenticationSuccessHandler {
	
//	@Autowired
	final private UsersDAO usersDAO;
	
	@Override
    public void onAuthenticationSuccess(
    		HttpServletRequest request
    		, HttpServletResponse response
    		, Authentication authentication //로그인한 사용자 정보가 있는 객체 
    		) throws IOException, ServletException {
        
		 if (authentication.isAuthenticated()) {
	            // 추가적인 처리가 필요하면 여기에 추가
	            usersDAO.updateMemberLastLogin(authentication.getName());
	            usersDAO.loginCountClear(authentication.getName());
	     }
		
		System.out.println("authentication ->" + authentication);
		
        setDefaultTargetUrl("/");
        
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
