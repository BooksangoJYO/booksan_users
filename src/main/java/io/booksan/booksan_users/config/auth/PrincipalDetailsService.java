package io.booksan.booksan_users.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.booksan.booksan_users.dao.UsersDAO;
import io.booksan.booksan_users.vo.UsersVO;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

	final private UsersDAO usersDAO;

	@Override
	public UserDetails loadUserByUsername(String uid) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService : 진입");
		UsersVO user = usersDAO.findByUid(uid);
		
		System.out.println("PrincipalDetailsService : user -> " + user);

		return new PrincipalDetails(user);
	}
}
