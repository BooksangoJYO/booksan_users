package io.booksan.booksan_users.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import io.booksan.booksan_users.vo.UsersVO;

public class PrincipalDetails implements UserDetails {

    private static final long serialVersionUID = -951226953749557253L;
	private UsersVO user;

    public PrincipalDetails(UsersVO user) {
        this.user = user;
    }

    public UsersVO getUser() {
        return user;
    }

    public Date getSignupDate() {
    	return user.getSignupDate();
    }
    
    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return user != null ? user.getEmail() : "";
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleId();
        
        return authorities;
    }
}
