package io.booksan.booksan_users.vo;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Builder
public class UsersVO {
	private String uid; //카카오 인증 코드
	private String nickname;
	private String email;
	private int imgId;
	private int roleId;
	private Date lastLoginDate;
	private Date lastLogoutDate;
	private String autoLogin;
	private Date signupDate;
	private Date signoutDate;
	private char disabled;
}
