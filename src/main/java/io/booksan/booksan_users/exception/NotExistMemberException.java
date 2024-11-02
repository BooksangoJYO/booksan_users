package io.booksan.booksan_users.exception;

//멤버가 존재할 경우 예외 객체
public class NotExistMemberException extends Exception {
	public NotExistMemberException(String email) {
		super(email + "계정이 존재하지 않습니다");
	}
}
