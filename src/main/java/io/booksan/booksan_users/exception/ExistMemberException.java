package io.booksan.booksan_users.exception;

//멤버가 존재할 경우 예외 객체
public class ExistMemberException extends Exception {
	public ExistMemberException(String email) {
		super(email + "계정이 존재합니다");
	}
}
