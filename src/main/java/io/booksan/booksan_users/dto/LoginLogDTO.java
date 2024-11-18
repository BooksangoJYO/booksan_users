package io.booksan.booksan_users.dto;

import java.util.Date;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class LoginLogDTO {

    private int loginLogId;
    private String email;
    private Date loginTime;

}
