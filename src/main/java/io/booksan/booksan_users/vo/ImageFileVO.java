package io.booksan.booksan_users.vo;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ImageFileVO {
    private int imgId;
    private String imgUuid;
    private String imgName;
    private int imgSize;
    private String imgType;
    private Date uploadDate;
}
