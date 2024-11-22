package io.booksan.booksan_users.dto;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ImageFileDTO {
    private int imgId;
    private String imgUuid;
    private String imgName;
    private int imgSize;
    private String imgType;
    private Date uploadDate;
}