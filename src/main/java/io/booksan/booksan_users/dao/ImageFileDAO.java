package io.booksan.booksan_users.dao;

import org.apache.ibatis.annotations.Mapper;

import io.booksan.booksan_users.vo.ImageFileVO;

@Mapper
public interface ImageFileDAO {
    // 이미지 등록
    int insertImageFile(ImageFileVO imageFileVO);
    
    // 이미지 불러오기
    ImageFileVO readImageFile(int imgId);

    int deleteImageFile(int imgId, String uid);
}
