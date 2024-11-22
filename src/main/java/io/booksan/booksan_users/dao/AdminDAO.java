package io.booksan.booksan_users.dao;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AdminDAO {

    List<Map<String, Object>> getWeeklyStats();
}
