package io.booksan.booksan_users.util;

import org.modelmapper.ModelMapper;
import org.modelmapper.config.Configuration;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.stereotype.Component;

@Component
public class MapperUtil extends ModelMapper {
	public MapperUtil() {
		//ModelMapper의 설정을 커스터마이징
		this.getConfiguration()
				.setFieldAccessLevel(Configuration.AccessLevel.PRIVATE) //private 필드에 접근 허용
				.setFieldMatchingEnabled(true) //필드이름 기반으로 매칭 활성화
				.setMatchingStrategy(MatchingStrategies.STRICT); //엄격한 매칭 전략 사용
	}
	
}
