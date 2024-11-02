package io.booksan.booksan_users.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import lombok.extern.slf4j.Slf4j;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI openAPI() {
	        return new OpenAPI()
	                .components(new Components())
	                .info(apiInfo());
	}

    private Info apiInfo() {
        return new Info()
	                .title("Users API")
	                .description("회원관리 기능에 관한 REST API")
	                .version("1.0.0");
    }
}