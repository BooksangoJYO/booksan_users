package io.booksan.booksan_users.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;

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
	                .title("Chat API")
	                .description("채팅에 관한 REST API")
	                .version("1.0.0");
    }
}