package dev.slethware.hermez;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@OpenAPIDefinition(
		info = @Info(
				contact = @Contact(
						name = "Slethware",
						email = "slethware@gmail.com",
						url = "https://slethware.dev"
				),
				description = "Hermez Tunneling Service API - Expose your localhost to the internet",
				title = "Hermez API Documentation",
				version = "1.0",
				license = @License(
						name = "MIT License",
						url = "https://opensource.org/licenses/MIT"
				)
		),
		security = {
                 @SecurityRequirement(
		                  name = "bearerAuth"
                 )
		}
)
@SecurityScheme(
		name = "bearerAuth",
		description = "JWT Bearer Token Authentication",
		scheme = "bearer",
		type = SecuritySchemeType.HTTP,
		bearerFormat = "JWT",
		in = SecuritySchemeIn.HEADER
)
@SpringBootApplication
public class HermezApplication {

	public static void main(String[] args) {
		SpringApplication.run(HermezApplication.class, args);
	}

}