package dev.slethware.hermez;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@OpenAPIDefinition(
		info = @Info(
				contact = @Contact(
						name = "Slethware",
						email = "slethware@gmail.com",
						url = "https://slethware.dev"
				),
				description = "Hermez - Open Source Tunneling Platform",
				title = "Hermez API Documentation",
				version = "1.0",
				license = @License(
						name = "MIT License",
						url = "https://opensource.org/licenses/MIT"
				)
		)
)
@SpringBootApplication
public class HermezApplication {

	public static void main(String[] args) {
		SpringApplication.run(HermezApplication.class, args);
	}

}