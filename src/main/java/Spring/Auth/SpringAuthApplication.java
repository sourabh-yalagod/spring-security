package Spring.Auth;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringAuthApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(SpringAuthApplication.class, args);
	}

    @Override
    public void run(String... args) throws Exception {
        System.out.println("http://localhost:8080");
    }
}
