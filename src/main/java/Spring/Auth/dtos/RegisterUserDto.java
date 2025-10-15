package Spring.Auth.dtos;

import jakarta.annotation.Nullable;
import lombok.*;

@Data
@Builder
public class RegisterUserDto {
    private String id;
    private String username;
    private String password;
}
