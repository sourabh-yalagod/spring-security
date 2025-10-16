package Spring.Auth.repository;

import Spring.Auth.ProviderType;
import Spring.Auth.dtos.RegisterUserDto;
import Spring.Auth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, String> {
    UserEntity findByUsername(String username);
    UserEntity save(RegisterUserDto registerUserDto);

    UserEntity findByProviderAndProviderId(ProviderType authProvider, String authProviderId);
}
