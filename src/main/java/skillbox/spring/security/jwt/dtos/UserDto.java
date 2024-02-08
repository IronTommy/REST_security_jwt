package skillbox.spring.security.jwt.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

import jakarta.persistence.*;

@Data
@AllArgsConstructor
public class UserDto {
    private Long id;
    private String username;
    private String email;
}
