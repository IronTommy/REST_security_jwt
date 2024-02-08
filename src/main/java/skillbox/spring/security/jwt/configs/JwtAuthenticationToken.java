package skillbox.spring.security.jwt.configs;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final String token;
    private final String username;

    public JwtAuthenticationToken(String username, String token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.username = username;
        this.token = token;
    }


    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }
}
