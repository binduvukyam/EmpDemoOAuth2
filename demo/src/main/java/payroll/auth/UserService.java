package payroll.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public UserDetails findUser(String username) {
        try {
            var appUser = userRepository.findByUsername(username);
            if (appUser == null) {
                throw new UsernameNotFoundException("$username was not found");
            }

            var authority = appUser.authorities.stream().map(
                a -> new SimpleGrantedAuthority(a)).collect(Collectors.toList());
            
            return new User(appUser.username, "", authority);

        } catch (Exception e) {
            return null;
        }
    }

    public UserDetails createUser(OAuth2LoginAuthenticationToken authToken) {
        var attributes = authToken.getPrincipal().getAttributes();
        var username = (String)attributes.get("email");
        
        var appUser = new AppUser();
        appUser.username = username;
        appUser.name = (String)attributes.get("name");
        appUser.registrationId = authToken.getClientRegistration().getRegistrationId();
        appUser.authorities = new ArrayList<String>() {{add("ROLE_USER");}}; // for now default to USER ROLE
        userRepository.save(appUser);

        return findUser(username);
    }

    public UserDetails findOrCreateUser(OAuth2LoginAuthenticationToken authToken) {
        var username = (String)authToken.getPrincipal().getAttributes().get("email");
        var user = this.findUser(username);
        
        if (user != null)  return user;

        return createUser(authToken);
    }
}
