package payroll.auth;

import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
public class AppUser {
    @Id @GeneratedValue 
    public Long id;

    @Column(unique = true)
    public String username;
    
    public String registrationId;
    
    public String name;

    @ElementCollection
    public Collection<String> authorities;
}
