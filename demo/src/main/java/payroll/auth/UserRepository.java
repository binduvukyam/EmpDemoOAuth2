package payroll.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository  extends JpaRepository<AppUser, Long> {
    @Query("SELECT m FROM AppUser m JOIN FETCH m.authorities WHERE m.username = (:username)")
    AppUser findByUsername(String username);
}
