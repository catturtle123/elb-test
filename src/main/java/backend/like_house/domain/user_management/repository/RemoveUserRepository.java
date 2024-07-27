package backend.like_house.domain.user_management.repository;

import backend.like_house.domain.family_space.entity.FamilySpace;
import backend.like_house.domain.user.entity.User;
import backend.like_house.domain.user_management.entity.RemoveUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RemoveUserRepository extends JpaRepository<RemoveUser, Long> {

    boolean existsByUserAndFamilySpace(User user, FamilySpace familySpace);

    Optional<RemoveUser> findByUserAndFamilySpace(User user, FamilySpace familySpace);
}
