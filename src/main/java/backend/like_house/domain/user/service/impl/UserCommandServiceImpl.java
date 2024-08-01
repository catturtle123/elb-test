package backend.like_house.domain.user.service.impl;
import backend.like_house.domain.user.dto.UserDTO.*;
import backend.like_house.domain.user.entity.User;
import backend.like_house.domain.user.repository.UserRepository;
import backend.like_house.domain.user.service.UserCommandService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserCommandServiceImpl implements UserCommandService {
    private final UserRepository userRepository;

    @Override
    public User updateUserProfile(User user, UpdateProfileRequest request) {
        Optional<User> requestUser = userRepository.findById(user.getId());
        requestUser.get().setUpdateUserProfile(request);
        return userRepository.save(requestUser.get());
    }
    @Override
    public void commentAlarmSetting(User user) {
        user.commentAlarmSetting();
    }

    @Override
    public void commentReplyAlarmSetting(User user) {
        user.commentReplyAlarmSetting();
    }

    @Override
    public void eventAlarmSetting(User user) {
        user.eventAlarmSetting();
    }

    @Override
    public void chatAlarmSetting(User user) {
        user.chatAlarmSetting();
    }
}