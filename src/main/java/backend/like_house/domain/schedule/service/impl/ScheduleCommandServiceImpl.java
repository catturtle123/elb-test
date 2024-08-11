package backend.like_house.domain.schedule.service.impl;

import backend.like_house.domain.schedule.converter.ScheduleConverter;
import backend.like_house.domain.schedule.dto.ScheduleDTO.ScheduleRequest.*;
import backend.like_house.domain.schedule.entity.Schedule;
import backend.like_house.domain.schedule.repository.ScheduleRepository;
import backend.like_house.domain.schedule.service.ScheduleCommandService;
import backend.like_house.domain.user.entity.User;
import backend.like_house.global.common.enums.ScheduleType;
import backend.like_house.global.error.code.status.ErrorStatus;
import backend.like_house.global.error.handler.ScheduleException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class ScheduleCommandServiceImpl implements ScheduleCommandService {

    private final ScheduleRepository scheduleRepository;

    @Override
    public Schedule generateNewSchedule(SaveScheduleRequest request, User user) {
        if (ScheduleType.valueOfKoreanName(request.getDtype()) == null) {
            throw new ScheduleException(ErrorStatus.INVALID_SCHEDULE_TYPE);
        }
        Schedule schedule = ScheduleConverter.toSchedule(request, user);
        return scheduleRepository.save(schedule);
    }

    @Override
    public void deleteSchedule(Long id) {
        scheduleRepository.deleteById(id);
    }

    @Override
    public Schedule updateSchedule(Long id, ModifyScheduleRequest request) {
        if (request.getDtype() != null && ScheduleType.valueOfKoreanName(request.getDtype()) == null) {
            throw new ScheduleException(ErrorStatus.INVALID_SCHEDULE_TYPE);
        }
        Schedule schedule = scheduleRepository.findById(id).get();
        schedule.setUpdateSchedule(request);
        return scheduleRepository.save(schedule);
    }
}
