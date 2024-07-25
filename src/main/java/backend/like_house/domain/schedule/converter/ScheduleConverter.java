package backend.like_house.domain.schedule.converter;

import backend.like_house.domain.schedule.dto.ScheduleDTO.ScheduleRequest.*;
import backend.like_house.domain.schedule.dto.ScheduleDTO.ScheduleResponse.*;
import backend.like_house.domain.schedule.entity.Schedule;
import backend.like_house.domain.user.entity.User;
import backend.like_house.global.common.enums.ScheduleType;

public class ScheduleConverter {

    public static ScheduleDataResponse toScheduleDataResponse(Schedule schedule) {
        return ScheduleDataResponse.builder()
                .scheduleId(schedule.getId())
                .date(schedule.getDate())
                .dtype(schedule.getDtype().getKoreanName())
                .title(schedule.getTitle())
                .content(schedule.getContent())
                .build();
    }

    public static SaveScheduleResponse toSaveScheduleResponse(Schedule schedule) {
        return SaveScheduleResponse.builder()
                .scheduleId(schedule.getId())
                .createdAt(schedule.getCreatedAt())
                .build();
    }

    public static Schedule toSchedule(SaveScheduleRequest request, User user) {
        return Schedule.builder()
                .familySpace(user.getFamilySpace())
                .date(request.getDate())
                .dtype(ScheduleType.valueOfKoreanName(request.getDtype()))
                .title(request.getTitle())
                .content(request.getContent())
                .build();
    }

    public static Schedule updateSchedule(Schedule schedule, ModifyScheduleRequest request) {
        return Schedule.builder()
                .id(schedule.getId())
                .date(request.getDate() != null ? request.getDate() : schedule.getDate())
                .dtype(request.getDtype() != null ? ScheduleType.valueOfKoreanName(request.getDtype()) : schedule.getDtype())
                .title(request.getTitle() != null ? request.getTitle() : schedule.getTitle())
                .content(request.getContent() != null ? request.getContent() : schedule.getContent())
                .build();
    }
}
