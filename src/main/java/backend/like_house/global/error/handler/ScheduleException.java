package backend.like_house.global.error.handler;

import backend.like_house.global.error.code.BaseErrorCode;
import backend.like_house.global.error.exception.GeneralException;

public class ScheduleException extends GeneralException {
    public ScheduleException(BaseErrorCode code) {
        super(code);
    }
}
