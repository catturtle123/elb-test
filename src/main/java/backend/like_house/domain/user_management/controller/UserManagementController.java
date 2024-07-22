package backend.like_house.domain.user_management.controller;

import backend.like_house.domain.user.entity.User;
import backend.like_house.domain.user_management.dto.UserManagementDTO.UserManagementRequest.ModifyFamilyDataRequest;
import backend.like_house.domain.user_management.dto.UserManagementDTO.UserManagementResponse.*;
import backend.like_house.global.common.ApiResponse;
import backend.like_house.global.security.annotation.LoginUser;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v0/user-management")
@Tag(name = "유저와 유저 관계 관련 컨트롤러")
public class UserManagementController {

    @GetMapping("")
    @Operation(summary = "가족 목록 확인 API", description = "가족 공간에 속한 가족 목록을 확인하는 API입니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "COMMON200", description = "OK, 성공"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "FAMILY_SPACE4002", description = "존재하지 않는 가족 공간 입니다.")
    })
    public ApiResponse<FamilyListResponse> getFamilyList(@Parameter(hidden = true) @LoginUser User user) {
        // TODO 가족 공간에 해당하는 가족 목록
        return ApiResponse.onSuccess(null);
    }

    @PatchMapping("")
    @Operation(summary = "가족 정보 수정 API", description = "가족 별명, 메모를 수정하는 API입니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "COMMON200", description = "OK, 성공")
    })
    public ApiResponse<ModifyFamilyDataResponse> modifyFamilyData(
            @Parameter(hidden = true) @LoginUser User user,
            @RequestBody @Valid ModifyFamilyDataRequest request) {
        // TODO contact 테이블에 없다면 contact, custom 테이블에 새로 save
        // TODO contact 테이블에 있다면 custom 테이블에 update
        return ApiResponse.onSuccess(null);
    }

    @PostMapping("/remove/{userId}")
    @Operation(summary = "가족 해제 API", description = "특정 유저를 가족 공간에서 내보내는 API입니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "COMMON200", description = "OK, 성공"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4001", description = "사용자를 찾을 수 없습니다."),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4004", description = "주최자가 아닙니다."),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4005", description = "이미 해제된 유저입니다.")
    })
    @Parameters({
            @Parameter(name = "userId", description = "해제할 유저 아이디, path variable 입니다.")
    })
    public ApiResponse<String> removeFamily(
            @Parameter(hidden = true) @LoginUser User user,
            @PathVariable(name = "userId") Long userId) {
        // TODO 주최자만 가능!!
        // TODO 특정 유저를 가족 공간에서 내보내기 + 이전 데이터 유지
        // TODO user - family space FK 끊기 + remove user에 저장
        return ApiResponse.onSuccess("Family removal completed successfully.");
    }

    @PostMapping("/remove/release/{userId}")
    @Operation(summary = "가족 해제 풀기 API", description = "특정 유저를 가족 공간에 다시 합류시키는 API입니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "COMMON200", description = "OK, 성공"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4001", description = "사용자를 찾을 수 없습니다."),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4004", description = "주최자가 아닙니다."),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4007", description = "이미 해제가 풀어진 유저입니다.")
    })
    @Parameters({
            @Parameter(name = "userId", description = "해제할 유저 아이디, path variable 입니다.")
    })
    public ApiResponse<String> releaseRemoveFamily(
            @Parameter(hidden = true) @LoginUser User user,
            @PathVariable(name = "userId") Long userId) {
        // TODO 주최자만 가능!
        // TODO user - family space FK 연결 + remove user 에서 삭제
        return ApiResponse.onSuccess("Family removal release completed successfully.");
    }

    @PostMapping("block/{userId}")
    @Operation(summary = "가족 차단 API", description = "특정 유저를 가족 공간에서 내보내는 API입니다. "
            + "차단되면 초대받더라도 다시 해당 공간에 소속될 수 없습니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "COMMON200", description = "OK, 성공"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4001", description = "사용자를 찾을 수 없습니다."),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4004", description = "주최자가 아닙니다."),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4006", description = "이미 차단된 유저입니다.")
    })
    @Parameters({
            @Parameter(name = "userId", description = "해제할 유저 아이디, path variable 입니다.")
    })
    public ApiResponse<String> blockFamily(
            @Parameter(hidden = true) @LoginUser User user,
            @PathVariable(name = "userId") Long userId) {
        // TODO 주최자만 가능!!
        // TODO 특정 유저를 가족 공간에서 내보내기 + 유저와 연결된 것 모두 삭제
        // TODO block user 테이블에 추가
        return ApiResponse.onSuccess("Family block completed successfully");
    }

    @PostMapping("block/release/{userId}")
    @Operation(summary = "가족 차단 풀기 API", description = "특정 유저를 가족 공간에 다시 합류시키는 API입니다.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "COMMON200", description = "OK, 성공"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4001", description = "사용자를 찾을 수 없습니다."),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4004", description = "주최자가 아닙니다."),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "USER4008", description = "이미 차단이 풀어진 유저입니다.")
    })
    @Parameters({
            @Parameter(name = "userId", description = "해제할 유저 아이디, path variable 입니다.")
    })
    public ApiResponse<String> releaseBlockFamily(
            @Parameter(hidden = true) @LoginUser User user,
            @PathVariable(name = "userId") Long userId) {
        // TODO 주최자만 가능!!
        // TODO user - family space FK 연결 + block user 에서 삭제
        return ApiResponse.onSuccess("Family block release completed successfully");
    }
}