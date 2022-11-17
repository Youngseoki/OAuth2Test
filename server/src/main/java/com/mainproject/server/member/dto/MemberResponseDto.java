package com.mainproject.server.member.dto;

import com.mainproject.server.member.entity.Role;
import com.mainproject.server.response.MultiResponseDto;
import lombok.*;

import java.time.LocalDateTime;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class MemberResponseDto {

    private Long memberId;

    private String email;

    private String name;

    private String picture;

    private String grade;

    private Integer follow;

    private Integer rank;

    private Role role;

    private LocalDateTime createdAt;

    private LocalDateTime modifiedAt;

/**    상세 페이지에서 필요한 room 관련 정보(on air 하나만) */
//    private String roomTitle;

//    멤버가 보유중인 플레이리스트
//    private MultiResponseDto<PlaylistResponseDto> plList;
}
