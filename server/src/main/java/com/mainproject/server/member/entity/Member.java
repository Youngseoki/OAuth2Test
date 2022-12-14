package com.mainproject.server.member.entity;

import com.mainproject.server.ChatRoom.entity.ChatMessage;
import com.mainproject.server.ChatRoom.entity.ChatRoom;
import com.mainproject.server.auditable.Auditable;
import com.mainproject.server.playlist.entity.Playlist;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
@Getter
@Setter
@Entity
public class Member extends Auditable {

    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long memberId;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String name;

    @Column
    private String picture;

    @Column
    private String grade = "silver";

    @OneToOne
    private Ranking ranking;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Builder
    public Member(Long memberId, String email, String name, String picture, Role role){
        this.memberId = memberId;
        this.email = email;
        this.name = name;
        this.picture = picture;
        this.role = role;
    }

    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL)
    private List<Playlist> playlists = new ArrayList<>();

    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL)
    private List<ChatRoom> chatRooms = new ArrayList<>();

    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL)
    private List<Follow> follows  = new ArrayList<>();

    @OneToMany(mappedBy = "member")
    private List<ChatMessage> messages  = new ArrayList<>();

//    public Member update(String name, String picture) {
//        this.name = name;
//        this.picture  = picture;
//
//        return this;
//    }

    public String getRoleKey() {
        return this.role.getKey();
    }

}
