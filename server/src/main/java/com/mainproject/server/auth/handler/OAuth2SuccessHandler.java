package com.mainproject.server.auth.handler;

import com.google.gson.Gson;
import com.mainproject.server.member.dto.MemberResponseDto;
import com.mainproject.server.member.dto.SimpleMemberResponseDto;
import com.mainproject.server.member.entity.Member;
import com.mainproject.server.member.jwt.JwtTokenizer;
import com.mainproject.server.member.mapper.MemberMapper;
import com.mainproject.server.member.repository.MemberRepository;
import com.mainproject.server.response.SingleResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtTokenizer jwtTokenizer;
    private final MemberRepository memberRepository;
    private final MemberMapper memberMapper;
    private final Gson gson;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        var oAuth2User = (OAuth2User)authentication.getPrincipal();

        String email = String.valueOf(oAuth2User.getAttributes().get("email"));
        List<String> authorities = List.of("ROLE_USER");

        String accessToken = delegateAccessToken(email, authorities);
        String refreshToken = delegateRefreshToken(email);

        Member loginMember = memberRepository.findByEmail(email).get();

        response.setHeader("Authorization", "bearer"+accessToken);
        response.setHeader("Refresh", refreshToken);

        //헤더 추가
        response.addHeader("memberId", loginMember.getMemberId().toString());

        //출력용
        System.out.println("Authorization = " + "bearer"+accessToken);

        setResponseBody(response, loginMember);
    }

    private void setResponseBody(HttpServletResponse response, Member loginMember) throws IOException{

        SimpleMemberResponseDto responseDto = memberMapper.memberToSimpleMemberResponseDto(loginMember);
        SingleResponseDto singleResponseDto = new SingleResponseDto(responseDto);
        String content = gson.toJson(singleResponseDto);
        response.getWriter().write(content);

    }

//    private void redirect(HttpServletRequest request, HttpServletResponse response, String username, List<String> authorities) throws IOException {
//        String accessToken = delegateAccessToken(username, authorities);
//        String refreshToken = delegateRefreshToken(username);
//
//        String uri = createURI(accessToken, refreshToken).toString();
//        getRedirectStrategy().sendRedirect(request, response, uri);
//    }

    private String delegateAccessToken(String username, List<String> authorities) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", username);
        claims.put("roles", authorities);

        String subject = username;
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes());

        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        return accessToken;
    }

    private String delegateRefreshToken(String username) {
        String subject = username;
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSecretKey);

        return refreshToken;
    }

//    private URI createURI(String accessToken, String refreshToken) {
//        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
//        queryParams.add("access_token", accessToken);
//        queryParams.add("refresh_token", refreshToken);
////        queryParams.add("member_id", memberId);
//
//        return UriComponentsBuilder
//                .newInstance()
//                .scheme("http")
//                .host("localhost")
//                .port(8080)
//                .path("/")
//                .queryParams(queryParams)
//                .build()
//                .toUri();
//    }

}
