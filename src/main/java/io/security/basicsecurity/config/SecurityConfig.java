package io.security.basicsecurity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
@Configuration
@EnableWebSecurity  // 웹 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        http
                .authorizeRequests()    // http 요청이 오면 보안 검사를 하겠다
                .anyRequest().authenticated();  // 어떠한 요청에도. 인증을 받겠다

        // 인증 정책
        http
                .formLogin()                                // 폼 로그인 인증 방식을 제공하겠다
//                .loginPage("/loginPage")                    // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")                     // 로그인 성공 후 이동 페이지
                .failureUrl("/login")   // 로그인 실패 후 이동 페이지
                .usernameParameter("userId")                // 아이디 파라미터명 설정(html 아이디 input 태그의 name값)
                .passwordParameter("passwd")                // 패스워드 파라미터명 설정(html 패스워드 input 태그의 name값)
                .loginProcessingUrl("/login_proc")          // 로그인 Form Action Url
                .successHandler(loginSuccessHandler())      // 로그인 성공 후 핸들러
                .failureHandler(loginFailureHandler())      // 로그인 실패 후 핸들러
                .permitAll();

        http
                .logout()                                       // 로그아웃 기능이 작동함
                .logoutUrl("/logout")                           // 로그아웃 처리 URL (스프링 시큐리티가 POST 방식으로 로그아웃을 처리합니다)
                .logoutSuccessUrl("/login")                     // 로그아웃 성공 후 이동 페이지
                .deleteCookies("JSESSIONID", "remember-me")     // 로그아웃 후 쿠키 삭제
                .addLogoutHandler(logoutHandler())              // 로그아웃 핸들러
                .logoutSuccessHandler(logoutSuccessHandler())   // 로그아웃 성공 후 핸들러
                ;
    }

    private AuthenticationSuccessHandler loginSuccessHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                log.info("authentication: " + authentication.getName());
                response.sendRedirect("/");
            }
        };
    }

    private AuthenticationFailureHandler loginFailureHandler() {
        return new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                log.error("exception: " + exception.getMessage());
                response.sendRedirect("/login");
            }
        };
    }

    private LogoutHandler logoutHandler() {
        return new LogoutHandler() {
            @Override
            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                HttpSession session = request.getSession();
                session.invalidate();
            }
        };
    }

    private LogoutSuccessHandler logoutSuccessHandler() {
        return new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                response.sendRedirect("/login");
            }
        };
    }

}
