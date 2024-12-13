package cn.myjszl.oauth.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author  公众号：码猿技术专栏
 * spring security的安全配置
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 加密算法
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 方法作用：
     *  - 配置与 HTTP 请求相关的安全细节，比如 URL 的访问权限、会话管理、CSRF 保护、登录表单等。
     *  - 这是最核心的配置，定义了应用程序的请求如何被保护。
     * 常见用法：
     *  - 配置路径的访问权限
     *  - 自定义登录、注销行为
     *  - 开启/关闭 CSRF 保护
     *  - 配置 HTTP 基础认证、表单登录等
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //todo 允许表单登录
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/login")
                .permitAll()
                .and()
                .csrf()
                .disable();
    }

    /**
     * 方法作用：
     *      配置认证（Authentication），也就是用户如何被验证，比如从数据库加载用户信息、内存中定义用户、或者使用自定义的认证机制。
     * 常见用法：
     *      - 配置用户信息来源（内存、数据库等）。
     *      - 自定义认证提供者（AuthenticationProvider）
     *      - 配置密码编码器（PasswordEncoder）
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //TODO 暂定从内存中加载用户，实际生产中需要从数据库中加载
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password(new BCryptPasswordEncoder().encode("123"))
                .roles("admin")
                .and()
                .withUser("user")
                .password(new BCryptPasswordEncoder().encode("123"))
                .roles("user");
    }

    /**
     * 方法作用:
     *  - 配置全局的 Web 层面安全设置，主要用于完全跳过 Spring Security 的过滤器链。
     *  - 一般用于静态资源（如 CSS、JS、图片）的忽略。
     * 常见用法:
     *  - 排除静态资源目录或某些特定的 URL，使其不经过安全过滤器。
     *  - web.ignoring().antMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**");
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    /**
     * AuthenticationManager对象在OAuth2认证服务中要使用，提前放入IOC容器中
     * Oauth的密码模式需要
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}