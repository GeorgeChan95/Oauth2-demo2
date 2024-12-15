package cn.myjszl.oauth.server.config;

import cn.myjszl.oauth.server.exception.OAuthResourceAuthenticationEntryPoint;
import cn.myjszl.oauth.server.exception.RequestAccessDeniedHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

/**
 * @author 公众号：码猿技术专栏
 * OAuth2.0 资源服务的配置类
 * `@EnableResourceServer`：该注解标记这是一个资源服务
 * `@EnableGlobalMethodSecurity`：该注解开启注解校验权限
 */
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true,jsr250Enabled = true,securedEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    @Autowired
    private RequestAccessDeniedHandler requestAccessDeniedHandler;

    @Autowired
    private OAuthResourceAuthenticationEntryPoint authenticationEntryPoint;

    /**
     * 令牌服务的配置
     */
    @Bean
    public ResourceServerTokenServices tokenServices() {
        DefaultTokenServices services = new DefaultTokenServices();
        //配置令牌存储策略，使用AccessTokenConfig配置的JwtTokenStore
        services.setTokenStore(tokenStore);
        //令牌的增强JwtAccessTokenConverter
        services.setTokenEnhancer(jwtAccessTokenConverter);
        return services;
    }

    /**
     * 方法作用：
     *      - 配置资源服务器的核心属性，比如资源 ID、令牌服务（Token Services）、令牌解析器（Token Store/Token Enhancer）等。
     *      - 定义与资源服务器本身相关的安全性配置。
     *
     * 常见用途：
     *      - 设置资源服务器的标识（Resource ID）。
     *      - 定义令牌验证方式，例如使用 JWT 或 远程校验（通过 RemoteTokenServices）
     *      - 自定义异常处理器。
     * 关键点：
     *      - 该方法通常用于配置资源服务器如何处理访问令牌（Access Token）的验证逻辑。
     *      - 如果你的资源服务器需要与授权服务器通信或自定义令牌解析，就需要在这里定义。
     *
     * 配置资源id和令牌校验服务
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources)  {
        //配置唯一资源id
        resources.resourceId("res1")
                //定制令牌失效的提示信息
                .authenticationEntryPoint(authenticationEntryPoint)
                //定制权限不足的提示信息
                .accessDeniedHandler(requestAccessDeniedHandler)
                //配置令牌校验服务
                .tokenServices(tokenServices());
    }

    /**
     * 方法作用：
     *      - 配置与 HTTP 请求相关的安全性规则，例如：
     *          - 资源的访问控制（基于 URL 的权限）
     *          - CSRF 保护。
     *          - Session 管理等。
     * 常见用途：
     *      - 定义哪些请求路径需要认证、哪些可以公开访问。
     *      - 配置访问控制规则（基于角色、Scope 等）。
     *      - 自定义登录、注销行为。
     * 关键点：
     *      - 这个方法是用来定义 资源服务器对请求的具体保护策略。
     *      - 一般与 OAuth2 的 Scope 或用户角色相结合，控制资源的访问权限。
     * 配置security的安全机制
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        //#oauth2.hasScope()校验客户端的权限，这个all是在客户端中的scope
        http.authorizeRequests()
                .antMatchers("/**").access("#oauth2.hasScope('all')")
                .anyRequest().authenticated();
    }
}