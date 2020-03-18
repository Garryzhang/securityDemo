package com.garry.springsecuritydemo.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;


@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .anyRequest().authenticated()
//                .and().
//                formLogin().loginPage("/views/myLogin.html")
//                .permitAll().and()
//                .csrf().disable();
        http.authorizeRequests()
                .antMatchers("/admin/api/**").hasRole("ADMIN")
                .antMatchers("/user/api/**").hasRole("USER")
                .antMatchers("/app/api/**").permitAll()
                .anyRequest().authenticated()
                .and().formLogin();
    }

    /**
     * 基于内存的多用户支持
     *
     @Override protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
     .withUser("user")
     .password(new BCryptPasswordEncoder().encode("123456"))
     .roles("USER")
     .and()
     .withUser("admin")
     .password(new BCryptPasswordEncoder().encode("123456"))
     .roles("USER","ADMIN");
     }
     */

    /**
     * 基于jdbc的多用户支持 一种方式
     *
     * @Override protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * auth.jdbcAuthentication().dataSource(dataSource)
     * .passwordEncoder(new BCryptPasswordEncoder())
     * .withUser("user")
     * .password(new BCryptPasswordEncoder().encode("123456"))
     * .roles("USER")
     * .and()
     * .withUser("admin")
     * .password(new BCryptPasswordEncoder().encode("123456"))
     * .roles("USER","ADMIN");
     * }
     */

    /**
     * 基于jdbc的多用户支持 另外一种方式
     * */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource)
                .passwordEncoder(new BCryptPasswordEncoder());
    }

    /**
     * 为自定义认证可注释
     *
    @Bean
    public UserDetailsService userDetailsService() {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager();
        manager.setDataSource(dataSource);

        if (!manager.userExists("user")) {
            manager.createUser(User.withUsername("user").password(new BCryptPasswordEncoder().encode("123456")).roles("USER").build());
        }
        if (!manager.userExists("admin")) {
            manager.createUser(User.withUsername("admin").password(new BCryptPasswordEncoder().encode("123456")).roles("USER", "ADMIN").build());
        }
        return manager;
    }
     */
}