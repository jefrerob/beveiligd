package be.vdab.beveiligd.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.sql.DataSource;

@EnableWebSecurity
class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String MANAGER = "manager";
    private static final String HELPDESKMEDEWERKER = "helpdeskmedewerker";
    private static final String MAGAZIJNIER = "magazijnier";
    private final DataSource datasource;

    public SecurityConfig(DataSource datasource) {
        this.datasource = datasource;
    }

    @Override
    protected void
    configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.jdbcAuthentication().dataSource(datasource);
    }

    @Override public void configure(WebSecurity web) {

        web
                .ignoring()
                .mvcMatchers("/images/**")
                .mvcMatchers("/css/**")
                .mvcMatchers("/js/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.logout(logout -> logout.logoutSuccessUrl("/"));
        http.formLogin(login -> login.loginPage("/login"));
        http
                    .authorizeRequests(requests -> requests
                            .mvcMatchers("/offertes").hasAuthority(MANAGER)
                        .mvcMatchers("/werknemers").hasAnyAuthority(MAGAZIJNIER,HELPDESKMEDEWERKER)
                            .mvcMatchers("/", "/login").permitAll()
                            .mvcMatchers("/**").authenticated());
    }
}
