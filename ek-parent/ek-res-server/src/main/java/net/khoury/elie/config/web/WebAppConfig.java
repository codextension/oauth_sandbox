package net.khoury.elie.config.web;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * Created by eelkhour on 24.10.2015.
 */
@Configuration
@EnableWebMvc
@Import(GlobalMethodSecurityConfig.class)
@ComponentScan(basePackages = { "net.khoury.elie.controller" })
public class WebAppConfig extends WebMvcConfigurerAdapter {

}
