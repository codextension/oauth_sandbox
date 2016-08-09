package net.khoury.elie.config;

import net.khoury.elie.config.web.GlobalMethodSecurityConfig;
import net.khoury.elie.config.web.InfrastructureConfig;
import net.khoury.elie.config.web.WebAppConfig;
import net.khoury.elie.config.web.security.AuthorizationServerConfig;
import net.khoury.elie.config.web.security.SecurityConfig;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

/**
 * Created by eelkhour on 24.10.2015.
 */
public class WebAppInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {
    public static final String DEFAULT_FILTER_NAME = "springSecurityFilterChain";
    private static final String SERVLET_CONTEXT_PREFIX = "org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher";

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class<?>[]{SecurityConfig.class, AuthorizationServerConfig.class};
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class<?>[]{WebAppConfig.class, GlobalMethodSecurityConfig.class, InfrastructureConfig.class};
    }

    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        super.onStartup(servletContext);
        registerProxyFilter(servletContext, DEFAULT_FILTER_NAME);
        servletContext.addListener(RequestContextListener.class);
    }

    @Override
    protected String[] getServletMappings() {
        return new String[]{"/"};
    }

    private void registerProxyFilter(ServletContext servletContext, String name) {
        DelegatingFilterProxy filter = new DelegatingFilterProxy(name);
        filter.setContextAttribute(SERVLET_CONTEXT_PREFIX);
        servletContext.addFilter(name, filter).addMappingForUrlPatterns(null, false, "/*");
    }
}