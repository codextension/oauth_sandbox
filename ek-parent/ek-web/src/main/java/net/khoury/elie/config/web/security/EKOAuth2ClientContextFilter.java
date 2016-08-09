package net.khoury.elie.config.web.security;

import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;

/**
 * Created by elie on 06.03.16.
 */
public class EKOAuth2ClientContextFilter extends OAuth2ClientContextFilter {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    protected void redirectUser(UserRedirectRequiredException e, HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUri = e.getRedirectUri();
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromHttpUrl(redirectUri);
        Map<String, String> requestParams = e.getRequestParams();
        for (Map.Entry<String, String> param : requestParams.entrySet()) {
            builder.queryParam(param.getKey(), param.getValue().replace(" ","+").replace("%20", "+"));
        }

        if (e.getStateKey() != null) {
            builder.queryParam("state", e.getStateKey());
        }

        this.redirectStrategy.sendRedirect(request, response, builder.build()
                .toUriString());
    }

    /**
     * Calculate the current URI given the request.
     *
     * @param request
     *            The request.
     * @return The current uri.
     */
    protected String calculateCurrentUri(HttpServletRequest request)
            throws UnsupportedEncodingException {
        ServletUriComponentsBuilder builder = ServletUriComponentsBuilder
                .fromRequest(request);
        // Now work around SPR-10172...
        String queryString = request.getQueryString();
        boolean legalSpaces = queryString != null && queryString.contains("+");
        if (legalSpaces) {
            builder.replaceQuery(queryString.replace("+", "%20"));
            builder.replaceQuery(queryString.replace("+", " "));
        }
        UriComponents uri = null;
        try {
            uri = builder.replaceQueryParam("code").build(true);
        } catch (IllegalArgumentException ex) {
            // ignore failures to parse the url (including query string). does't
            // make sense for redirection purposes anyway.
            return null;
        }
        String query = uri.getQuery();
        if (legalSpaces) {
            query = query.replace("%20", "+");
            query = query.replace(" ", "+");
        }
        return ServletUriComponentsBuilder.fromUri(uri.toUri())
                .replaceQuery(query).build().toString();
    }
}
