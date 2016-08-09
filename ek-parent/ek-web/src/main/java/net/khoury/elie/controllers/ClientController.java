package net.khoury.elie.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Created by eelkhour on 28.10.2015.
 */
@Controller
public class ClientController extends AbstractController {
    private String baseResUrl = "https://localhost:8443/ek-res-server/";

    @Autowired
    private OAuth2RestOperations restTemplate;

    @Autowired
    private ResourceServerTokenServices tokenServices;

    @RequestMapping("/user")
    public String currentUser(Model model) throws URISyntaxException {
        ResponseEntity<String> user = restTemplate.getForEntity(new URI(baseResUrl + "services/user/current"),
                String.class);
        model.addAttribute("user", user.getBody());
        return "user";
    }

    @RequestMapping("/")
    public String home() throws URISyntaxException {
        return "home";
    }
}
