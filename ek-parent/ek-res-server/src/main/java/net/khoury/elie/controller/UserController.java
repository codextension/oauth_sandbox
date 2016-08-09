package net.khoury.elie.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by eelkhour on 25.10.2015.
 */
@RestController
public class UserController extends AbstractController {

    @PreAuthorize("#oauth2.hasScope('account_info') or (!#oauth2.isOAuth() and hasRole('ROLE_USER'))")
    @RequestMapping("/services/user/current")
	public String getUsername() {
		return SecurityContextHolder.getContext().getAuthentication().getName();

	}
}
