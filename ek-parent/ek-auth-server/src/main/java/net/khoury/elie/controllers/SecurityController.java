package net.khoury.elie.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Created by eelkhour on 31.10.2015.
 */

@Controller
@SessionAttributes("authorizationRequest")
public class SecurityController extends AbstractController {

	@RequestMapping("/login")
	public String login() {
		return "login";
	}

	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public String logout(Model model, @RequestParam(value = "redirect", required = false) String redirectUrl) {
		model.addAttribute("redirectUrl", redirectUrl);
		return "logout";
	}

	@RequestMapping("/oauth/confirm_access")
	public ModelAndView getAccessConfirmation(Map<String, Object> model, HttpServletRequest request) throws Exception {

		return new ModelAndView("/oauth/confirm_access", model);
	}
}
