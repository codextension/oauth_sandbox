package net.khoury.elie.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Created by eelkhour on 28.10.2015.
 */
@Controller
public class HomeController extends AbstractController {

    @RequestMapping("/")
    public String home(Model model) {
        return "home";
    }

}
