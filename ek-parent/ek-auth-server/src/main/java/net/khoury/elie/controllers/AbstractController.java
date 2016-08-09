package net.khoury.elie.controllers;

import net.khoury.elie.dao.PersonalDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.ServletRequestDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Created by eelkhour on 22.11.2015.
 */
public abstract class AbstractController implements Serializable {
    @Autowired
    private PersonalDataRepository personalDataRepository;


    @InitBinder
    protected void initBinder(HttpServletRequest request, ServletRequestDataBinder binder) throws Exception {
        // bind empty strings as null
        binder.registerCustomEditor(String.class, new StringTrimmerEditor(true));
    }

    @ModelAttribute(value = "supportedLocales")
    public List<Locale> supportedLocales() {
        List<Locale> locales = new ArrayList<>();
        locales.add(Locale.GERMANY);
        locales.add(Locale.UK);

        return locales;
    }

    @ModelAttribute(value = "loggedInName")
    public String loggedInName() {
        if (!SecurityContextHolder.getContext().getAuthentication().getName().equalsIgnoreCase("anonymousUser")) {
            return personalDataRepository.findNameByUsername(SecurityContextHolder.getContext().getAuthentication().getName());
        } else {
            return "Anonymous";
        }
    }
}
