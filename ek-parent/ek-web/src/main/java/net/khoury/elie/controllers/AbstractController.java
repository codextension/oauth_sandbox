package net.khoury.elie.controllers;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.web.bind.ServletRequestDataBinder;
import org.springframework.web.bind.annotation.InitBinder;

/**
 * Created by Elie on 25.10.2015.
 */
public abstract class AbstractController {

	@InitBinder
	protected void initBinder(HttpServletRequest request, ServletRequestDataBinder binder) throws Exception {
		// bind empty strings as null
		binder.registerCustomEditor(String.class, new StringTrimmerEditor(true));
	}
}
