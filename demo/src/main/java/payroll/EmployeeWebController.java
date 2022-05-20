package payroll;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import java.util.Map;
import java.util.Collections;

@Controller
public class EmployeeWebController {
    //private final EmployeeRepository repository;

    EmployeeWebController(EmployeeRepository repository) {
        //this.repository = repository;
    }

    @GetMapping("/")
	public String home(@AuthenticationPrincipal OAuth2User principal, Model model) {
        if(principal == null) return "home";
        model.addAttribute("loggedInUser", principal.getAttribute("name"));
    
        // Resolved through thymeleaf view resolver
        //Thymeleaf searches for this template in templates folder
		return "loggedIn";
	}

    @GetMapping("/employees")
	public String getEmployees(@AuthenticationPrincipal OAuth2User principal, Model model) {
        model.addAttribute("loggedInUser", principal.getAttribute("name"));
		// List<Employee> employees = repository.findAll();
        // model.addAttribute("employeeList", employees);

        // Resolved through thymeleaf view resolver
        //Thymeleaf searches for this template in templates folder
		return "employees";
	}

    @GetMapping("/login")
	public String login(Model model) {
		return "login";
	}
}
