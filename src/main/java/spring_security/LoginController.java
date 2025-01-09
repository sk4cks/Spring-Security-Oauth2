package spring_security;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class LoginController {

    @GetMapping("/loginPage")
    @ResponseBody
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/login")
    public String login() { return "login"; }
}
