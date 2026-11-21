// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data choosing the view or the template rendered.
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@Controller
class ViewController {
    @GetMapping("/doc")
    String doc(@RequestParam String section) {
        // ruleid: secreview.java.taint-view-injection
        return "docs/" + section;
    }

    @GetMapping("/page")
    ModelAndView page(@RequestParam String name) {
        // ruleid: secreview.java.taint-view-injection
        return new ModelAndView("pages/" + name);
    }

    @GetMapping("/back")
    String back(@RequestParam String target) {
        // ok: secreview.java.taint-view-injection
        return "redirect:/home";
    }

    @GetMapping("/help")
    String help(@RequestParam String topic, org.springframework.ui.Model model) {
        model.addAttribute("topic", topic);
        // ok: secreview.java.taint-view-injection
        return "help";
    }

    @GetMapping("/raw")
    @ResponseBody
    String raw(@RequestParam String text) {
        // ok: secreview.java.taint-view-injection
        return text;
    }
}
