// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// MongoDB queries built from request data.
package com.example;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.springframework.data.mongodb.core.query.BasicQuery;
import org.springframework.web.bind.annotation.*;

@RestController
public class MongoController {
    private MongoCollection<Document> users;

    @GetMapping("/users/search")
    public Object search(@RequestParam String filter, @RequestParam String name) {
        // ruleid: secreview.java.taint-nosql-injection
        users.find(Document.parse(filter));
        // ruleid: secreview.java.taint-nosql-injection
        users.find(Filters.where("this.name == '" + name + "'"));
        // ruleid: secreview.java.taint-nosql-injection
        new BasicQuery("{ name: '" + name + "' }");
        // ok: secreview.java.taint-nosql-injection
        return users.find(Filters.eq("name", name));
    }
}
