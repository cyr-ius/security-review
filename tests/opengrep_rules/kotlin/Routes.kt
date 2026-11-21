// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Ktor routes and servlets in Kotlin.
package com.example

import io.ktor.http.ContentType
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

fun Application.routes() {
    routing {
        get("/users/{id}") {
            val id = call.parameters["id"]
            // ruleid: secreview.kotlin.taint-sql
            connection.prepareStatement("SELECT * FROM users WHERE id = $id")
            val name = call.request.queryParameters["name"]
            // ruleid: secreview.kotlin.taint-xss
            call.respondText("<h1>Hello $name</h1>", ContentType.Text.Html)
            // ok: secreview.kotlin.taint-xss
            call.respondText("Hello $name", ContentType.Text.Plain)
            // ruleid: secreview.kotlin.taint-open-redirect
            call.respondRedirect(call.parameters["next"]!!)
            // ok: secreview.kotlin.taint-open-redirect
            call.respondRedirect("/users/$id")
            // ruleid: secreview.kotlin.taint-open-redirect
            call.respondRedirect("//${call.parameters["host"]}/login")
            // ruleid: secreview.kotlin.taint-ssrf
            client.get(call.parameters["url"]!!)
        }
    }
}

class SearchServlet : HttpServlet() {
    override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
        val term = request.getParameter("q")
        // ruleid: secreview.kotlin.taint-sql
        statement.executeQuery("SELECT * FROM articles WHERE title LIKE '%$term%'")
        // ruleid: secreview.kotlin.taint-xss
        response.writer.write("<p>$term</p>")
    }
}
