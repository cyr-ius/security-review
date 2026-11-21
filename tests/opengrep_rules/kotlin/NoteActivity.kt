// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Android: data sent by another application to an exported component.
package com.example

import android.app.Activity
import android.database.sqlite.SQLiteDatabase
import android.util.Base64
import android.webkit.WebView
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream

class NoteActivity : Activity() {
    fun load(db: SQLiteDatabase, web: WebView) {
        val id = intent.getStringExtra("id")
        // ruleid: secreview.kotlin.taint-sql
        db.rawQuery("SELECT * FROM notes WHERE id = $id", null)
        // ok: secreview.kotlin.taint-sql
        db.rawQuery("SELECT * FROM notes WHERE id = ?", arrayOf(id))
        val tag = intent.data?.getQueryParameter("tag")
        // ruleid: secreview.kotlin.taint-sql
        db.execSQL("DELETE FROM notes WHERE tag = '$tag'")
        // ruleid: secreview.kotlin.taint-xss
        web.loadDataWithBaseURL(null, intent.getStringExtra("html")!!, "text/html", "utf-8", null)
        val state = Base64.decode(intent.getStringExtra("state"), Base64.DEFAULT)
        // ruleid: secreview.kotlin.taint-deserialization
        ObjectInputStream(ByteArrayInputStream(state)).readObject()
        // ok: secreview.kotlin.taint-deserialization
        ObjectInputStream(openFileInput("cache.bin")).readObject()
    }
}
