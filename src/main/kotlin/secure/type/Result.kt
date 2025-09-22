package tx.secure.type

import org.json.JSONException
import org.json.JSONObject

class Result {
    val alg: String
    val iv: String
    val ct: String
    val tag: String
    val epub: String?

    constructor(alg: String, iv: String, ct: String, tag: String, epk: String?) {
        this.alg = alg
        this.iv = iv
        this.ct = ct
        this.tag = tag
        this.epub = epk
    }

    @Throws(JSONException::class)
    constructor(obj: JSONObject) {
        this.alg = obj.getString("alg")
        this.iv = obj.getString("iv")
        this.ct = obj.getString("ct")
        this.tag = obj.getString("tag")
        this.epub = obj.getString("epub")
    }

    @Throws(JSONException::class)
    constructor(json: String) : this(JSONObject(json))

    @Throws(JSONException::class)
    fun toJson(): JSONObject {
        val obj = JSONObject()
        obj.put("alg", alg)
        obj.put("iv", iv)
        obj.put("ct", ct)
        obj.put("tag", tag)
        obj.put("epub", epub)
        return obj
    }

    // Sample output: {"alg":"AES-GCM-256","iv":"...","ct":"...","tag":"...","epub":"..."}
    fun toJsonString(): String {
        return try {
            toJson().toString()
        } catch (e: JSONException) {
            throw RuntimeException("Failed to convert to JSON string", e)
        }
    }
}