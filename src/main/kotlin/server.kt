import com.github.kevinsawicki.http.HttpRequest
import com.google.gson.Gson
import com.google.gson.JsonParser
import io.ktor.application.*
import io.ktor.html.respondHtml
import io.ktor.http.HttpStatusCode
import io.ktor.response.*
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import jdk.nashorn.internal.parser.JSONParser
import kotlinx.html.*
import kotlinx.serialization.Serializable
import net.mamoe.yamlkt.Yaml
import java.net.URLEncoder
import java.text.SimpleDateFormat
import java.util.*

val gson = Gson()
val sdf = SimpleDateFormat()

fun main() {
    embeddedServer(Netty, port = System.getProperty("port").toInt(), host = "0.0.0.0") {
        routing {
            get("/subconv/{subUrl}/{extraOptions}") {
                if(call.parameters["subUrl"]==null){ //  || call.parameters["extraOptions"]==null
                    call.respondText { genSub("trojan","114514","127.0.0.1",11451,null,"[Converter] whereis suburl?") }
                }else{
                    val clashSubURL = Base64.URLSafe.decode(call.parameters["subUrl"]!!)
                    val extraOptions =if(call.parameters["extraOptions"]!=null) Base64.URLSafe.decode(call.parameters["extraOptions"]!!) else ""
                    runCatching {
                        HttpRequest.get(clashSubURL).body()
                    }.onFailure {
                        it.printStackTrace()
                        call.response.status(HttpStatusCode.NoContent)
                        call.respondText { genSub("trojan","114514","127.0.0.1",11451,null,"[Converter] FAILED_to_CONVERT") }
                    }.onSuccess { respond ->
                        println("Fetch subscribe success! $clashSubURL")
                        try {
                            val sub = parseSub( respond)
                        val subConvResult = StringBuilder()
                        println("Parsing proxies... ${sub.size}")
                        sub.forEach { proxy->
                            val json= JsonParser.parseString(proxy).asJsonObject
                            val data = ClashSubColumn()
                            val extraOpts = StringBuilder()
                            json.keySet().forEach{
                                when(it){
                                    "name" -> data.name = json[it].asString
                                    "type" -> data.type = json[it].asString
                                    "server" -> data.server=json[it].asString
                                    "port" -> data.port = json[it].asString
                                    "password" -> data.password=json[it].asString
                                    else -> {
                                        extraOpts.append("$it=${URLEncoder.encode(json[it].asString)}").append('&')
                                    }
                                }
                            }
                            if(!data.validate()){
                                println("Invalid proxy! $proxy")
                                subConvResult.append(genSub("trojan","114514","1",1,null,"[PARSEFAIL] ${data.name}")).append('\n')
                            }else{
                             //   println("Valid proxy! ${data.name}")
                                subConvResult.append(genSub(data.type!!,data.password!!,data.server!!,data.port!!.toInt(),extraOpts.toString()+extraOptions,data.name)).append('\n')
                            }
                        }
                        subConvResult.append(genSub("trojan","114514","1",1,null,"[Converter] Time: ${sdf.format(Date())} ${sub.size} proxies."))
                        call.respondText { subConvResult.toString() }
                        }catch(a: Throwable){
                            a.printStackTrace()
                        }
                    }
                }

            }
        }
    }.start(wait = true)
}
fun genSub(protoType:String,password:String,serverIp:String,serverPort:Int,extraOptions:String?,name:String?):String{
    return "$protoType://$password@$serverIp:$serverPort"+if(extraOptions==null){""}else{"?${extraOptions}"} + if(name==null){""}else{"#$name"}
}
class ClashSubColumn{
    var name:String?=null
    var type:String?=null
    var server:String?=null
    var port: String?=null
    var password: String?=null
    fun validate():Boolean{
        return name!=null && type !=null && server !=null && port !=null && password !=null
    }
}
fun parseSub(yaml: String):List<String>{
    val result = mutableListOf<String>()
    var flag = false
    var met = false
    for (it in yaml.lines()) {
        if(it.contains("proxies:")){
            flag = true
            met = true
        }else{
            if(met && it.isEmpty() || it.contains("proxy-groups")){
                flag=false
                return result
            }
            if(flag){
                result.add(it.removePrefix("  - "))
            }
        }
    }
    return emptyList()
}