package cc.spray.examples

import com.typesafe.config.ConfigFactory
import akka.actor.{Props, ActorSystem}
import cc.spray.io.IOBridge
import cc.spray.can.client.{HttpDialog, HttpClient}
import cc.spray.http.HttpRequest


object HttpsExample extends App {
  // we need an ActorSystem to host our application in
  implicit val system = ActorSystem("https-example")
  def log = system.log

  // every spray-can HttpClient (and HttpServer) needs an IOBridge for low-level network IO
  // (but several servers and/or clients can share one)
  val ioBridge = new IOBridge(system).start()

  // create and start a spray-can HttpClient with SSL/TLS support enabled
  val httpClient = system.actorOf(
    props = Props(new HttpClient(ioBridge, ConfigFactory.parseString("spray.can.client.ssl-encryption = on"))),
    name = "https-client"
  )

  // create a very basic HttpDialog that results in a Future[HttpResponse]
  log.info("Dispatching GET request to github.com")
  val responseF =
    HttpDialog(httpClient, "github.com", port = 443, ssl = true)
      .send(HttpRequest(uri = "/spray/spray"))
      .end

  // "hook in" our continuation
  responseF onComplete {
    case Right(response) =>
      log.info(
        """|Result from host:
           |status : {}
           |headers: {}
           |body   : {} bytes""".stripMargin,
        response.status,
        response.headers.mkString("\n  ", "\n  ", ""),
        response.entity.buffer.length
      )
      system.shutdown()

    case Left(error) =>
      log.error("Could not get response due to {}", error)
      system.shutdown()
  }

  // finally we drop the main thread but hook the shutdown of
  // our IOBridge into the shutdown of the applications ActorSystem
  system.registerOnTermination {
    ioBridge.stop()
  }

}
