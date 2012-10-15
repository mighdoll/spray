package spray.io

import javax.net.ssl.SSLEngine
import collection.mutable.Queue
import akka.actor.ActorRef
import akka.event.LoggingAdapter
import java.nio.ByteBuffer

import SslTlsSupport.EngineCreated
import org.eclipse.jetty.npn.NextProtoNego.{ClientProvider, ServerProvider}
import org.eclipse.jetty.npn.NextProtoNego

object SslNpnSupport {
  def apply(supported: TlsNpnSupportedProtocols, log: LoggingAdapter, server: Boolean)(sslStage: PipelineStage): PipelineStage = new PipelineStage {
    def build(context: PipelineContext, commandPL: CPL, eventPL: EPL): Pipelines = new Pipelines {
      // This stage has three states:
      //
      //   - Waiting for an engine to register the npn handler to. In this state
      //     we don't let any events get to the Ssl stage because we might otherwise miss
      //     the Npn callbacks. After the npn callback is registered we replay those events.
      //   - Waiting for Npn negotiation to be finished. In this state we don't expect
      //     any events to flow out of the Ssl stage. If we receive commands we queue them
      //     for later when NPN is finished and the final pipelines have been built.
      //   - Npn was finished and the callbacks have installed the final protocol-specific
      //     pipelines.

      var engineCreated = false
      val pendingEvents = Queue.empty[(Event, ActorRef)]

      var handshakeReady = false
      val pendingCommands = Queue.empty[(Command, ActorRef)]

      val sslPipes = sslStage.build(context, commandPL, e => upstreamEventPL(e))

      var upstreamEventPL: EPL = {
        case e if !handshakeReady =>
          throw new IllegalStateException("Unexpected event received before NPN "+e)
        case e => eventPL(e)
      }
      var downstreamCommandPL: CPL = sslCommandPipeline

      // it is important to introduce the proxy to the var here
      def commandPipeline = { c => downstreamCommandPL(c) }

      def sslCommandPipeline: CPL = {
        // if we are the client we receive the send which from below
        // which should trigger the ssl handshake with the remote party.
        case s: IOPeer.Send if !handshakeReady =>
          require(!server)
          sslPipes.commandPipeline(s)

        case cmd if !handshakeReady =>
            log.debug("Queing command for after handshake: "+cmd)
            pendingCommands.enqueue((cmd, context.sender))

        case c => sslPipes.commandPipeline(c)
      }
      def eventPipeline = {
        case EngineCreated(sslEngine) => registerNpn(sslEngine)

        // we need to make sure that the Npn handler is registered before
        // we let the ssl stage process any incoming data
        case e if !engineCreated =>
          log.debug("Queing event for after engine registration: {}", e)
          pendingEvents.enqueue((e, context.sender))

        case e => sslPipes.eventPipeline(e)
      }

      def registerNpn(engine: SSLEngine) {
        import scala.collection.JavaConverters._
        val protocolNames = supported.pipelinesPerProtocol.map(_._1)
        log.debug("NPN with supported protocols: {}", protocolNames.mkString(", "))

        if (server){
            object NPNServerProvider extends ServerProvider {
              def unsupported() {
                protocolSelected(supported.defaultProtocol)
              }
              def protocols(): java.util.List[String] = protocolNames.asJava
              def protocolSelected(protocol: String) {
                val stage = supported.pipelinesPerProtocol.find(_._1 == protocol).get._2
                val pls = stage.build(context, sslCommandPipeline, _ => () /* we ignore things flowing out of the pipe at the top */)

                // the idea is that we rewire the pipelines so that the chosen protocol
                // pipeline is now on top of us
                upstreamEventPL = pls.eventPipeline
                downstreamCommandPL = pls.commandPipeline

                handshakeReady = true
                pendingCommands.foreach { case (cmd, sender) => context.self.tell(cmd, sender) }
                pendingCommands.clear()
              }
            }
            // we already make sure that we choose the first protocol in case *we* don't support
            // NPN (bootCP missing)
            NPNServerProvider.unsupported()
            NextProtoNego.put(engine, NPNServerProvider)

        } else {
            log.debug("Switching on client side TLS-NPN")

            object NPNClientProvider extends ClientProvider {
              def supports(): Boolean = true
              def unsupported() {
                selectProtocol(java.util.Arrays.asList(supported.defaultProtocol))
              }
              def selectProtocol(protocols: java.util.List[String]): String = {
                val chosen = protocols.asScala.find(protocolNames.contains).getOrElse {
                  log.warning("No protocol supported ({}) from offered ones ({}).", protocolNames.mkString(", "), protocols.asScala.mkString(", "))
                  supported.defaultProtocol
                }

                log.debug("Selected protocol {}", chosen)

                val stage = supported.pipelinesPerProtocol.find(_._1 == chosen).get._2
                val pls = stage.build(context, sslCommandPipeline, _ => () /* we ignore things flowing out of the pipe at the top */)

                // we rewire the pipelines so that the chosen protocol pipeline is now on top of us
                upstreamEventPL = pls.eventPipeline
                downstreamCommandPL = pls.commandPipeline

                handshakeReady = true
                pendingCommands.foreach { case (cmd, sender) => context.self.tell(cmd, sender) }
                pendingCommands.clear()

                chosen
              }
            }
            NextProtoNego.put(engine, NPNClientProvider)
            engine.beginHandshake()
            context.self ! IOPeer.Send(ByteBuffer.allocate(0))
        }

        engineCreated = true
        pendingEvents.foreach { case (cmd, sender) => context.self.tell(cmd, sender) }
        pendingEvents.clear()
      }
    }
  }
}

case class TlsNpnSupportedProtocols(defaultProtocol: String, pipelinesPerProtocol: (String, PipelineStage)*) {
  require(pipelinesPerProtocol.exists(_._1 == defaultProtocol))
}
