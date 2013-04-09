/*
 * Copyright (C) 2011-2012 spray.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package spray.io

import spray.util.Reply
import akka.actor.{ActorRef, Status}
import akka.spray.RefUtils


abstract class IOClient(val rootIoBridge: ActorRef) extends IOPeer {
  require(RefUtils.isLocal(rootIoBridge), "An IOClient must live in the same JVM as the IOBridge it is to use")

  import IOClient._

  override def preStart() {
    log.info("Starting {}", self.path)
  }

  override def postStop() {
    log.info("Stopped {}", self.path)
  }

  case class Registered(commander: ActorRef, handle: Connection)

  def receive: Receive = {
    case cmd: Connect =>
      rootIoBridge.tell(cmd, Reply.withContext(sender))

    case Reply(IOBridge.Connected(key, tag), commander: ActorRef) =>
      val handle = createConnectionHandle(key, sender, commander, tag)
      sender ! IOBridge.Register(handle, Registered(commander, handle))

    case Registered(commander, handle) =>
      handle.handler ! ConnectedWithCommander(handle, commander)

    case ConnectedWithCommander(handle, commander) =>
      commander ! Connected(handle)

    case Reply(Status.Failure(CommandException(Connect(remoteAddress, _, _), msg, cause)), commander: ActorRef) =>
      commander ! Status.Failure(IOClientException("Couldn't connect to " + remoteAddress, cause))
  }
}

object IOClient {
  object ReportConnected extends PipelineStage {
    def build(context: PipelineContext, commandPL: CPL, eventPL: EPL): Pipelines = new Pipelines {
      def commandPipeline = commandPL
      def eventPipeline = {
        case IOClient.ConnectedWithCommander(connection, commander) =>
          commandPL(IOClient.Tell(commander, IOClient.Connected(connection), context.connection.handler))
        case e => eventPL(e)
      }
    }
  }

  case class IOClientException(msg: String, cause: Throwable = null) extends RuntimeException(msg, cause)

  ////////////// COMMANDS //////////////
  type Connect  = IOBridge.Connect; val Connect = IOBridge.Connect
  type Close    = IOPeer.Close;     val Close = IOPeer.Close
  type Send     = IOPeer.Send;      val Send = IOPeer.Send
  type Tell     = IOPeer.Tell;      val Tell = IOPeer.Tell // only available with ConnectionActors mixin
  val StopReading = IOPeer.StopReading
  val ResumeReading = IOPeer.ResumeReading

  ////////////// EVENTS //////////////
  case class Connected(connection: Connection) extends Event
  case class ConnectedWithCommander(connection: Connection, commander: ActorRef) extends Event
  type Closed = IOPeer.Closed;     val Closed = IOPeer.Closed
  type AckEvent = IOPeer.AckEvent; val AckEvent = IOPeer.AckEvent
  type Received = IOPeer.Received; val Received = IOPeer.Received
}
