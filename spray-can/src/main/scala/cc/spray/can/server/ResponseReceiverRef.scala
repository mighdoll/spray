/*
 * Copyright (C) 2011-2012 spray.cc
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

package cc.spray.can.server

import akka.util.Unsafe
import akka.spray.UnregisteredActorRef
import akka.actor._
import cc.spray.io.Command
import cc.spray.http._
import cc.spray.can.HttpCommand


object ResponseReceiverRef {
  private val responseStateOffset = Unsafe.instance.objectFieldOffset(
    classOf[ResponseReceiverRef].getDeclaredField("_responseStateDoNotCallMeDirectly"))

  sealed trait ResponseState
  case object Uncompleted extends ResponseState
  case object Completed extends ResponseState
  case object Chunking extends ResponseState
}

private class ResponseReceiverRef(openRequest: OpenRequest)
  extends UnregisteredActorRef(openRequest.connectionActorContext) {
  import ResponseReceiverRef._

  @volatile private[this] var _responseStateDoNotCallMeDirectly: ResponseState = Uncompleted

  def handle(message: Any)(implicit sender: ActorRef) {
    message match {
      case x: HttpResponse         => dispatch(x, Uncompleted, Completed)
      case x: ChunkedResponseStart => dispatch(x, Uncompleted, Chunking)
      case x: MessageChunk         => dispatch(x, Chunking, Chunking)
      case x: ChunkedMessageEnd    => dispatch(x, Chunking, Completed)
      case x: Command              => dispatch(x)
      case x =>
        openRequest.log.warning("Illegal response " + x + " to " + requestInfo)
        unhandledMessage(x)
    }
  }

  private def dispatch(part: HttpResponsePart, expectedState: ResponseState, newState: ResponseState)
                      (implicit sender: ActorRef) {
    if (Unsafe.instance.compareAndSwapObject(this, responseStateOffset, expectedState, newState)) {
      dispatch(new Response(openRequest, HttpCommand(part)))
    } else {
      openRequest.log.warning("Cannot dispatch " + part.getClass.getSimpleName +
        " as response (part) for " + requestInfo + " since current response state is '" +
        Unsafe.instance.getObjectVolatile(this, responseStateOffset) + "' but should be '" + expectedState + '\'')
      unhandledMessage(part)
    }
  }

  private def dispatch(cmd: Command)(implicit sender: ActorRef) {
    openRequest.connectionActorContext.self ! new Response(openRequest, cmd)
  }

  private def unhandledMessage(message: Any)(implicit sender: ActorRef) {
    openRequest.connectionActorContext.system.eventStream.publish(UnhandledMessage(message, sender, this))
  }

  private def requestInfo = openRequest.request.method.toString + " request to '" + openRequest.request.uri + '\''
}

private[server] case class Response(openRequest: OpenRequest, cmd: Command) extends Command