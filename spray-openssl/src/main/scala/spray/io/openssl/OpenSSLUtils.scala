package spray.io.openssl

import api.TCMalloc
import org.bridj.Pointer

object OpenSSLUtils {
  val tcstatsbuffer = Pointer.allocateBytes(60000)
  def tcMallocDumpStats() {
    TCMalloc.MallocExtension_GetStats(tcstatsbuffer, 10000)
    println(tcstatsbuffer.getCString)
    api.SSL.report()
  }
  def tcMallocFree() {
    TCMalloc.MallocExtension_ReleaseFreeMemory()
  }
}
