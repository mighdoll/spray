package spray.io.openssl.api;

import org.bridj.BridJ;
import org.bridj.Pointer;
import org.bridj.ann.Library;

@Library("tcmalloc_minimal")
public class TCMalloc {
    static {
        BridJ.register();
    }

    public static native void MallocExtension_GetStats(Pointer<Byte> chars, int length);
    public static native void MallocExtension_ReleaseFreeMemory();
}
