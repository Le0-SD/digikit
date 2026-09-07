import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;

public class Callers extends GhidraScript {
    public void run() throws Exception {
        PrintWriter w = new PrintWriter(getScriptArgs()[0]);
        long[] targets = {0x40179f90L, 0x40179ea8L, 0x40179e64L, 0x4011122cL};
        for (long t : targets) {
            Address a = toAddr(t);
            w.println(String.format("=== callers of 0x%08x ===", t));
            int n = 0;
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
                Address from = r.getFromAddress();
                Function cf = getFunctionContaining(from);
                w.println(String.format("   from %s  in fn %s  (%s)", from,
                    cf == null ? "?" : cf.getEntryPoint().toString(), r.getReferenceType()));
                if (++n >= 40) break;
            }
            if (n == 0) w.println("   (none)");
        }
        w.close();
        println("ok");
    }
}
