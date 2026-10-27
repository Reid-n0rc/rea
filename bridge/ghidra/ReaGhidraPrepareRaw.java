import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

/**
 * Seed the caller-supplied raw-binary entry before default auto-analysis.
 *
 * Arguments: the committed language ID, the address where file offset 0 is
 * mapped, and the entry address. The two addresses are equal unless the
 * caller selected a separate base address.
 */
public final class ReaGhidraPrepareRaw extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 3) {
            throw new IllegalArgumentException(
                "Raw binary preparation requires the committed language, base address and entry address"
            );
        }
        String expectedLanguage = arguments[0];
        String baseHex = arguments[1];
        String entryHex = arguments[2];
        if (!currentProgram.getLanguageID().getIdAsString().equals(expectedLanguage) ||
            !currentProgram.getExecutableFormat().equals("Raw Binary")) {
            throw new IllegalArgumentException(
                "Raw binary preparation requires the committed language and BinaryLoader import"
            );
        }
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Address base = space.getAddress(baseHex);
        Address entry = space.getAddress(entryHex);
        boolean separateBase = base != null && !base.equals(entry);
        if (!fileStartsAt(base)) {
            throw new IllegalArgumentException(
                separateBase
                    ? "Raw binary import must map file offset 0 at the caller-supplied base address"
                    : "Raw binary import must map file offset 0 at the caller-supplied entry"
            );
        }
        if (separateBase && !fileBacked(entry)) {
            throw new IllegalArgumentException(
                "Raw binary entry must lie inside the file-backed initialized image"
            );
        }
        addEntryPoint(entry);
        if (!disassemble(entry) || createFunction(entry, "entry") == null) {
            throw new IllegalStateException("Raw binary entry cannot be decoded as a function");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA raw binary prepared", true);
    }

    /** Processor-defined zero page/stack blocks can precede the imported file. */
    private boolean fileStartsAt(Address address) {
        MemoryBlock block = address == null ? null : currentProgram.getMemory().getBlock(address);
        if (block == null) {
            return false;
        }
        for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
            if (source.getFileBytes().isPresent() && source.getFileBytesOffset() == 0 &&
                address.equals(source.getMinAddress())) {
                return true;
            }
        }
        return false;
    }

    /** The entry must decode from initialized bytes of the imported file. */
    private boolean fileBacked(Address address) {
        MemoryBlock block = address == null ? null : currentProgram.getMemory().getBlock(address);
        if (block == null || !block.isInitialized()) {
            return false;
        }
        for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
            if (source.getFileBytes().isPresent() && source.contains(address)) {
                return true;
            }
        }
        return false;
    }
}
