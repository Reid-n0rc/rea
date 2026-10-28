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
 * caller selected a separate base address. An optional fourth argument lists
 * comma-separated inclusive {@code 0xstart-0xend} ranges that are split from
 * the file block and made non-writable before auto-analysis, so the decompiler
 * treats constants and switch tables read from them as fixed.
 */
public final class ReaGhidraPrepareRaw extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 3 && arguments.length != 4) {
            throw new IllegalArgumentException(
                "Raw binary preparation requires the committed language, base address, entry address and optional read-only ranges"
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
        if (arguments.length == 4) {
            for (String range : arguments[3].split(",")) {
                markReadOnly(space, range);
            }
        }
        addEntryPoint(entry);
        if (!disassemble(entry) || createFunction(entry, "entry") == null) {
            throw new IllegalStateException("Raw binary entry cannot be decoded as a function");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA raw binary prepared", true);
    }

    /** Split one file-backed range from its block and clear the block's write permission. */
    private void markReadOnly(AddressSpace space, String range) throws Exception {
        String[] bounds = range.split("-", -1);
        if (bounds.length != 2 || !bounds[0].startsWith("0x") || !bounds[1].startsWith("0x")) {
            throw new IllegalArgumentException("Raw binary read-only range must be 0xstart-0xend: " + range);
        }
        Address start = space.getAddress(bounds[0]);
        Address end = space.getAddress(bounds[1]);
        MemoryBlock block = start == null ? null : currentProgram.getMemory().getBlock(start);
        if (end == null || end.compareTo(start) < 0 || block == null || !block.contains(end) ||
            !fileBacked(start) || !fileBacked(end)) {
            throw new IllegalArgumentException(
                "Raw binary read-only range must lie inside one file-backed initialized block: " + range
            );
        }
        if (!block.getStart().equals(start)) {
            currentProgram.getMemory().split(block, start);
            block = currentProgram.getMemory().getBlock(start);
        }
        if (!block.getEnd().equals(end)) {
            currentProgram.getMemory().split(block, end.add(1));
            block = currentProgram.getMemory().getBlock(start);
        }
        block.setWrite(false);
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
