package skeleton;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.*;
import ghidra.util.Msg;


/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class XbeLoader extends AbstractLibrarySupportLoader {
	public XbeImageHeader header;
	List<XbeSectionHeader> sectionHeaders;
	boolean isDebug;

	@Override
	public String getName() {

		// TODO: Name the loader.  gThis name must match the name of the loader in the .opinion
		// files.

		return "Xbox Executable Format (XBE)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		sectionHeaders = new ArrayList<>();

		// Examine the bytes in 'provider' to determine if this loader can load it.  If it
		// can load it, return the appropriate load specifications.
		BinaryReader reader = new BinaryReader(provider, true);
		if (reader.readNextAsciiString(4).equals("XBEH")) {
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair("x86:LE:32:default", "windows"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);

		// Read XBE header
		header = new XbeImageHeader(reader);

		// Read headers into memory
		reader.setPointerIndex(0);
		createSection(api, "headers", reader,
				header.baseAddr, header.imageHeaderSize,
				0, header.imageHeaderSize, false);

		long FLAG_WRITABLE            = 0X00000001L;
		long FLAG_PRELOAD             = 0X00000002L;
		long FLAG_EXECUTABLE          = 0X00000004L;
		long FLAG_INSERTED_FILE       = 0X00000008L;
		long FLAG_HEAD_PAGE_READ_ONLY = 0X00000010L;
		long FLAG_TAIL_PAGE_READ_ONLY = 0X00000020L;

		// Read sections headers
		reader.setPointerIndex(header.sectionHeadersAddr - header.baseAddr);
		for (int i = 0; i < (int)header.sectionCount; i++) {
			XbeSectionHeader secHdr = new XbeSectionHeader(reader);
			sectionHeaders.add(secHdr);

			// Get section name
			String name = reader.readAsciiString(secHdr.sectionNameAddr - header.baseAddr);

			// Read section data
			createSection(api, name, reader,
					secHdr.virtualAddr, secHdr.virtualSize,
					secHdr.rawAddr, secHdr.rawSize, (secHdr.flags & FLAG_EXECUTABLE) != 0);
		}

		// Unscramble entry point
		long ENTRY_DEBUG  = 0x94859D4BL;
		long ENTRY_RETAIL = 0xA8FC57ABL;
		long entryAddr = header.entryAddr ^ ENTRY_DEBUG;
		if (entryAddr < 0x4000000) {
			isDebug = true;
		} else {
			entryAddr = header.entryAddr ^ ENTRY_RETAIL;
			isDebug = false;
		}

		// Initialize entry point (FIXME)
		api.createFunction(api.toAddr(entryAddr), "_entry");
		api.addEntryPoint(api.toAddr(entryAddr));
	}

	private void createSection(FlatProgramAPI api, String name, BinaryReader input, long vaddr, long vlen, long off, long len, boolean exec)
	{
		try {
			// Read in section data and blank difference
			byte[] data = input.readByteArray(off, (int)vlen);
			for (int i = (int)len; i < (int)vlen; i++) {
				data[i] = 0;
			}

			// Create the memory block
			MemoryBlock sec = api.createMemoryBlock(name, api.toAddr(vaddr), data, true);
			sec.setExecute(exec);
			sec.setRead(true);
			sec.setWrite(true);
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
//		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
