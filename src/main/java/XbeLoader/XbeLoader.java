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
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.*;
import ghidra.util.Msg;
import ghidra.program.database.function.OverlappingFunctionException;


/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class XbeLoader extends AbstractLibrarySupportLoader {
	public XbeImageHeader header;
	List<XbeSectionHeader> sectionHeaders;
	boolean isDebug;
	private Program program;

	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the .opinion
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
		this.program = program;

		// Read XBE header
		header = new XbeImageHeader(reader);

		try {
			program.setImageBase(api.toAddr(header.baseAddr), true);
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}

		// Unscramble entry point
		long ENTRY_DEBUG  = 0x94859D4BL;
		long ENTRY_RETAIL = 0xA8FC57ABL;
		long entry = header.entryAddr ^ ENTRY_DEBUG;
		if (entry < 0x4000000) {
			isDebug = true;
		} else {
			entry = header.entryAddr ^ ENTRY_RETAIL;
			isDebug = false;
		}

		// Add entry point
		Address entryAddr = api.toAddr(entry);
		try {
			program.getSymbolTable().createLabel(entryAddr, "entry", SourceType.IMPORTED);
			program.getSymbolTable().addExternalEntryPoint(entryAddr);
			createOneByteFunction("entry", entryAddr);
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}

		// Read headers into memory
		reader.setPointerIndex(0);
		createSection(api, "headers", reader,
				header.baseAddr, header.imageHeaderSize,
				0, header.imageHeaderSize, false);

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
					secHdr.rawAddr, secHdr.rawSize, (secHdr.flags & secHdr.FLAG_EXECUTABLE) != 0);
		}
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
			MemoryBlock sec = api.createMemoryBlock(name, api.toAddr(vaddr), data, false);
			sec.setExecute(exec);
			sec.setRead(true);
			sec.setWrite(true);
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	/* MachoProgramBuilder.java */
	/**
	 * create a one-byte function, so that when the code is analyzed,
	 * it will be disassembled, and the function created with the correct body.
	 *
	 * @param name the name of the function
	 * @param address location to create the function
	 */
	void createOneByteFunction(String name, Address address) {
		FunctionManager functionMgr = program.getFunctionManager();
		if (functionMgr.getFunctionAt(address) != null) {
			return;
		}
		try {
			functionMgr.createFunction(name, address, new AddressSet(address), SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			// ignore
		}
		catch (OverlappingFunctionException e) {
			// ignore
		}
	}


	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		// list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
