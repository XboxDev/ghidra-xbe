package skeleton;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class XbeSectionHeader {
	public long flags;
	public long virtualAddr;
	public long virtualSize;
	public long rawAddr;
	public long rawSize;
	public long sectionNameAddr;
	public long sectionNameRefCount;
	public long headSharedPageRefCountAddr;
	public long tailSharedPageRefCountAddr;
	public byte[] digest;

	public XbeSectionHeader(BinaryReader reader) throws IOException {
		flags = reader.readNextUnsignedInt();
		virtualAddr = reader.readNextUnsignedInt();
		virtualSize = reader.readNextUnsignedInt();
		rawAddr = reader.readNextUnsignedInt();
		rawSize = reader.readNextUnsignedInt();
		sectionNameAddr = reader.readNextUnsignedInt();
		sectionNameRefCount = reader.readNextUnsignedInt();
		headSharedPageRefCountAddr = reader.readNextUnsignedInt();
		tailSharedPageRefCountAddr = reader.readNextUnsignedInt();
		digest = reader.readNextByteArray(20);
	}
}
