package xbeloader;

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
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class XbeSectionHeader implements StructConverter {
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

	public final static long FLAG_WRITABLE            = 0x00000001L;
	public final static long FLAG_PRELOAD             = 0x00000002L;
	public final static long FLAG_EXECUTABLE          = 0x00000004L;
	public final static long FLAG_INSERTED_FILE       = 0x00000008L;
	public final static long FLAG_HEAD_PAGE_READ_ONLY = 0x00000010L;
	public final static long FLAG_TAIL_PAGE_READ_ONLY = 0x00000020L;

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

	/**
	 * Returns the name to use when converting into a structure data type.
	 * @return the name to use when converting into a structure data type
	 */
	public String getName() {
		return "XBE_SECTION_HEADER";
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(getName(), 0);

		struct.add(DWORD, 4, "Flags", null);
		struct.add(DWORD, 4, "VirtualAddress", null);
		struct.add(DWORD, 4, "VirtualSize", null);
		struct.add(DWORD, 4, "FileAddress", null);
		struct.add(DWORD, 4, "FileSize", null);
		struct.add(POINTER, 4, "SectionName", null);
		struct.add(DWORD, 4, "SectionReferenceCount", null);
		struct.add(POINTER, 4, "HeadReferenceCount", null);
		struct.add(POINTER, 4, "TailReferenceCount", null);
		struct.add(new ArrayDataType(BYTE, 20, 1), "CheckSum", null);

		struct.setCategoryPath(new CategoryPath("/XBE"));

		return struct;
	}
}
