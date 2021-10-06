package xbeloader;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class XbeLibraryHeader implements StructConverter {
	/**
	 * Returns the name to use when converting into a structure data type.
	 * @return the name to use when converting into a structure data type
	 */
	public String getName() {
		return "XBE_LIBRARY_HEADER";
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(getName(), 0);

		struct.add(new ArrayDataType(ASCII, 8, 1), "LibraryName", null);
		struct.add(WORD, 2, "MajorVersion", null);
		struct.add(WORD, 2, "MinorVersion", null);
		struct.add(WORD, 2, "BuildVersion", null);
		struct.add(WORD, 2, "LibraryFlags", null);

		struct.setCategoryPath(new CategoryPath("/XBE"));

		return struct;
	}
}
