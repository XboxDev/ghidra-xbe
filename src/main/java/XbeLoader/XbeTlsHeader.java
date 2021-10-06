package xbeloader;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class XbeTlsHeader implements StructConverter {
	/**
	 * Returns the name to use when converting into a structure data type.
	 * @return the name to use when converting into a structure data type
	 */
	public String getName() {
		return "IMAGE_TLS_DIRECTORY_32";
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(getName(), 0);

		struct.add(DWORD, 4, "StartAddressOfRawData", null);
		struct.add(DWORD, 4, "EndAddressOfRawData", null);
		struct.add(DWORD, 4, "AddressOfIndex", null);
		struct.add(DWORD, 4, "AddressOfCallBacks", null);
		struct.add(DWORD, 4, "SizeOfZeroFill", null);
		struct.add(DWORD, 4, "Characteristics", null);

		struct.setCategoryPath(new CategoryPath("/XBE"));

		return struct;
	}
}
