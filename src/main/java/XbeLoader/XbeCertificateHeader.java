package xbeloader;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class XbeCertificateHeader implements StructConverter {
	public long size;
	public long timestamp;
	public long titleId;
	public String titleName;
	public long[] altTitleIds;
	public long allowedMedia;
	public long region;
	public long ratings;
	public long discNum;
	public long version;
	public byte[] lanKey;
	public byte[] signatureKey;
	public byte[][] altSignatureKeys;

	public XbeCertificateHeader(BinaryReader reader) throws IOException {
		size = reader.readNextUnsignedInt();
		timestamp = reader.readNextUnsignedInt();
		titleId = reader.readNextUnsignedInt();
		titleName = reader.readNextUnicodeString(40);
		altTitleIds = new long[16];
		for (int i = 0; i < 16; i++)
			altTitleIds[i] = reader.readNextUnsignedInt();
		allowedMedia = reader.readNextUnsignedInt();
		region = reader.readNextUnsignedInt();
		ratings = reader.readNextUnsignedInt();
		discNum = reader.readNextUnsignedInt();
		version = reader.readNextUnsignedInt();
		lanKey = reader.readNextByteArray(16);
		signatureKey = reader.readNextByteArray(16);
		altSignatureKeys = new byte[16][];
		for (int i = 0; i < 16; i++)
			altSignatureKeys[i] = reader.readNextByteArray(16);
	}

	/**
	 * Returns the name to use when converting into a structure data type.
	 * @return the name to use when converting into a structure data type
	 */
	public String getName() {
		return "XBE_CERTIFICATE_HEADER";
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(getName(), 0);

		struct.add(DWORD, 4, "SizeOfHeader", null);
		struct.add(DWORD, 4, "TimeDateStamp", null);
		struct.add(DWORD, 4, "TitleID", null);
		struct.add(UTF16, 80, "TitleName", null);
		struct.add(new ArrayDataType(DWORD, 16, 4), "AlternateTitleIDs", null);
		struct.add(DWORD, 4, "AllowedMedia", null);
		struct.add(DWORD, 4, "GameRegion", null);
		struct.add(DWORD, 4, "GameRatings", null);
		struct.add(DWORD, 4, "DiscNumber", null);
		struct.add(DWORD, 4, "Version", null);
		struct.add(new ArrayDataType(BYTE, 16, 1), "LANKey", null);
		struct.add(new ArrayDataType(BYTE, 16, 1), "SignatureKey", null);
		struct.add(new ArrayDataType(new ArrayDataType(BYTE, 16, 1), 16, 1), "AlternateSignatureKeys", null);

		if (size >= 0x1D4)
			struct.add(DWORD, 4, "OriginalCertificateSize", null);
		if (size >= 0x1D8)
			struct.add(DWORD, 4, "OnlineServiceID", null);
		if (size >= 0x1DC)
			struct.add(DWORD, 4, "SecurityFlags", null);
		if (size >= 0x1EC)
			struct.add(new ArrayDataType(BYTE, 16, 1), "CodeEncryptionKey", null);

		struct.setCategoryPath(new CategoryPath("/XBE"));

		return struct;
	}
}
