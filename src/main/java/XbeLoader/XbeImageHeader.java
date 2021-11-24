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

public class XbeImageHeader implements StructConverter {
	public long   magic;
	public byte[] signature;
	public long   baseAddr;
	public long   headersSize;
	public long   imageSize;
	public long   imageHeaderSize;
	public long   timestamp;
	public long   certificateAddr;
	public long   sectionCount;
	public long   sectionHeadersAddr;
	public long   initFlags;
	public long   entryAddr;
	public long   tlsAddr;
	public long   peStackCommit;
	public long   peHeapReserve;
	public long   peHeapCommit;
	public long   peBaseAddr;
	public long   peImageSize;
	public long   peChecksum;
	public long   peTimestamp;
	public long   debugPathnameAddr;
	public long   debugFilenameAddr;
	public long   debugUnicodeFilenameAddr;
	public long   kernThunkAddr;
	public long   importDirAddr;
	public long   libVersionsCount;
	public long   libVersionsAddr;
	public long   kernLibVersionAddr;
	public long   xapiLibVersionAddr;
	public long   logoAddr;
	public long   logoSize;
	public long   libFeaturesAddr;
	public long   libFeaturesCount;
	public long   debugInfo;
	// Not part of structure, extended feature check
	public XbeType type;

	XbeCertificateHeader certificateHeader;

	public enum XbeType {
		RETAIL(0),
		DEBUG(1),
		CHIHIRO(2);

		private int value;

		private XbeType(int setValue) {
			value = setValue;
		}

		public int getValue() {
			return value;
		}
	}

	private long[] xorEntryPoint = {
		0xA8FC57ABL, // Retail
		0x94859D4BL, // Debug
		0x40B5C16EL  // Chihiro
	};

	private long[] xorKernelThunk = {
		0x5B6D40B6L, // Retail
		0xEFB1F152L, // Debug
		0x2290059DL  // Chihiro
	};

	// ported from Dxbx's XbeExplorer
	private XbeType GetXbeType() {

		// Detect if the XBE is for Chihiro :
		// This is based on https://github.com/radare/radare2/blob/7ffe2599a192bf5b9333560345f80dd97f096277/libr/bin/p/bin_xbe.c#L29
		if ((entryAddr & 0xF0000000) == 0x40000000) {
			return XbeType.CHIHIRO;
		}

		// Check for Debug XBE, using high bit of the kernel thunk address :
		// (DO NOT test like https://github.com/radare/radare2/blob/7ffe2599a192bf5b9333560345f80dd97f096277/libr/bin/p/bin_xbe.c#L33 !)
		if ((kernThunkAddr & 0x80000000) > 0) {
			return XbeType.DEBUG;
		}

		// Otherwise, the XBE is a Retail build :
		return XbeType.RETAIL;
	}

	// Unscramble entry point
	public long GetEntryPoint() {
		return entryAddr ^ xorEntryPoint[type.getValue()];
	}

	// Unscramble kernel thunk
	public long GetKernelThunk() {
		return kernThunkAddr ^ xorKernelThunk[type.getValue()];
	}

	public XbeImageHeader(BinaryReader reader) throws IOException {
		reader.setPointerIndex(0);
		magic                    = reader.readNextUnsignedInt();
		signature                = reader.readNextByteArray(256);
		baseAddr                 = reader.readNextUnsignedInt();
		headersSize              = reader.readNextUnsignedInt();
		imageSize                = reader.readNextUnsignedInt();
		imageHeaderSize          = reader.readNextUnsignedInt();
		timestamp                = reader.readNextUnsignedInt();
		certificateAddr          = reader.readNextUnsignedInt();
		sectionCount             = reader.readNextUnsignedInt();
		sectionHeadersAddr       = reader.readNextUnsignedInt();
		initFlags                = reader.readNextUnsignedInt();
		entryAddr                = reader.readNextUnsignedInt();
		tlsAddr                  = reader.readNextUnsignedInt();
		peStackCommit            = reader.readNextUnsignedInt();
		peHeapReserve            = reader.readNextUnsignedInt();
		peHeapCommit             = reader.readNextUnsignedInt();
		peBaseAddr               = reader.readNextUnsignedInt();
		peImageSize              = reader.readNextUnsignedInt();
		peChecksum               = reader.readNextUnsignedInt();
		peTimestamp              = reader.readNextUnsignedInt();
		debugPathnameAddr        = reader.readNextUnsignedInt();
		debugFilenameAddr        = reader.readNextUnsignedInt();
		debugUnicodeFilenameAddr = reader.readNextUnsignedInt();
		kernThunkAddr            = reader.readNextUnsignedInt();
		importDirAddr            = reader.readNextUnsignedInt();
		libVersionsCount         = reader.readNextUnsignedInt();
		libVersionsAddr          = reader.readNextUnsignedInt();
		kernLibVersionAddr       = reader.readNextUnsignedInt();
		xapiLibVersionAddr       = reader.readNextUnsignedInt();
		logoAddr                 = reader.readNextUnsignedInt();
		logoSize                 = reader.readNextUnsignedInt();
		if (imageHeaderSize >= 0x180) {
			libFeaturesAddr      = reader.readNextUnsignedInt();
			libFeaturesCount     = reader.readNextUnsignedInt();
		}
		if (imageHeaderSize >= 0x184) {
			debugInfo            = reader.readNextUnsignedInt();
		}

		type                     = GetXbeType();

		reader.setPointerIndex(certificateAddr);
		certificateHeader = new XbeCertificateHeader(reader);
	}

	/**
	 * Returns the name to use when converting into a structure data type.
	 * @return the name to use when converting into a structure data type
	 */
	public String getName() {
		return "XBE_FILE_HEADER";
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(getName(), 0);

		struct.add(new ArrayDataType(ASCII, 4, 1), "magic", null);
		struct.add(new ArrayDataType(BYTE, 256, 1), "Signature", null);
		struct.add(DWORD, 4, "ImageBase", null);
		struct.add(DWORD, 4, "SizeOfHeaders", null);
		struct.add(DWORD, 4, "SizeOfImage", null);
		struct.add(DWORD, 4, "SizeOfImageHeader", null);
		struct.add(DWORD, 4, "TimeDateStamp", null);
		struct.add(POINTER, 4, "CertificateHeader", null);
		struct.add(DWORD, 4, "NumberOfSections", null);
		struct.add(POINTER, 4, "PointerToSectionTable", null);
		struct.add(DWORD, 4, "InitFlags", null);
		struct.add(DWORD, 4, "AddressOfEntryPoint", null);
		struct.add(POINTER, 4, "PointerToTlsDirectory", null);
		struct.add(DWORD, 4, "SizeOfStack", null);
		struct.add(DWORD, 4, "SizeOfHeapReserve", null);
		struct.add(DWORD, 4, "SizeOfHeapCommit", null);
		struct.add(DWORD, 4, "PeImageBase", null);
		struct.add(DWORD, 4, "PeSizeOfImage", null);
		struct.add(DWORD, 4, "PeImageCheckSum", null);
		struct.add(DWORD, 4, "PeTimeDateStamp", null);
		struct.add(DWORD, 4, "PeDebugPath", null);
		struct.add(DWORD, 4, "PeDebugFilename", null);
		struct.add(DWORD, 4, "PeDebugFilenameUnicode", null);
		struct.add(DWORD, 4, "PointerToKernelThunkTable", null);
		struct.add(DWORD, 4, "PointerToDebugImportTable", null);
		struct.add(DWORD, 4, "NumberOfLibraries", null);
		struct.add(POINTER, 4, "PointerToLibraries", null);
		struct.add(POINTER, 4, "PointerToKernelLibrary", null);
		struct.add(POINTER, 4, "PointerToXapiLibrary", null);
		struct.add(POINTER, 4, "PointerToLogoBitmap", null);
		struct.add(DWORD, 4, "SizeOfLogoBitmap", null);
		if (imageHeaderSize >= 0x180) {
			struct.add(POINTER, 4, "PointerToFeatureLibraries", null);
			struct.add(DWORD, 4, "NumberOfFeatureLibraries", null);
		}
		if (imageHeaderSize >= 0x184)
			struct.add(DWORD, 4, "DebugInfo", null);

		struct.setCategoryPath(new CategoryPath("/XBE"));

		return struct;
	}
}
