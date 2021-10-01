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
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.data.PointerDataType;


/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class XbeLoader extends AbstractLibrarySupportLoader {
	public static String XBE_NAME = "Xbox Executable Format (XBE)";
	public XbeImageHeader header;
	List<XbeSectionHeader> sectionHeaders;
	boolean isDebug;
	private Program program;
	private Address kernelThunkTableAddr;
	private static String[] kernelExports = {
		"",                                     // 0
		"AvGetSavedDataAddress",                // 1
		"AvSendTVEncoderOption",                // 2
		"AvSetDisplayMode",                     // 3
		"AvSetSavedDataAddress",                // 4
		"DbgBreakPoint",                        // 5
		"DbgBreakPointWithStatus",              // 6
		"DbgLoadImageSymbols",                  // 7
		"DbgPrint",                             // 8
		"HalReadSMCTrayState",                  // 9
		"DbgPrompt",                            // 10
		"DbgUnLoadImageSymbols",                // 11
		"ExAcquireReadWriteLockExclusive",      // 12
		"ExAcquireReadWriteLockShared",         // 13
		"ExAllocatePool",                       // 14
		"ExAllocatePoolWithTag",                // 15
		"ExEventObjectType",                    // 16
		"ExFreePool",                           // 17
		"ExInitializeReadWriteLock",            // 18
		"ExInterlockedAddLargeInteger",         // 19
		"ExInterlockedAddLargeStatistic",       // 20
		"ExInterlockedCompareExchange64",       // 21
		"ExMutantObjectType",                   // 22
		"ExQueryPoolBlockSize",                 // 23
		"ExQueryNonVolatileSetting",            // 24
		"ExReadWriteRefurbInfo",                // 25
		"ExRaiseException",                     // 26
		"ExRaiseStatus",                        // 27
		"ExReleaseReadWriteLock",               // 28
		"ExSaveNonVolatileSetting",             // 29
		"ExSemaphoreObjectType",                // 30
		"ExTimerObjectType",                    // 31
		"ExfInterlockedInsertHeadList",         // 32
		"ExfInterlockedInsertTailList",         // 33
		"ExfInterlockedRemoveHeadList",         // 34
		"FscGetCacheSize",                      // 35
		"FscInvalidateIdleBlocks",              // 36
		"FscSetCacheSize",                      // 37
		"HalClearSoftwareInterrupt",            // 38
		"HalDisableSystemInterrupt",            // 39
		"HalDiskCachePartitionCount",           // 40
		"HalDiskModelNumber",                   // 41
		"HalDiskSerialNumber",                  // 42
		"HalEnableSystemInterrupt",             // 43
		"HalGetInterruptVector",                // 44
		"HalReadSMBusValue",                    // 45
		"HalReadWritePCISpace",                 // 46
		"HalRegisterShutdownNotification",      // 47
		"HalRequestSoftwareInterrupt",          // 48
		"HalReturnToFirmware",                  // 49
		"HalWriteSMBusValue",                   // 50
		"InterlockedCompareExchange",           // 51
		"InterlockedDecrement",                 // 52
		"InterlockedIncrement",                 // 53
		"InterlockedExchange",                  // 54
		"InterlockedExchangeAdd",               // 55
		"InterlockedFlushSList",                // 56
		"InterlockedPopEntrySList",             // 57
		"InterlockedPushEntrySList",            // 58
		"IoAllocateIrp",                        // 59
		"IoBuildAsynchronousFsdRequest",        // 60
		"IoBuildDeviceIoControlRequest",        // 61
		"IoBuildSynchronousFsdRequest",         // 62
		"IoCheckShareAccess",                   // 63
		"IoCompletionObjectType",               // 64
		"IoCreateDevice",                       // 65
		"IoCreateFile",                         // 66
		"IoCreateSymbolicLink",                 // 67
		"IoDeleteDevice",                       // 68
		"IoDeleteSymbolicLink",                 // 69
		"IoDeviceObjectType",                   // 70
		"IoFileObjectType",                     // 71
		"IoFreeIrp",                            // 72
		"IoInitializeIrp",                      // 73
		"IoInvalidDeviceRequest",               // 74
		"IoQueryFileInformation",               // 75
		"IoQueryVolumeInformation",             // 76
		"IoQueueThreadIrp",                     // 77
		"IoRemoveShareAccess",                  // 78
		"IoSetIoCompletion",                    // 79
		"IoSetShareAccess",                     // 80
		"IoStartNextPacket",                    // 81
		"IoStartNextPacketByKey",               // 82
		"IoStartPacket",                        // 83
		"IoSynchronousDeviceIoControlRequest",  // 84
		"IoSynchronousFsdRequest",              // 85
		"IofCallDriver",                        // 86
		"IofCompleteRequest",                   // 87
		"KdDebuggerEnabled",                    // 88
		"KdDebuggerNotPresent",                 // 89
		"IoDismountVolume",                     // 90
		"IoDismountVolumeByName",               // 91
		"KeAlertResumeThread",                  // 92
		"KeAlertThread",                        // 93
		"KeBoostPriorityThread",                // 94
		"KeBugCheck",                           // 95
		"KeBugCheckEx",                         // 96
		"KeCancelTimer",                        // 97
		"KeConnectInterrupt",                   // 98
		"KeDelayExecutionThread",               // 99
		"KeDisconnectInterrupt",                // 100
		"KeEnterCriticalRegion",                // 101
		"MmGlobalData",                         // 102
		"KeGetCurrentIrql",                     // 103
		"KeGetCurrentThread",                   // 104
		"KeInitializeApc",                      // 105
		"KeInitializeDeviceQueue",              // 106
		"KeInitializeDpc",                      // 107
		"KeInitializeEvent",                    // 108
		"KeInitializeInterrupt",                // 109
		"KeInitializeMutant",                   // 110
		"KeInitializeQueue",                    // 111
		"KeInitializeSemaphore",                // 112
		"KeInitializeTimerEx",                  // 113
		"KeInsertByKeyDeviceQueue",             // 114
		"KeInsertDeviceQueue",                  // 115
		"KeInsertHeadQueue",                    // 116
		"KeInsertQueue",                        // 117
		"KeInsertQueueApc",                     // 118
		"KeInsertQueueDpc",                     // 119
		"KeInterruptTime",                      // 120
		"KeIsExecutingDpc",                     // 121
		"KeLeaveCriticalRegion",                // 122
		"KePulseEvent",                         // 123
		"KeQueryBasePriorityThread",            // 124
		"KeQueryInterruptTime",                 // 125
		"KeQueryPerformanceCounter",            // 126
		"KeQueryPerformanceFrequency",          // 127
		"KeQuerySystemTime",                    // 128
		"KeRaiseIrqlToDpcLevel",                // 129
		"KeRaiseIrqlToSynchLevel",              // 130
		"KeReleaseMutant",                      // 131
		"KeReleaseSemaphore",                   // 132
		"KeRemoveByKeyDeviceQueue",             // 133
		"KeRemoveDeviceQueue",                  // 134
		"KeRemoveEntryDeviceQueue",             // 135
		"KeRemoveQueue",                        // 136
		"KeRemoveQueueDpc",                     // 137
		"KeResetEvent",                         // 138
		"KeRestoreFloatingPointState",          // 139
		"KeResumeThread",                       // 140
		"KeRundownQueue",                       // 141
		"KeSaveFloatingPointState",             // 142
		"KeSetBasePriorityThread",              // 143
		"KeSetDisableBoostThread",              // 144
		"KeSetEvent",                           // 145
		"KeSetEventBoostPriority",              // 146
		"KeSetPriorityProcess",                 // 147
		"KeSetPriorityThread",                  // 148
		"KeSetTimer",                           // 149
		"KeSetTimerEx",                         // 150
		"KeStallExecutionProcessor",            // 151
		"KeSuspendThread",                      // 152
		"KeSynchronizeExecution",               // 153
		"KeSystemTime",                         // 154
		"KeTestAlertThread",                    // 155
		"KeTickCount",                          // 156
		"KeTimeIncrement",                      // 157
		"KeWaitForMultipleObjects",             // 158
		"KeWaitForSingleObject",                // 159
		"KfRaiseIrql",                          // 160
		"KfLowerIrql",                          // 161
		"KiBugCheckData",                       // 162
		"KiUnlockDispatcherDatabase",           // 163
		"LaunchDataPage",                       // 164
		"MmAllocateContiguousMemory",           // 165
		"MmAllocateContiguousMemoryEx",         // 166
		"MmAllocateSystemMemory",               // 167
		"MmClaimGpuInstanceMemory",             // 168
		"MmCreateKernelStack",                  // 169
		"MmDeleteKernelStack",                  // 170
		"MmFreeContiguousMemory",               // 171
		"MmFreeSystemMemory",                   // 172
		"MmGetPhysicalAddress",                 // 173
		"MmIsAddressValid",                     // 174
		"MmLockUnlockBufferPages",              // 175
		"MmLockUnlockPhysicalPage",             // 176
		"MmMapIoSpace",                         // 177
		"MmPersistContiguousMemory",            // 178
		"MmQueryAddressProtect",                // 179
		"MmQueryAllocationSize",                // 180
		"MmQueryStatistics",                    // 181
		"MmSetAddressProtect",                  // 182
		"MmUnmapIoSpace",                       // 183
		"NtAllocateVirtualMemory",              // 184
		"NtCancelTimer",                        // 185
		"NtClearEvent",                         // 186
		"NtClose",                              // 187
		"NtCreateDirectoryObject",              // 188
		"NtCreateEvent",                        // 189
		"NtCreateFile",                         // 190
		"NtCreateIoCompletion",                 // 191
		"NtCreateMutant",                       // 192
		"NtCreateSemaphore",                    // 193
		"NtCreateTimer",                        // 194
		"NtDeleteFile",                         // 195
		"NtDeviceIoControlFile",                // 196
		"NtDuplicateObject",                    // 197
		"NtFlushBuffersFile",                   // 198
		"NtFreeVirtualMemory",                  // 199
		"NtFsControlFile",                      // 200
		"NtOpenDirectoryObject",                // 201
		"NtOpenFile",                           // 202
		"NtOpenSymbolicLinkObject",             // 203
		"NtProtectVirtualMemory",               // 204
		"NtPulseEvent",                         // 205
		"NtQueueApcThread",                     // 206
		"NtQueryDirectoryFile",                 // 207
		"NtQueryDirectoryObject",               // 208
		"NtQueryEvent",                         // 209
		"NtQueryFullAttributesFile",            // 210
		"NtQueryInformationFile",               // 211
		"NtQueryIoCompletion",                  // 212
		"NtQueryMutant",                        // 213
		"NtQuerySemaphore",                     // 214
		"NtQuerySymbolicLinkObject",            // 215
		"NtQueryTimer",                         // 216
		"NtQueryVirtualMemory",                 // 217
		"NtQueryVolumeInformationFile",         // 218
		"NtReadFile",                           // 219
		"NtReadFileScatter",                    // 220
		"NtReleaseMutant",                      // 221
		"NtReleaseSemaphore",                   // 222
		"NtRemoveIoCompletion",                 // 223
		"NtResumeThread",                       // 224
		"NtSetEvent",                           // 225
		"NtSetInformationFile",                 // 226
		"NtSetIoCompletion",                    // 227
		"NtSetSystemTime",                      // 228
		"NtSetTimerEx",                         // 229
		"NtSignalAndWaitForSingleObjectEx",     // 230
		"NtSuspendThread",                      // 231
		"NtUserIoApcDispatcher",                // 232
		"NtWaitForSingleObject",                // 233
		"NtWaitForSingleObjectEx",              // 234
		"NtWaitForMultipleObjectsEx",           // 235
		"NtWriteFile",                          // 236
		"NtWriteFileGather",                    // 237
		"NtYieldExecution",                     // 238
		"ObCreateObject",                       // 239
		"ObDirectoryObjectType",                // 240
		"ObInsertObject",                       // 241
		"ObMakeTemporaryObject",                // 242
		"ObOpenObjectByName",                   // 243
		"ObOpenObjectByPointer",                // 244
		"ObpObjectHandleTable",                 // 245
		"ObReferenceObjectByHandle",            // 246
		"ObReferenceObjectByName",              // 247
		"ObReferenceObjectByPointer",           // 248
		"ObSymbolicLinkObjectType",             // 249
		"ObfDereferenceObject",                 // 250
		"ObfReferenceObject",                   // 251
		"PhyGetLinkState",                      // 252
		"PhyInitialize",                        // 253
		"PsCreateSystemThread",                 // 254
		"PsCreateSystemThreadEx",               // 255
		"PsQueryStatistics",                    // 256
		"PsSetCreateThreadNotifyRoutine",       // 257
		"PsTerminateSystemThread",              // 258
		"PsThreadObjectType",                   // 259
		"RtlAnsiStringToUnicodeString",         // 260
		"RtlAppendStringToString",              // 261
		"RtlAppendUnicodeStringToString",       // 262
		"RtlAppendUnicodeToString",             // 263
		"RtlAssert",                            // 264
		"RtlCaptureContext",                    // 265
		"RtlCaptureStackBackTrace",             // 266
		"RtlCharToInteger",                     // 267
		"RtlCompareMemory",                     // 268
		"RtlCompareMemoryUlong",                // 269
		"RtlCompareString",                     // 270
		"RtlCompareUnicodeString",              // 271
		"RtlCopyString",                        // 272
		"RtlCopyUnicodeString",                 // 273
		"RtlCreateUnicodeString",               // 274
		"RtlDowncaseUnicodeChar",               // 275
		"RtlDowncaseUnicodeString",             // 276
		"RtlEnterCriticalSection",              // 277
		"RtlEnterCriticalSectionAndRegion",     // 278
		"RtlEqualString",                       // 279
		"RtlEqualUnicodeString",                // 280
		"RtlExtendedIntegerMultiply",           // 281
		"RtlExtendedLargeIntegerDivide",        // 282
		"RtlExtendedMagicDivide",               // 283
		"RtlFillMemory",                        // 284
		"RtlFillMemoryUlong",                   // 285
		"RtlFreeAnsiString",                    // 286
		"RtlFreeUnicodeString",                 // 287
		"RtlGetCallersAddress",                 // 288
		"RtlInitAnsiString",                    // 289
		"RtlInitUnicodeString",                 // 290
		"RtlInitializeCriticalSection",         // 291
		"RtlIntegerToChar",                     // 292
		"RtlIntegerToUnicodeString",            // 293
		"RtlLeaveCriticalSection",              // 294
		"RtlLeaveCriticalSectionAndRegion",     // 295
		"RtlLowerChar",                         // 296
		"RtlMapGenericMask",                    // 297
		"RtlMoveMemory",                        // 298
		"RtlMultiByteToUnicodeN",               // 299
		"RtlMultiByteToUnicodeSize",            // 300
		"RtlNtStatusToDosError",                // 301
		"RtlRaiseException",                    // 302
		"RtlRaiseStatus",                       // 303
		"RtlTimeFieldsToTime",                  // 304
		"RtlTimeToTimeFields",                  // 305
		"RtlTryEnterCriticalSection",           // 306
		"RtlUlongByteSwap",                     // 307
		"RtlUnicodeStringToAnsiString",         // 308
		"RtlUnicodeStringToInteger",            // 309
		"RtlUnicodeToMultiByteN",               // 310
		"RtlUnicodeToMultiByteSize",            // 311
		"RtlUnwind",                            // 312
		"RtlUpcaseUnicodeChar",                 // 313
		"RtlUpcaseUnicodeString",               // 314
		"RtlUpcaseUnicodeToMultiByteN",         // 315
		"RtlUpperChar",                         // 316
		"RtlUpperString",                       // 317
		"RtlUshortByteSwap",                    // 318
		"RtlWalkFrameChain",                    // 319
		"RtlZeroMemory",                        // 320
		"XboxEEPROMKey",                        // 321
		"XboxHardwareInfo",                     // 322
		"XboxHDKey",                            // 323
		"XboxKrnlVersion",                      // 324
		"XboxSignatureKey",                     // 325
		"XeImageFileName",                      // 326
		"XeLoadSection",                        // 327
		"XeUnloadSection",                      // 328
		"READ_PORT_BUFFER_UCHAR",               // 329
		"READ_PORT_BUFFER_USHORT",              // 330
		"READ_PORT_BUFFER_ULONG",               // 331
		"WRITE_PORT_BUFFER_UCHAR",              // 332
		"WRITE_PORT_BUFFER_USHORT",             // 333
		"WRITE_PORT_BUFFER_ULONG",              // 334
		"XcSHAInit",                            // 335
		"XcSHAUpdate",                          // 336
		"XcSHAFinal",                           // 337
		"XcRC4Key",                             // 338
		"XcRC4Crypt",                           // 339
		"XcHMAC",                               // 340
		"XcPKEncPublic",                        // 341
		"XcPKDecPrivate",                       // 342
		"XcPKGetKeyLen",                        // 343
		"XcVerifyPKCS1Signature",               // 344
		"XcModExp",                             // 345
		"XcDESKeyParity",                       // 346
		"XcKeyTable",                           // 347
		"XcBlockCrypt",                         // 348
		"XcBlockCryptCBC",                      // 349
		"XcCryptService",                       // 350
		"XcUpdateCrypto",                       // 351
		"RtlRip",                               // 352
		"XboxLANKey",                           // 353
		"XboxAlternateSignatureKeys",           // 354
		"XePublicKeyData",                      // 355
		"HalBootSMCVideoMode",                  // 356
		"IdexChannelObject",                    // 357
		"HalIsResetOrShutdownPending",          // 358
		"IoMarkIrpMustComplete",                // 359
		"HalInitiateShutdown",                  // 360
		"RtlSnprintf",                          // 361
		"RtlSprintf",                           // 362
		"RtlVsnprintf",                         // 363
		"RtlVsprintf",                          // 364
		"HalEnableSecureTrayEject",             // 365
		"HalWriteSMCScratchRegister",           // 366
		"",                                     // 367
		"",                                     // 368
		"",                                     // 369
		"",                                     // 370
		"",                                     // 371
		"",                                     // 372
		"",                                     // 373
		"MmDbgAllocateMemory",                  // 374
		"MmDbgFreeMemory",                      // 375
		"MmDbgQueryAvailablePages",             // 376
		"MmDbgReleaseAddress",                  // 377
		"MmDbgWriteCheck",                      // 378
		};


	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the .opinion
		// files.

		return XBE_NAME;
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
				0, header.imageHeaderSize, false, false);

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
					secHdr.rawAddr, secHdr.rawSize, (secHdr.flags & secHdr.FLAG_WRITABLE) != 0,
					(secHdr.flags & secHdr.FLAG_EXECUTABLE) != 0);
		}

		// Process imports
		long KTHUNK_DEBUG  = 0xEFB1F152L;
		long KTHUNK_RETAIL = 0x5B6D40B6L;
		if (isDebug) {
			kernelThunkTableAddr = api.toAddr(header.kernThunkAddr ^ KTHUNK_DEBUG);
		} else {
			kernelThunkTableAddr = api.toAddr(header.kernThunkAddr ^ KTHUNK_RETAIL);
		}
		processImports(program, monitor, log);
	}

	private void createSection(FlatProgramAPI api, String name, BinaryReader input, long vaddr, long vlen, long off, long len, boolean write, boolean exec)
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
			sec.setWrite(write);
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	/* Based on PELoader.java */
	private void processImports(Program program, TaskMonitor monitor, MessageLog log) {
		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("[" + program.getName() + "]: processing imports...");

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();

		Listing listing = program.getListing();
		ReferenceManager refManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();

		Address address = kernelThunkTableAddr;
		if (address.getOffset() == 0) {
			// No kernel thunk table, skip processing step
			return;
		}

		while (true) {
			if (monitor.isCancelled()) {
				return;
			}

			long importAddr;
			Data data;
			try {
				data = listing.getDataAt(address);
				importAddr = data.getUnsignedInt(0);
				if (importAddr == 0) {
					break;
				}
			} catch (MemoryAccessException e) {
				log.appendMsg("Failed to read memory: " + e.getMessage());
				break;
			}

			Address extAddr = space.getAddress(importAddr);
			if (extAddr != null) {
				// remove the existing mem reference that was created
				// when making a pointer
				data.removeOperandReference(0, extAddr);

				try {
					String importName = kernelExports[(int)(importAddr & ~0x80000000L)];
					symbolTable.createLabel(address, importName, SourceType.IMPORTED);
					listing.createData(address, new PointerDataType(), 4);
					refManager.addExternalReference(address, "xboxkrnl.exe",
						importName, extAddr, SourceType.IMPORTED, 0, RefType.DATA);
				}
				catch (DuplicateNameException e) {
					log.appendMsg("External location not created: " + e.getMessage());
				}
				catch (InvalidInputException e) {
					log.appendMsg("External location not created: " + e.getMessage());
				}
				catch (CodeUnitInsertionException e) {
					log.appendMsg("External location not created: " + e.getMessage());
				}
			}

			address = address.add(4);
		}
	}

	/* Based on MachoProgramBuilder.java */
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
