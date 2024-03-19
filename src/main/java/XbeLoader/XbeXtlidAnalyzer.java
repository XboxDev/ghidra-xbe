package xbeloader;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class XbeXtlidAnalyzer extends AbstractAnalyzer {
	public XbeXtlidAnalyzer() {
		super("Xbox XTLID Symbol ID Analyzer", "Scan XBE for known library functions", AnalyzerType.BYTE_ANALYZER);
	}

    @Override
	public boolean getDefaultEnablement(Program program) {
		return program.getExecutableFormat().equals(XbeLoader.XBE_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getExecutableFormat().equals(XbeLoader.XBE_NAME);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// options.registerOption("Option name goes here", false, null,
		// 	"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		Listing listing = program.getListing();
		MemoryBlock section = program.getMemory().getBlock(".XTLID");

		if (section != null) {
			for (Address cur_addr = section.getStart(); cur_addr.compareTo(section.getEnd()) <= 0; cur_addr = cur_addr.add(8)) {
				try {
					Data data = listing.getDataAt(cur_addr);
					long id = data.getUnsignedInt(0);
					if (id == 0) {
						continue;
					}

					data = listing.getDataAt(cur_addr.add(4));
					Address address = space.getAddress(data.getUnsignedInt(0));

					String[] name_namespace = XbeXtlidDb.xtlids.get(id);
					if (name_namespace == null) {
						log.appendMsg("Unknown XTLID id 0x" + Long.toHexString(id) + " @ 0x" + address.toString());
						continue;
					}
					program.getSymbolTable().createLabel(address, name_namespace[1], getNamespace(program, name_namespace[0]), SourceType.ANALYSIS);
				} catch (MemoryAccessException e) {
					log.appendMsg("Failed to read memory: " + e.getMessage());
					break;
				} catch (InvalidInputException e) {
					log.appendMsg("Failed to set label: " + e.getMessage());
				}
			}
		}

		return true;
	}

	private Namespace getNamespace(Program program, String namespace) {
		Namespace space = program.getSymbolTable().getNamespace(namespace, null);
		if (space != null) {
			return space;
		}
		try {
			return program.getSymbolTable().createNameSpace(null, namespace, SourceType.IMPORTED);
		}
		catch (Exception e) {
			return null;
		}
	}
}
