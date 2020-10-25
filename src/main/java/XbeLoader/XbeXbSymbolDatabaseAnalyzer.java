/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package skeleton;

import java.util.List;
import java.util.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.File;
import java.io.FileNotFoundException;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.framework.OperatingSystem;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;
import ghidra.program.model.address.*;
import ghidra.util.exception.*;


/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class XbeXbSymbolDatabaseAnalyzer extends AbstractAnalyzer {
	
	private static final String xbsdb_tool_exec = "XbSymbolDatabaseTool";
	private static final String xbsdb_tool_exec_wins = "XbSymbolDatabaseTool.exe";

	public XbeXbSymbolDatabaseAnalyzer() {
		super("Xbox Symbol Database Analyzer", "Scan XBE for known library functions", AnalyzerType.BYTE_ANALYZER);
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
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		String toolExec;
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			toolExec = xbsdb_tool_exec_wins;
		} else {
			toolExec = xbsdb_tool_exec;
		}
		
		String toolPath;
		try {
			toolPath = Application.getOSFile(toolExec).getAbsolutePath();
		} catch (FileNotFoundException e) {
			log.appendMsg("Failed to find " + toolExec);
			return false;
		}
		String xbePath = program.getExecutablePath();
		List<String> cmd = new ArrayList<>();
		cmd.add(toolPath);
		cmd.add(xbePath);

		try {
			Process exec = new ProcessBuilder().command(cmd).start();
			BufferedReader output = new BufferedReader(new InputStreamReader(exec.getInputStream()));

			String line;
			while ((line = output.readLine()) != null) {
				String[] params = line.split("=");
				Address address = api.toAddr(Long.decode(params[1].strip()));
				String fullName = params[0].strip();
				int libNameLength = fullName.indexOf("__");
				String lib = fullName.substring(0, libNameLength);
				String name = fullName.substring(libNameLength+2);
				program.getSymbolTable().createLabel(address, name, getNamespace(program, lib), SourceType.ANALYSIS);
			}
			
			exec.waitFor();
		} catch (InterruptedException e) {
			log.appendMsg("Failed to run " + toolExec);
			return false;
		} catch (IOException e) {
			log.appendMsg("Failed to run " + toolExec);
			return false;
		} catch (InvalidInputException e) {
			log.appendMsg("Failed to run " + toolExec);
			return false;
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
