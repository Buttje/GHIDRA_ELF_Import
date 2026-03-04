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
package ghidraelfimport;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * ELF loader that extends the built-in {@link ElfLoader} with optional namespace support.
 *
 * <p>When used via "Add To Program", two additional options allow the user to specify namespace
 * names for the existing program's symbols and for the newly loaded ELF symbols, preventing
 * symbol name clashes between the two binaries.
 *
 * <p>If the namespace options are left blank the loader behaves identically to the standard
 * {@link ElfLoader}.
 */
public class ElfFileAdderLoader extends ElfLoader {

	/** Display name shown in the "Add To Program" / "Import" format drop-down. */
	public static final String LOADER_NAME = "ELF File Adder";

	private static final String OPT_EXISTING_NS = "Existing Binary Namespace";
	private static final String OPT_NEW_NS = "New Binary Namespace";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> options = new ArrayList<>(
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram));
		if (isLoadIntoProgram) {
			options.add(new Option(OPT_EXISTING_NS, ""));
			options.add(new Option(OPT_NEW_NS, ""));
		}
		return options;
	}

	@Override
	public void loadInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Program program, TaskMonitor monitor)
			throws CancelledException, IOException {

		String existingNs = getOptionString(options, OPT_EXISTING_NS);
		String newNs = getOptionString(options, OPT_NEW_NS);

		// Snapshot block names so we can identify newly added blocks after loading
		Set<String> existingBlockNames = new HashSet<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			existingBlockNames.add(block.getName());
		}

		// Namespace existing symbols before loading new ones
		if (!existingNs.isBlank()) {
			applyNamespaceToGlobalSymbols(program, existingNs, log);
		}

		// Delegate to the built-in ELF loader
		super.loadInto(provider, loadSpec, options, log, program, monitor);

		// Rename new memory blocks and namespace newly imported symbols
		if (!newNs.isBlank()) {
			renameNewMemoryBlocks(program, existingBlockNames, newNs, log);
			applyNamespaceToGlobalSymbols(program, newNs, log);
		}
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	private static String getOptionString(List<Option> options, String name) {
		for (Option opt : options) {
			if (name.equals(opt.getName())) {
				Object val = opt.getValue();
				return val != null ? val.toString().trim() : "";
			}
		}
		return "";
	}

	private static void applyNamespaceToGlobalSymbols(Program program, String namespaceName,
			MessageLog log) {
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace global = program.getGlobalNamespace();
		try {
			Namespace ns = symbolTable.getNamespace(namespaceName, global);
			if (ns == null) {
				ns = symbolTable.createNameSpace(global, namespaceName, SourceType.USER_DEFINED);
			}
			SymbolIterator it = symbolTable.getAllSymbols(false);
			while (it.hasNext()) {
				Symbol symbol = it.next();
				if (!symbol.getParentNamespace().isGlobal()) {
					continue;
				}
				if (symbol.getSymbolType() == SymbolType.NAMESPACE ||
					symbol.getSymbolType() == SymbolType.CLASS) {
					continue;
				}
				try {
					symbol.setNamespace(ns);
				}
				catch (DuplicateNameException | InvalidInputException
						| CircularDependencyException e) {
					log.appendMsg(LOADER_NAME,
						"Skipping symbol '" + symbol.getName() + "': " + e.getMessage());
				}
			}
		}
		catch (DuplicateNameException | InvalidInputException e) {
			log.appendMsg(LOADER_NAME,
				"Failed to create namespace '" + namespaceName + "': " + e.getMessage());
		}
	}

	private static void renameNewMemoryBlocks(Program program, Set<String> preExistingNames,
			String newNs, MessageLog log) {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!preExistingNames.contains(block.getName())) {
				try {
					block.setName(newNs + ":" + block.getName());
					block.setComment(ElfNamespaceImportTask.ELF_MERGER_COMMENT);
				}
				catch (Exception e) {
					log.appendMsg(LOADER_NAME,
						"Could not rename block '" + block.getName() + "': " + e.getMessage());
				}
			}
		}
	}
}
