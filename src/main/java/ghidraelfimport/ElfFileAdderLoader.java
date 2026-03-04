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
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A custom ELF loader that extends Ghidra's built-in ELF loader with namespace support.
 * This loader registers itself with Ghidra's loader discovery (via ClassSearcher, because the
 * class name ends in "Loader") and appears in the <em>Add To Program</em> dialog for ELF files.
 *
 * <p>When the user clicks <em>Options…</em> in the Add To Program dialog two extra options are
 * exposed:
 * <ul>
 *   <li><b>Existing Binary Namespace</b> – namespace applied to every global symbol that is
 *       already present in the target program before the ELF is loaded.</li>
 *   <li><b>New Binary Namespace</b> – namespace applied to every global symbol that arrives
 *       from the ELF load, and prefix added to every newly created memory block.</li>
 * </ul>
 * Both options default to the respective file name (without extension) and are ignored when
 * they are left blank.
 */
public class ElfFileAdderLoader extends ElfLoader {

	/** Name shown in Ghidra's "Format" dropdown of the Add To Program dialog. */
	public static final String LOADER_NAME = "ELF File Adder";

	/** Option name for the namespace to apply to the existing program's global symbols. */
	static final String EXISTING_NS_OPTION = "Existing Binary Namespace";

	/** Option name for the namespace to apply to the symbols loaded from the ELF. */
	static final String NEW_NS_OPTION = "New Binary Namespace";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public boolean supportsLoadIntoProgram(Program program) {
		return true;
	}

	/**
	 * Re-maps specs from the standard {@link ElfLoader} so that they reference this loader
	 * rather than the parent.  This is necessary because {@link ElfLoader#findSupportedLoadSpecs}
	 * internally calls {@link #getName()} (via virtual dispatch) to query the opinion service,
	 * and "ELF File Adder" has no registered opinion file.
	 */
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		Collection<LoadSpec> elfSpecs = new ElfLoader().findSupportedLoadSpecs(provider);
		List<LoadSpec> mySpecs = new ArrayList<>();
		for (LoadSpec spec : elfSpecs) {
			mySpecs.add(new LoadSpec(this, spec.getDesiredImageBase(),
				spec.getLanguageCompilerSpec(), spec.isPreferred()));
		}
		return mySpecs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options = new ArrayList<>(
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
				mirrorFsLayout));
		if (loadIntoProgram && domainObject instanceof Program) {
			Program program = (Program) domainObject;
			options.add(new Option(EXISTING_NS_OPTION,
				ElfImportWithNamespaceDialog.stripExtension(program.getName()), String.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-existingNamespace"));
			options.add(new Option(NEW_NS_OPTION,
				ElfImportWithNamespaceDialog.stripExtension(provider.getName()), String.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-newNamespace"));
		}
		return options;
	}

	/**
	 * Extends the standard ELF loading with namespace separation:
	 * <ol>
	 *   <li>Moves existing global symbols into the <em>existing namespace</em>.</li>
	 *   <li>Loads the ELF content (delegates to the parent).</li>
	 *   <li>Renames every newly added memory block to {@code <newNs>:<originalName>}.</li>
	 *   <li>Moves the newly imported global symbols into the <em>new namespace</em>.</li>
	 * </ol>
	 * All modifications occur within the single transaction started by
	 * {@link ghidra.app.util.opinion.AbstractProgramLoader#loadInto}.
	 */
	@Override
	protected void loadProgramInto(Program program, Loader.ImporterSettings settings)
			throws CancelledException, LoadException, IOException {

		String existingNs = OptionUtils.getOption(EXISTING_NS_OPTION, settings.options(), "");
		String newNs = OptionUtils.getOption(NEW_NS_OPTION, settings.options(), "");

		// Phase 1: namespace existing symbols
		if (!existingNs.isBlank()) {
			applyNamespace(program, existingNs, settings.log(), settings.monitor());
		}

		// Snapshot block names before the ELF load
		Set<String> preExistingBlocks = getBlockNames(program);

		// Phase 2: load the ELF content
		super.loadProgramInto(program, settings);

		// Phase 3: rename newly added memory blocks
		if (!newNs.isBlank()) {
			renameNewBlocks(program, preExistingBlocks, newNs, settings.log(), settings.monitor());
		}

		// Phase 4: namespace symbols that arrived from the ELF
		if (!newNs.isBlank()) {
			applyNamespace(program, newNs, settings.log(), settings.monitor());
		}
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	private static Set<String> getBlockNames(Program program) {
		Set<String> names = new HashSet<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			names.add(block.getName());
		}
		return names;
	}

	private static void renameNewBlocks(Program program, Set<String> preExistingNames, String ns,
			MessageLog log, TaskMonitor monitor)
			throws CancelledException {

		List<MemoryBlock> newBlocks = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!preExistingNames.contains(block.getName())) {
				newBlocks.add(block);
			}
		}

		for (MemoryBlock block : newBlocks) {
			monitor.checkCancelled();
			try {
				block.setName(ns + ":" + block.getName());
				block.setComment(ElfNamespaceImportTask.ELF_MERGER_COMMENT);
			}
			catch (Exception e) {
				log.appendMsg(
					"Could not rename block '" + block.getName() + "': " + e.getMessage());
			}
		}
	}

	private static void applyNamespace(Program program, String namespaceName,
			MessageLog log, TaskMonitor monitor)
			throws CancelledException {

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace global = program.getGlobalNamespace();

		Namespace ns;
		try {
			ns = symbolTable.getNamespace(namespaceName, global);
			if (ns == null) {
				ns = symbolTable.createNameSpace(global, namespaceName, SourceType.USER_DEFINED);
			}
		}
		catch (DuplicateNameException | InvalidInputException e) {
			log.appendMsg(
				"Failed to create namespace '" + namespaceName + "': " + e.getMessage());
			return;
		}

		SymbolIterator it = symbolTable.getAllSymbols(false);
		while (it.hasNext()) {
			monitor.checkCancelled();
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
			catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				// Skip symbols that cannot be moved
			}
		}
	}
}
