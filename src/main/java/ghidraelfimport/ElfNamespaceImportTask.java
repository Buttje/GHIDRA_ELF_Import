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

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Background task that merges an ELF binary into the already-open program ("Add To Program"
 * semantics).  The memory segments and symbols from the ELF file become part of the existing
 * program's memory map rather than creating a separate program.
 *
 * <ol>
 *   <li><b>Namespace existing symbols</b> – creates the user-supplied namespace in the currently
 *       open program and moves all current global symbols into it.</li>
 *   <li><b>Load ELF into existing program</b> – uses Ghidra's {@link ElfLoader} to add the ELF
 *       file's memory segments and symbols directly into the open program.  Overlays are used
 *       automatically when address ranges conflict.</li>
 *   <li><b>Rename new memory blocks</b> – every memory block that was added by the ELF load is
 *       renamed to {@code <newNamespace>:<originalName>} so segments from both binaries are
 *       clearly distinguished.  The block comment is set to {@value #ELF_MERGER_COMMENT}.</li>
 *   <li><b>Namespace imported symbols</b> – all global symbols that are still in the global
 *       namespace after step 1 (i.e., those that came from the ELF) are moved into the
 *       new-binary namespace.</li>
 *   <li><b>Re-run analysis</b> (optional) – if the user requested it, the auto-analysis
 *       manager re-analyzes the full program.</li>
 * </ol>
 */
public class ElfNamespaceImportTask extends Task {

	private static final String TASK_NAME = "Merge ELF into Program";

	/** Comment placed on every memory block that is added from the ELF merge. */
	static final String ELF_MERGER_COMMENT = "Loaded by elf-merger";

	private final PluginTool tool;
	private final Program existingProgram;
	private final File elfFile;
	private final String existingNamespace;
	private final String newNamespace;
	private final boolean reRunAnalysis;

	/**
	 * Constructs the task.
	 *
	 * @param tool              The plugin tool (used for analysis manager look-up).
	 * @param existingProgram   The program currently open in the CodeBrowser.
	 * @param elfFile           The ELF binary to merge in.
	 * @param existingNamespace Namespace name for all current global symbols in
	 *                          {@code existingProgram}.
	 * @param newNamespace      Namespace name for all symbols loaded from the ELF.
	 * @param reRunAnalysis     If {@code true}, re-run auto-analysis after the merge.
	 */
	public ElfNamespaceImportTask(PluginTool tool, Program existingProgram, File elfFile,
			String existingNamespace, String newNamespace, boolean reRunAnalysis) {
		super(TASK_NAME, true, false, true);
		this.tool = tool;
		this.existingProgram = existingProgram;
		this.elfFile = elfFile;
		this.existingNamespace = existingNamespace;
		this.newNamespace = newNamespace;
		this.reRunAnalysis = reRunAnalysis;
	}

	// -------------------------------------------------------------------------
	// Task entry point
	// -------------------------------------------------------------------------

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		// Phase 1 – namespace existing symbols
		monitor.setMessage("Applying namespace '" + existingNamespace + "' to existing symbols…");
		applyNamespaceToProgram(existingProgram, existingNamespace, monitor);
		monitor.checkCancelled();

		// Snapshot of block names before the ELF load so we can identify new blocks afterward
		Set<String> existingBlockNames = getMemoryBlockNames(existingProgram);

		// Phase 2 – load ELF content INTO the existing program
		monitor.setMessage("Loading ELF into program: " + elfFile.getName() + "…");
		if (!loadElfIntoExistingProgram(monitor)) {
			// loadElfIntoExistingProgram() already reported the error
			return;
		}
		monitor.checkCancelled();

		// Phase 3 – rename new memory blocks with namespace prefix
		monitor.setMessage("Renaming new memory segments with namespace prefix…");
		renameNewMemoryBlocks(existingBlockNames, monitor);
		monitor.checkCancelled();

		// Phase 4 – namespace imported symbols (those still in global namespace after Phase 1)
		monitor.setMessage("Applying namespace '" + newNamespace + "' to imported symbols…");
		applyNamespaceToProgram(existingProgram, newNamespace, monitor);
		monitor.checkCancelled();

		// Phase 5 – optionally re-run analysis
		if (reRunAnalysis) {
			monitor.setMessage("Re-running analysis…");
			runAnalysis(monitor);
		}
	}

	// -------------------------------------------------------------------------
	// Phase 2 – load ELF into existing program
	// -------------------------------------------------------------------------

	/**
	 * Uses {@link ElfLoader} to load the ELF file's segments and symbols directly into
	 * {@link #existingProgram}.  Overlays are used automatically for conflicting address ranges.
	 *
	 * @return {@code true} on success, {@code false} if an error was reported.
	 */
	private boolean loadElfIntoExistingProgram(TaskMonitor monitor) throws CancelledException {
		MessageLog log = new MessageLog();

		try (ByteProvider provider = new RandomAccessByteProvider(elfFile)) {
			ElfLoader elfLoader = new ElfLoader();
			Collection<LoadSpec> specs = elfLoader.findSupportedLoadSpecs(provider);

			if (specs.isEmpty()) {
				Msg.showError(this, null, TASK_NAME,
					"No ELF load specifications found for: " + elfFile.getName() +
						"\nThe file may not be a valid ELF binary.");
				return false;
			}

			LoadSpec loadSpec = specs.iterator().next();
			List<Option> options =
				elfLoader.getDefaultOptions(provider, loadSpec, existingProgram, true, false);

			Loader.ImporterSettings settings = new Loader.ImporterSettings(
				provider, elfFile.getName(), null, null, false, loadSpec, options, null, log,
				monitor);
			elfLoader.loadInto(existingProgram, settings);

			if (log.hasMessages()) {
				Msg.info(this, TASK_NAME + " – ELF load log:\n" + log);
			}
			return true;
		}
		catch (CancelledException ce) {
			throw ce;
		}
		catch (IOException e) {
			Msg.showError(this, null, TASK_NAME,
				"Could not read ELF file:\n" + elfFile.getAbsolutePath() + "\n\n" +
					e.getMessage(),
				e);
			return false;
		}
		catch (Exception e) {
			Msg.showError(this, null, TASK_NAME,
				"Error loading ELF into program:\n" + elfFile.getAbsolutePath() + "\n\n" +
					e.getMessage(),
				e);
			return false;
		}
	}

	// -------------------------------------------------------------------------
	// Phase 3 – rename new memory blocks
	// -------------------------------------------------------------------------

	/**
	 * Returns the set of memory block names currently present in {@code program}.
	 */
	private static Set<String> getMemoryBlockNames(Program program) {
		Set<String> names = new HashSet<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			names.add(block.getName());
		}
		return names;
	}

	/**
	 * Renames every memory block that was added after the snapshot in {@code preExistingNames} to
	 * {@code <newNamespace>:<originalName>} and sets the block comment to
	 * {@value #ELF_MERGER_COMMENT}.
	 */
	private void renameNewMemoryBlocks(Set<String> preExistingNames, TaskMonitor monitor)
			throws CancelledException {

		List<MemoryBlock> newBlocks = new ArrayList<>();
		for (MemoryBlock block : existingProgram.getMemory().getBlocks()) {
			if (!preExistingNames.contains(block.getName())) {
				newBlocks.add(block);
			}
		}

		if (newBlocks.isEmpty()) {
			return;
		}

		int tx = existingProgram.startTransaction("Rename ELF memory blocks");
		boolean success = false;
		try {
			for (MemoryBlock block : newBlocks) {
				monitor.checkCancelled();
				String newName = newNamespace + ":" + block.getName();
				try {
					block.setName(newName);
					block.setComment(ELF_MERGER_COMMENT);
				}
				catch (Exception e) {
					Msg.warn(this,
						"Could not rename memory block '" + block.getName() + "': " +
							e.getMessage());
				}
			}
			success = true;
		}
		finally {
			existingProgram.endTransaction(tx, success);
		}
	}

	// -------------------------------------------------------------------------
	// Phase 1 / 4 helper – apply namespace to a program's global symbols
	// -------------------------------------------------------------------------

	/**
	 * Creates {@code namespaceName} in {@code program} (if it does not already exist) and moves
	 * every global, non-default symbol into it.
	 */
	private void applyNamespaceToProgram(Program program, String namespaceName,
			TaskMonitor monitor) throws CancelledException {

		int tx = program.startTransaction("Apply namespace: " + namespaceName);
		boolean success = false;
		try {
			Namespace ns = getOrCreateNamespace(program, namespaceName);
			moveGlobalSymbolsToNamespace(program, ns, monitor);
			success = true;
		}
		catch (DuplicateNameException | InvalidInputException e) {
			Msg.showError(this, null, TASK_NAME,
				"Failed to create namespace '" + namespaceName + "' in program '" +
					program.getName() + "': " + e.getMessage(),
				e);
		}
		finally {
			program.endTransaction(tx, success);
		}
	}

	// -------------------------------------------------------------------------
	// Phase 5 – re-run analysis
	// -------------------------------------------------------------------------

	/**
	 * Schedules a full re-analysis of {@link #existingProgram} via Ghidra's
	 * {@link AutoAnalysisManager}.
	 */
	private void runAnalysis(TaskMonitor monitor) {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(existingProgram);
		manager.reAnalyzeAll(null);
		manager.startAnalysis(monitor);
	}

	// -------------------------------------------------------------------------
	// Symbol helpers
	// -------------------------------------------------------------------------

	/**
	 * Returns the namespace with {@code name} under the global namespace in {@code program},
	 * creating it (as a {@link SourceType#USER_DEFINED} namespace) if it does not yet exist.
	 */
	private static Namespace getOrCreateNamespace(Program program, String name)
			throws DuplicateNameException, InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace global = program.getGlobalNamespace();

		Namespace existing = symbolTable.getNamespace(name, global);
		if (existing != null) {
			return existing;
		}
		return symbolTable.createNameSpace(global, name, SourceType.USER_DEFINED);
	}

	/**
	 * Moves every global symbol that can be safely re-namespaced into {@code targetNamespace}.
	 * Symbols that cannot be moved (e.g., due to duplicate-name conflicts in the target namespace)
	 * are skipped with a warning.
	 */
	private static void moveGlobalSymbolsToNamespace(Program program, Namespace targetNamespace,
			TaskMonitor monitor) throws CancelledException {

		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator it = symbolTable.getAllSymbols(false);

		while (it.hasNext()) {
			monitor.checkCancelled();
			Symbol symbol = it.next();

			// Only operate on symbols that are currently in the global namespace
			if (!symbol.getParentNamespace().isGlobal()) {
				continue;
			}

			// Skip the special "global" namespace symbol itself (if present)
			if (symbol.getSymbolType() == SymbolType.NAMESPACE ||
				symbol.getSymbolType() == SymbolType.CLASS) {
				continue;
			}

			try {
				symbol.setNamespace(targetNamespace);
			}
			catch (DuplicateNameException | InvalidInputException
					| CircularDependencyException e) {
				Msg.warn(ElfNamespaceImportTask.class,
					"Skipping symbol '" + symbol.getName() + "': " + e.getMessage());
			}
		}
	}
}
