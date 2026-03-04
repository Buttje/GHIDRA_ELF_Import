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

import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Background task that performs the three-phase ELF-with-namespace import:
 *
 * <ol>
 *   <li><b>Namespace existing symbols</b> – creates the user-supplied namespace in the currently
 *       open program and moves all global symbols into it.</li>
 *   <li><b>Import the ELF</b> – uses Ghidra's automatic loader to import the ELF file into the
 *       current project folder and save it.</li>
 *   <li><b>Namespace imported symbols</b> – creates the user-supplied namespace in the newly
 *       imported program and moves all global symbols into it.</li>
 * </ol>
 */
public class ElfNamespaceImportTask extends Task {

	private static final String TASK_NAME = "Import ELF with Namespace";

	private final PluginTool tool;
	private final Program existingProgram;
	private final File elfFile;
	private final String existingNamespace;
	private final String newNamespace;

	/**
	 * Constructs the task.
	 *
	 * @param tool              The plugin tool (used to retrieve the active {@link Project}).
	 * @param existingProgram   The program currently open in the CodeBrowser.
	 * @param elfFile           The ELF binary to import.
	 * @param existingNamespace Namespace name for all global symbols in {@code existingProgram}.
	 * @param newNamespace      Namespace name for all global symbols in the imported program.
	 */
	public ElfNamespaceImportTask(PluginTool tool, Program existingProgram, File elfFile,
			String existingNamespace, String newNamespace) {
		super(TASK_NAME, true, false, true);
		this.tool = tool;
		this.existingProgram = existingProgram;
		this.elfFile = elfFile;
		this.existingNamespace = existingNamespace;
		this.newNamespace = newNamespace;
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

		// Phase 2 – import the ELF file
		monitor.setMessage("Importing ELF file: " + elfFile.getName() + "…");
		Program importedProgram = importElf(monitor);
		if (importedProgram == null) {
			// importElf() already reported the error
			return;
		}

		try {
			monitor.checkCancelled();

			// Phase 3 – namespace imported symbols
			monitor.setMessage("Applying namespace '" + newNamespace + "' to imported symbols…");
			applyNamespaceToProgram(importedProgram, newNamespace, monitor);

		}
		finally {
			importedProgram.release(this);
		}
	}

	// -------------------------------------------------------------------------
	// Phase 1 / 3 helper – apply namespace to a program's global symbols
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
	// Phase 2 helper – import the ELF file
	// -------------------------------------------------------------------------

	/**
	 * Imports the ELF file using Ghidra's automatic loader.  The imported program is saved to the
	 * root folder of the current project and returned with {@code this} task registered as a
	 * consumer.  The caller is responsible for calling {@code program.release(this)} when done.
	 *
	 * @return The imported {@link Program}, or {@code null} on failure.
	 */
	private Program importElf(TaskMonitor monitor) {
		Project project = tool.getProject();
		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		MessageLog log = new MessageLog();

		// Use a dedicated short-lived consumer for the LoadResults object itself.
		// 'this' task is registered separately via getPrimaryDomainObject(this) so that the
		// returned Program stays open after the LoadResults is closed.
		Object importConsumer = new Object();

		try (LoadResults<Program> results = AutoImporter.importByUsingBestGuess(elfFile, project,
			rootFolder.getPathname(), importConsumer, log, monitor)) {

			// Save all loaded programs to the project
			results.save(monitor);

			// Register 'this' task as a consumer; caller must call program.release(this).
			return results.getPrimaryDomainObject(this);
		}
		catch (Exception e) {
			Msg.showError(this, null, TASK_NAME,
				"Error importing ELF file:\n" + elfFile.getAbsolutePath() + "\n\n" +
					e.getMessage() + "\n\nLog:\n" + log.toString(),
				e);
			return null;
		}
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
