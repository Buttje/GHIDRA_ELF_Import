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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.task.TaskLauncher;

import java.io.File;

/**
 * Plugin that adds a "Merge ELF into Program" action to the CodeBrowser File menu.
 *
 * <p>When triggered, the user is prompted for an ELF file to merge, a namespace name for the
 * symbols already present in the open program (existing binary), and a namespace name for the
 * symbols of the newly merged binary.  Default namespace values are derived from the respective
 * file names (without the {@code .elf} extension).
 *
 * <p>After the dialog is confirmed, the extension:
 * <ol>
 *   <li>Creates the specified namespace in the existing program and moves all current global
 *       symbols into it.</li>
 *   <li>Loads the selected ELF binary's memory segments and symbols <em>directly into the
 *       existing program</em> using Ghidra's ELF loader ("Add To Program" semantics).  The new
 *       file's content becomes part of the same memory map – no separate program is created.</li>
 *   <li>Renames every newly added memory block to {@code <newNamespace>:<originalName>} and marks
 *       it as loaded by the elf-merger.</li>
 *   <li>Creates the specified namespace in the existing program and moves all symbols that arrived
 *       from the ELF into it.</li>
 *   <li>Optionally re-runs Ghidra's auto-analysis on the merged program.</li>
 * </ol>
 *
 * <p>This prevents symbol name clashes when two related binaries share common symbol names.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "ELF Namespace Import",
	category = PluginCategoryNames.IMPORT_EXPORT,
	shortDescription = "Merge ELF file into the current program with namespace support",
	description = "Merges an ELF binary into the currently open program (Add To Program " +
		"semantics) and applies namespaces to symbols in both the existing and merged binary " +
		"to prevent name clashes."
)
//@formatter:on
public class ElfNamespaceImportPlugin extends ProgramPlugin {

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public ElfNamespaceImportPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		setupActions();
	}

	private void setupActions() {
		DockingAction action = new DockingAction("Merge ELF into Program", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				mergeElfIntoProgram();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};

		action.setMenuBarData(
			new MenuData(new String[] { "File", "Merge ELF into Program..." }, "Import"));
		action.setDescription(
			"Merge an ELF binary into the current program and apply namespaces to avoid name clashes.");

		tool.addAction(action);
	}

	private void mergeElfIntoProgram() {
		ElfImportWithNamespaceDialog dialog =
			new ElfImportWithNamespaceDialog(tool, currentProgram);
		tool.showDialog(dialog);

		if (dialog.isCancelled()) {
			return;
		}

		File elfFile = dialog.getElfFile();
		String existingNs = dialog.getExistingBinaryNamespace();
		String newNs = dialog.getNewBinaryNamespace();
		boolean reRunAnalysis = dialog.isReRunAnalysis();

		TaskLauncher.launch(
			new ElfNamespaceImportTask(tool, currentProgram, elfFile, existingNs, newNs,
				reRunAnalysis));
	}
}
