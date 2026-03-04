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

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Dialog that collects the three parameters required for an ELF-with-namespace import:
 * <ul>
 *   <li>The ELF file to import.</li>
 *   <li>A namespace name for the symbols of the already-open (existing) binary.</li>
 *   <li>A namespace name for the symbols of the binary being imported.</li>
 * </ul>
 *
 * <p>Default values for the namespace fields are derived from the respective file names with the
 * {@code .elf} extension removed.
 */
public class ElfImportWithNamespaceDialog extends DialogComponentProvider {

	private final PluginTool tool;

	private JTextField elfFileField;
	private JTextField existingNsField;
	private JTextField newNsField;

	private File elfFile;
	private boolean cancelled = true;

	/**
	 * Constructs the dialog.
	 *
	 * @param tool           The plugin tool (parent for file choosers).
	 * @param currentProgram The program currently open in the CodeBrowser; used to derive the
	 *                       default existing-namespace value.
	 */
	public ElfImportWithNamespaceDialog(PluginTool tool, Program currentProgram) {
		super("Import ELF with Namespace", true, true, true, false);
		this.tool = tool;

		addWorkPanel(buildMainPanel(currentProgram));
		addOKButton();
		addCancelButton();

		setDefaultButton(okButton);
		setRememberSize(true);
	}

	// -------------------------------------------------------------------------
	// Panel construction
	// -------------------------------------------------------------------------

	private JPanel buildMainPanel(Program currentProgram) {
		JPanel panel = new JPanel(new GridBagLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		GridBagConstraints labelConstraints = new GridBagConstraints();
		labelConstraints.anchor = GridBagConstraints.WEST;
		labelConstraints.insets = new Insets(4, 4, 4, 8);
		labelConstraints.gridx = 0;
		labelConstraints.fill = GridBagConstraints.NONE;

		GridBagConstraints fieldConstraints = new GridBagConstraints();
		fieldConstraints.anchor = GridBagConstraints.WEST;
		fieldConstraints.insets = new Insets(4, 0, 4, 4);
		fieldConstraints.gridx = 1;
		fieldConstraints.fill = GridBagConstraints.HORIZONTAL;
		fieldConstraints.weightx = 1.0;

		GridBagConstraints buttonConstraints = new GridBagConstraints();
		buttonConstraints.anchor = GridBagConstraints.WEST;
		buttonConstraints.insets = new Insets(4, 4, 4, 4);
		buttonConstraints.gridx = 2;

		int row = 0;

		// --- ELF file row ---
		labelConstraints.gridy = row;
		panel.add(new JLabel("ELF File:"), labelConstraints);

		elfFileField = new JTextField(30);
		elfFileField.setEditable(false);
		elfFileField.setToolTipText("Path to the ELF binary to import");
		fieldConstraints.gridy = row;
		panel.add(elfFileField, fieldConstraints);

		JButton browseButton = new JButton("Browse...");
		browseButton.addActionListener(e -> browseForElfFile());
		buttonConstraints.gridy = row;
		panel.add(browseButton, buttonConstraints);
		row++;

		// --- Existing binary namespace row ---
		labelConstraints.gridy = row;
		panel.add(new JLabel("Existing Binary Namespace:"), labelConstraints);

		String existingDefault = stripExtension(currentProgram.getName());
		existingNsField = new JTextField(existingDefault, 30);
		existingNsField.setToolTipText(
			"Namespace to assign to all current global symbols (default: program name without extension)");
		fieldConstraints.gridy = row;
		panel.add(existingNsField, fieldConstraints);
		row++;

		// --- New binary namespace row ---
		labelConstraints.gridy = row;
		panel.add(new JLabel("New Binary Namespace:"), labelConstraints);

		newNsField = new JTextField(30);
		newNsField.setToolTipText(
			"Namespace to assign to all symbols in the imported binary (default: file name without .elf)");
		fieldConstraints.gridy = row;
		panel.add(newNsField, fieldConstraints);

		// Wrap in a border panel so the dialog has a decent minimum size
		JPanel wrapper = new JPanel(new BorderLayout());
		wrapper.add(panel, BorderLayout.NORTH);
		return wrapper;
	}

	// -------------------------------------------------------------------------
	// Button callbacks
	// -------------------------------------------------------------------------

	private void browseForElfFile() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Select ELF File");
		chooser.setFileFilter(new FileNameExtensionFilter("ELF files (*.elf)", "elf"));
		chooser.setAcceptAllFileFilterUsed(true);

		int result = chooser.showOpenDialog(getComponent());
		if (result == JFileChooser.APPROVE_OPTION) {
			File selected = chooser.getSelectedFile();
			elfFileField.setText(selected.getAbsolutePath());
			elfFile = selected;

			// Auto-populate the new-binary namespace field from the selected file name
			String defaultNs = stripExtension(selected.getName());
			if (newNsField.getText().isBlank()) {
				newNsField.setText(defaultNs);
			}
		}
	}

	@Override
	protected void okCallback() {
		// Validate ELF file
		String filePath = elfFileField.getText().trim();
		if (filePath.isEmpty()) {
			Msg.showError(this, getComponent(), "Validation Error",
				"Please select an ELF file to import.");
			return;
		}
		File candidate = new File(filePath);
		if (!candidate.isFile()) {
			Msg.showError(this, getComponent(), "Validation Error",
				"The selected path does not point to a readable file:\n" + filePath);
			return;
		}
		elfFile = candidate;

		// Validate existing namespace
		String existingNs = existingNsField.getText().trim();
		if (existingNs.isEmpty()) {
			Msg.showError(this, getComponent(), "Validation Error",
				"Please enter a namespace name for the existing binary.");
			return;
		}

		// Validate new namespace
		String newNs = newNsField.getText().trim();
		if (newNs.isEmpty()) {
			Msg.showError(this, getComponent(), "Validation Error",
				"Please enter a namespace name for the imported binary.");
			return;
		}

		if (existingNs.equals(newNs)) {
			Msg.showError(this, getComponent(), "Validation Error",
				"The existing-binary namespace and the new-binary namespace must be different.");
			return;
		}

		cancelled = false;
		close();
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		close();
	}

	// -------------------------------------------------------------------------
	// Accessors
	// -------------------------------------------------------------------------

	/** Returns {@code true} if the user cancelled or closed the dialog without confirming. */
	public boolean isCancelled() {
		return cancelled;
	}

	/** Returns the ELF file selected by the user, or {@code null} if cancelled. */
	public File getElfFile() {
		return elfFile;
	}

	/** Returns the namespace name the user entered for the existing (already-open) binary. */
	public String getExistingBinaryNamespace() {
		return existingNsField.getText().trim();
	}

	/** Returns the namespace name the user entered for the newly imported binary. */
	public String getNewBinaryNamespace() {
		return newNsField.getText().trim();
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Strips the file extension from {@code name}.  If the name contains no dot, the original
	 * name is returned unchanged.
	 *
	 * @param name File name (with or without extension).
	 * @return The name without its last dot-delimited suffix.
	 */
	static String stripExtension(String name) {
		if (name == null) {
			return "";
		}
		int dot = name.lastIndexOf('.');
		return (dot > 0) ? name.substring(0, dot) : name;
	}
}
