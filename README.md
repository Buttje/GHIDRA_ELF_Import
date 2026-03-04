"# GHIDRA ELF Namespace Import Extension

A Ghidra extension that adds a **"Merge ELF into Program"** action to the CodeBrowser
*File* menu.  When triggered, the extension merges the chosen ELF binary **directly into the
currently open program** (identical to Ghidra's built-in *Add To Program* semantics) rather than
creating a separate program.  The new file's memory segments and symbols become part of the
existing memory map.

The full operation:

1. Moves all global symbols in the currently open program into the specified *existing-binary*
   namespace.
2. Loads the selected ELF binary's segments and symbols into the same program using Ghidra's
   `ElfLoader`.  Overlays are created automatically for any conflicting address ranges.
3. Renames every newly added memory block to `<newNamespace>:<originalName>` (e.g.
   `mylib:.text`) and marks it with the comment *Loaded by elf-merger*.
4. Moves all symbols that arrived from the ELF into the specified *new-binary* namespace.
5. (Optionally) Re-runs Ghidra's auto-analysis on the merged program.

This prevents symbol-name clashes when two related binaries share common symbol names
(e.g. `main`, `init`).

---

## Requirements

| Requirement | Version |
|---|---|
| Ghidra | 12.0 or later |
| JDK | 21 (as required by Ghidra 12.x) |
| Gradle | 8.5+ (or use the Gradle wrapper) |

---

## Building the Extension

1. **Install Ghidra** from the [Ghidra releases page](https://github.com/NationalSecurityAgency/ghidra/releases)
   and note its installation directory (e.g. `/opt/ghidra_12.0.4`).

2. **Clone this repository**:
   ```bash
   git clone https://github.com/Buttje/GHIDRA_ELF_Import.git
   cd GHIDRA_ELF_Import
   ```

3. **Build** by pointing Gradle at your Ghidra installation:
   ```bash
   export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4   # adjust to your installation path
   gradle
   ```
   or inline:
   ```bash
   gradle -PGHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4
   ```

4. The built extension ZIP file is placed in the `dist/` directory:
   ```
   dist/ghidra_12.0.4_PUBLIC_<date>_ELF_File_Adder.zip
   ```

---

## Installing the Extension in Ghidra

1. Launch Ghidra.
2. In the **Project Manager**, go to **File → Install Extensions…**
3. Click the **+** (Add Extension) button and select the ZIP file from the `dist/` directory.
4. Restart Ghidra when prompted.
5. Enable the extension in **File → Configure → Configure All Plugins** (search for
   *ElfNamespaceImport*) or leave it to be auto-discovered.

---

## Using the Extension

1. Open a binary in the **CodeBrowser**.
2. Go to **File → Merge ELF into Program…**
3. In the dialog:
   - Click **Browse…** to select the ELF file you want to merge in.
   - Set the **Existing Binary Namespace** (default: current program name without extension).
   - Set the **New Binary Namespace** (default: selected file name without `.elf`).
   - Optionally check **Re-run analysis after merge** to trigger auto-analysis when done.
4. Click **OK**.  The merge runs as a background task.

---

## Development Setup (Eclipse / GhidraDev)

For interactive development and debugging, use the
[GhidraDev Eclipse plugin](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/README.md)
bundled with every Ghidra installation under `Extensions/Eclipse/GhidraDev/`.

1. Install Eclipse IDE for Java Developers.
2. Install GhidraDev from `<GHIDRA_INSTALL_DIR>/Extensions/Eclipse/GhidraDev/`.
3. In Eclipse: **GhidraDev → Import Ghidra Module Source** → select this repository directory.
4. Use the generated run configuration to launch and debug Ghidra with the extension loaded.

---

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)" 
