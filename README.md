"# GHIDRA ELF Namespace Import Extension

A Ghidra extension that adds an **"Import ELF with Namespace"** action to the CodeBrowser
*File* menu.  When triggered, the extension:

1. Asks the user for an ELF file to import, a namespace name for the symbols of the
   already-open binary, and a namespace name for the symbols of the new binary.
2. Moves all global symbols in the currently open program into the specified *existing-binary*
   namespace.
3. Imports the selected ELF binary into the current Ghidra project using the standard ELF loader.
4. Moves all global symbols of the imported program into the specified *new-binary* namespace.

This prevents symbol-name clashes when two related binaries share common symbol names
(e.g. `main`, `init`).

---

## Requirements

| Requirement | Version |
|---|---|
| Ghidra | 11.x or later |
| JDK | 21 (as required by Ghidra 11.x) |
| Gradle | 8.5+ (or use the Gradle wrapper) |

---

## Building the Extension

1. **Install Ghidra** from the [Ghidra releases page](https://github.com/NationalSecurityAgency/ghidra/releases)
   and note its installation directory (e.g. `/opt/ghidra_11.0`).

2. **Clone this repository**:
   ```bash
   git clone https://github.com/Buttje/GHIDRA_ELF_Import.git
   cd GHIDRA_ELF_Import
   ```

3. **Build** by pointing Gradle at your Ghidra installation:
   ```bash
   export GHIDRA_INSTALL_DIR=/opt/ghidra_11.0   # adjust to your installation path
   gradle
   ```
   or inline:
   ```bash
   gradle -PGHIDRA_INSTALL_DIR=/opt/ghidra_11.0
   ```

4. The built extension ZIP file is placed in the `dist/` directory:
   ```
   dist/ghidra_11.0_PUBLIC_<date>_ELF_Namespace_Import.zip
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
2. Go to **File → Import ELF with Namespace…**
3. In the dialog:
   - Click **Browse…** to select the ELF file you want to import.
   - Set the **Existing Binary Namespace** (default: current program name without extension).
   - Set the **New Binary Namespace** (default: selected file name without `.elf`).
4. Click **OK**.  The import runs as a background task.

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
