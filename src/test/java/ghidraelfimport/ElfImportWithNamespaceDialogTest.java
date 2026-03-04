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

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for {@link ElfImportWithNamespaceDialog} utility methods.
 */
public class ElfImportWithNamespaceDialogTest {

	@Test
	public void testStripExtension_elfExtension() {
		assertEquals("firmware", ElfImportWithNamespaceDialog.stripExtension("firmware.elf"));
	}

	@Test
	public void testStripExtension_noExtension() {
		assertEquals("firmware", ElfImportWithNamespaceDialog.stripExtension("firmware"));
	}

	@Test
	public void testStripExtension_multipleDotsKeepsBaseName() {
		assertEquals("my.binary", ElfImportWithNamespaceDialog.stripExtension("my.binary.elf"));
	}

	@Test
	public void testStripExtension_dotAtStart() {
		// Leading dot (hidden file, no real extension) – the dot is at index 0, so the name is
		// returned unchanged.
		assertEquals(".hidden", ElfImportWithNamespaceDialog.stripExtension(".hidden"));
	}

	@Test
	public void testStripExtension_nullInput() {
		assertEquals("", ElfImportWithNamespaceDialog.stripExtension(null));
	}

	@Test
	public void testStripExtension_emptyString() {
		assertEquals("", ElfImportWithNamespaceDialog.stripExtension(""));
	}
}
