package org.bowparser.bowparser

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

object NativeLoader {
    private const val MACHINE_X64 = 0x6486
    private const val MACHINE_ARM64 = 0xAA64

    @JvmStatic
    fun ensureCorrectJSerialCommNativeLoaded() {
        val arch = System.getProperty("os.arch").lowercase()
        val wantX64 = arch.contains("amd64") || arch.contains("x86_64")
        val resourcePath = if (wantX64) "/Windows/x86_64/jSerialComm.dll" else "/Windows/armv7/jSerialComm.dll"

        val resStream = NativeLoader::class.java.getResourceAsStream(resourcePath)
            ?: throw IllegalStateException("Native resource not found in JAR: $resourcePath")

        val tmpDir = Files.createTempDirectory("jsc_native_")
        tmpDir.toFile().deleteOnExit()
        val target = tmpDir.resolve("jSerialComm.dll").toFile()
        target.deleteOnExit()

        val tmpWrite = tmpDir.resolve(target.name + ".writing")
        try {
            // Stream copy and ensure stream is closed
            resStream.use { input ->
                Files.copy(input, tmpWrite, StandardCopyOption.REPLACE_EXISTING)
            }

            // Try atomic move, fallback to replace if not supported
            try {
                Files.move(tmpWrite, target.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } catch (e: Exception) {
                Files.move(tmpWrite, target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }

            val machine = readPeMachine(target)
            if (wantX64 && machine != MACHINE_X64) {
                target.delete()
                throw IllegalStateException("Extracted native is not x64 (found 0x${machine.toString(16)}).")
            }
            if (!wantX64 && machine != MACHINE_ARM64) {
                target.delete()
                throw IllegalStateException("Extracted native is not ARM64 (found 0x${machine.toString(16)}).")
            }

            System.load(target.absolutePath)
            println("Loaded jSerialComm native from ${target.absolutePath} (machine=0x${machine.toString(16)})")
        } catch (ioe: IOException) {
            // cleanup on failure
            try { Files.deleteIfExists(tmpWrite) } catch (_: Exception) {}
            try { Files.deleteIfExists(target.toPath()) } catch (_: Exception) {}
            throw ioe
        }
    }

    private fun readPeMachine(dll: File): Int {
        RandomAccessFile(dll, "r").use { raf ->
            val fileLen = raf.length()
            if (fileLen < 0x40) throw IOException("File too small to be a valid PE")
            raf.seek(0x3C)
            val e_lfanew = Integer.reverseBytes(raf.readInt()).toLong()
            if (e_lfanew <= 0 || e_lfanew + 6 > fileLen) throw IOException("Invalid PE header offset")
            raf.seek(e_lfanew + 4) // skip "PE\0\0"
            return raf.readUnsignedShort()
        }
    }
}