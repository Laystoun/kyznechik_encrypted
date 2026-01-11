import java.io.File
import java.util.Base64
import java.util.UUID
import kotlin.text.format
import java.io.BufferedWriter
import java.security.SecureRandom
import kotlin.experimental.xor

fun main() {
    val kuz = BasicConst()
    print("Отображать логи шифрования?\nY/N: ")
    val viewLogsChange = readln().lowercase()
    println("")
    val viewLogs = isViewLogs(viewLogsChange)

    if (viewLogs) println("Create 10 rounded key (128bit) ")

    val startKeyTimer = System.currentTimeMillis()
    kuz.generateRoundKey()
    val generateKeyTime = System.currentTimeMillis() - startKeyTimer

    if (viewLogs) {
        for (i in kuz.roundKeys.indices) {
            print("$i) ")
            for (j in kuz.roundKeys.indices) {
                print("%02x".format(kuz.roundKeys[i][j]))
            }
            println()
        }

        print("Create master-key encrypted (256 bit): ")
        kuz.cipherKey.forEach { print("%02x".format(it)) }
        println()
        println("round key generation time: ${generateKeyTime}ms\n")
    }

    println("Choise data for encrypted\n1 Text\n2 File\nEnter 1 or 2: ")

    val choice = readln()   // Text or File?

    println("")

    if (choice == "1") {
        println("Enter your text: ")
        val inputText = readln()
        val inputBytes = inputText.toByteArray()
        val pkcs7Padding = pkcs7Pad(inputBytes)
        val blockCount = pkcs7Padding.size / 16
        val block16 = Array(blockCount) { ByteArray(16) }

        println("")

        for (blockIndex in 0 until blockCount) {
            for (byteIndex in 0 until 16) {
                block16[blockIndex][byteIndex] =
                    pkcs7Padding[blockIndex * 16 + byteIndex]
            }
        }

        val startEncryptedTime = System.currentTimeMillis()
        for (i in block16.indices) {
            kuz.encryptBlock(block16[i], kuz.roundKeys, viewLogs)
        }
        val endEncryptedTime = (System.currentTimeMillis() - startEncryptedTime).toFloat()

        val encryptedBlock = ByteArray(block16.size * 16)
        for (i in block16.indices) {
            for (j in 0 until 16) {
                encryptedBlock[i * 16 + j] = block16[i][j]
            }
        }

        val base64 = Base64.getEncoder().encodeToString(encryptedBlock)

        val encryptedOutput = StringBuilder()
        for (i in block16.indices) {
            encryptedOutput.append("encrypted block $i: [")
            for (j in 0 until 16) {
                encryptedOutput.append("%02x".format(block16[i][j]))
            }
            encryptedOutput.append("]\n")
        }
        encryptedOutput.append("encrypted string (base64): $base64\n\n")

        val startDecryptedTime = System.currentTimeMillis()

        for (i in block16.indices) {
            kuz.decryptBlock(block16[i], kuz.roundKeys, viewLogs)
        }

        val endDecryptedTime = (System.currentTimeMillis() - startDecryptedTime).toFloat()

        print("\n${encryptedOutput}")

        val decryptedBytes = ByteArray(block16.size * 16)

        for (i in block16.indices) {
            print("decrypted block $i: [")
            for (j in 0 until 16) {
                decryptedBytes[i * 16 + j] = block16[i][j]
                print("%02x".format(block16[i][j]))
            }
            println("]")
        }

        val unpadded = pkcs7Unpad(decryptedBytes)
        val resultText = String(unpadded)

        println(
            "decrypted text: $resultText\n\n" +
                    "encrypted time: ${endEncryptedTime}ms \n" +
                    "decryption time: ${endDecryptedTime}ms"
        )

    } else if (choice == "2") {
        print("enter file path\nexample: C:\\Users\\User\\Desktop\\image.png\npath: ")
        val path = readln()
        val fileBytes = getFileBytes(path)

        if (fileBytes != null) {
            println("Start encrypted...")

            pkcs7Pad(fileBytes)

            if (viewLogsChange.lowercase() == "n") mainUxFun(kuz, fileBytes, null)
            else if (viewLogsChange.lowercase() == "y") {
                val logFile = File(
                    "C:\\Users\\${System.getProperty("user.name")}\\Desktop\\log_file${
                        UUID.randomUUID().toString().take(8)
                    }.txt"
                )

                val bufferedWriter = logFile.bufferedWriter()
                mainUxFun(kuz, fileBytes, bufferedWriter, path)
            }
        }
    }


}

fun mainUxFun(
    kuz: BasicConst,
    fileBytes: ByteArray,
    writeObject: BufferedWriter? = null,
    path: String? = null
) {
    val pkcs7_array = pkcs7Pad(fileBytes)

    writeObject?.write("add pkcs7 padding\n")
    val block16 = Array(pkcs7_array.size / 16) { ByteArray(16) }

    // Write padding array with block16
    for (blockIndex in 0 until pkcs7_array.size / 16) {
        for (byteIndex in 0 until 16) {
            block16[blockIndex][byteIndex] =
                pkcs7_array[blockIndex * 16 + byteIndex]
        }
    }


    val startEncryptedTime = System.currentTimeMillis()
    writeObject?.write("start_encrypt\n")
    for (i in block16.indices) {
        kuz.encryptBlock(block16[i], kuz.roundKeys, false, writeObject)
    }
    val endEncryptedTime = (System.currentTimeMillis() - startEncryptedTime).toFloat()

    var encrypted_block: ByteArray? = null

    if (writeObject != null) {
        encrypted_block = ByteArray(block16.size * 16)
        for (i in block16.indices) {
            writeObject.write("encrypted block $i: [")
            for (j in 0 until 16) {
                writeObject.append("%02x".format(block16[i][j]))
                encrypted_block[i * 16 + j] = block16[i][j]
            }
            writeObject.write("]\n")
        }
    }

    val encryptedFileBase64 = if (writeObject != null) {
        Base64.getEncoder()
            .encodeToString(encrypted_block)
    } else null

    var decryptedBlock: ByteArray? = null

    writeObject?.write("\nencrypted bytes: $encryptedFileBase64\n")

    val startDecryptionTime = System.currentTimeMillis()
    for (i in block16.indices) {
        kuz.decryptBlock(block16[i], kuz.roundKeys, false, writeObject)
    }
    val end_decrypted_time = (System.currentTimeMillis() - startDecryptionTime).toFloat()

    if (writeObject != null) {
        decryptedBlock = ByteArray(block16.size * 16)
        for (i in block16.indices) {
            for (j in 0 until 16) {
                decryptedBlock[i * 16 + j] = block16[i][j]
            }
        }
    }

    if (writeObject != null) {
        for (i in block16.indices) {
            writeObject.write("decrypted block $i: [")
            for (j in 0 until 16) {
                decryptedBlock!![i * 16 + j] = block16[i][j]
                writeObject.write("%02x".format(block16[i][j]))
            }
            writeObject.write("]\n")
        }
    }

    println(
        "Congratulations, your file has been successfully encrypted.\n" +
                "Time encrypted: ${endEncryptedTime}ms\n" +
                "Time decrypted: ${end_decrypted_time}ms"
    )

    writeFileBytes(path, encrypted_block)
    writeObject?.flush()
}

fun isViewLogs(change: String): Boolean {
    return when(change) {
        "y" -> true
        "n" -> false
        else -> true
    }
}

fun getFileBytes(path: String): ByteArray? {
    return try {
        File(path).readBytes()
    } catch (e: Exception) {
        print("Error read file...\n${e.message}")
        null
    }
}

fun writeFileBytes(path: String? = null, byteArray: ByteArray? = null) {
    try {
        if (path == null || byteArray == null) {
            println("writeFileByte(): Error path or writing file \npath: $path\n byteArray: $byteArray")
            return
        }

        val file = File(path)

        val fileExtension = file.extension
        val endNameFile = "encrypted_file${UUID.randomUUID().toString().take(8)}.$fileExtension"
        val endPathFile = "C:\\Users\\${System.getProperty("user.name")}\\Desktop\\$endNameFile"
        val outputFile = File(endPathFile)
        val base64 = Base64.getEncoder().encodeToString(byteArray)
        outputFile.writeBytes(base64.toByteArray())

        println("Encrypted file saved to: $endPathFile")
    } catch (e: Exception) {
        println("Error creating file (${e.message})")
    }
}

fun pkcs7Pad(data: ByteArray, blockSize: Int = 16): ByteArray {
    // 16 - (3 % 16) = 13
    val padLen = blockSize - (data.size % blockSize)
    // 3 + 13 = 16byte (1d, 2d, 3d, 13, 13, 13...)
    val result = ByteArray(data.size + padLen)

    // put enter data
    for (i in 0 until data.size) {
        result[i] = data[i]
    }

    // put padding
    for (i in data.size until result.size) {
        result[i] = padLen.toByte()
    }

    return result
}

fun pkcs7Unpad(data: ByteArray, blockSize: Int = 16): ByteArray {
    require(data.isNotEmpty())
    require(data.size % blockSize == 0)

    val padLen = data.last().toInt() and 0xFF

    require(padLen in 1..blockSize)

    for (i in data.size - padLen until data.size) {
        require((data[i].toInt() and 0xFF) == padLen)
    }

    return data.copyOfRange(0, data.size - padLen)
}

class BasicConst() {
    val rnd = SecureRandom()
    val cipherKey = ByteArray(32)
    val roundKeys = Array(10) { ByteArray(16) }

    init {
        fillOut(rnd, cipherKey)
    }

    val PI = arrayOf<Int>(
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250,
        218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
        153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249,
        24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
        139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
        160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52,
        44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253,
        58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18,
        191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150,
        41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
        178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109,
        84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
        62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
        3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232,
        40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30,
        0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
        173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165,
        125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172,
        29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225,
        27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144,
        202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9,
        91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
        116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57,
        75, 99, 182
    )

    // Генерация мастер ключа
    private fun fillOut(rnd: SecureRandom, cipherArray: ByteArray) {
        rnd.nextBytes(cipherArray)
    }

    // Нелинейное S-преобразование
    fun sBoxTransformation(byteArray: ByteArray, piTable: Array<Int>): ByteArray {
        val outputEncryptedBytes = mutableListOf<Byte>()
        for (i in byteArray) {
            val piTableValue = piTable[i.toInt() and 0xFF].toByte()
            outputEncryptedBytes.add(piTableValue)
        }
        return outputEncryptedBytes.toByteArray()
    }

    // Сдвиги влево и вправо / xor
    // (GF умножение) для ограничения выхода за 1 байт + обратимости
    fun gfMultiplication(block: Byte, coefficient: Byte): Byte {
        var result: Int = 0
        var innerA = block.toInt()
        var innerB = coefficient.toInt()
        var seniorA = false

        for (i in 0..7) {
            seniorA = (innerA and 0x80) != 0
            if ((innerB and 1) == 1) {
                result = result xor innerA
            }
            innerA *= 2
            innerA = innerA and 0xFF
            if (seniorA) innerA = innerA xor 0xC3    // Граница 255
            innerB /= 2
        }

        return result.toByte()
    }

    // Сжатие всех байтов в один
    fun rTransformation(block: ByteArray) {
        if (block.size != 16) {
            print("data block is > 16 byte...")
            return
        }
        var x: Byte = 0

        val rCoefficient = byteArrayOf(
            148.toByte(), 32.toByte(), 133.toByte(), 16.toByte(),
            194.toByte(), 192.toByte(), 1.toByte(), 251.toByte(),
            1.toByte(), 192.toByte(), 194.toByte(), 16.toByte(),
            133.toByte(), 32.toByte(), 148.toByte(), 1.toByte()
        )

        for (i in 0..15) {
            x = x xor gfMultiplication(block[i], rCoefficient[i])
        }

        for (i in 15 downTo 1) {    // Сдвиг вправо
            block[i] = block[i - 1]
        }

        block[0] = x
    }

    // Усиление R-перемешивания
    fun lTransformation(block: ByteArray) {
        for (i in 0..15) {
            rTransformation(block)
        }
    }

    fun encryptBlock(
        block: ByteArray,
        roundKeys: Array<ByteArray>,
        viewLogs: Boolean,
        writer: BufferedWriter? = null
    ) {
        if (block.size != 16) {
            throw IllegalArgumentException("block must be 16 bytes")
        }

        // 9 основных раундов
        for (round in 0 until 9) {
            // xor с раундовым ключом
            for (i in 0 until 16) {
                val saveLast = block[i]
                block[i] = block[i] xor roundKeys[round][i]
                if (viewLogs) println("xor with round-key №$round: ${"%02x".format(saveLast)} -> ${"%02x".format(block[i])}")
                writer?.write("xor with round-key №$round: ${"%02x".format(saveLast)} -> ${"%02x".format(block[i])}\n")
            }

            // S-преобразование
            val s = sBoxTransformation(block, PI)
            for (i in 0 until 16) {
                val save_last = block[i]
                block[i] = s[i]
                if (viewLogs) println("s_box_moving: ${"%02x".format(save_last)} -> ${"%02x".format(block[i])}")
                writer?.write("s_box_moving: ${"%02x".format(save_last)} -> ${"%02x".format(block[i])}\n")
            }

            // L-преобразование
            lTransformation(block)
        }

        // финальный раунд (только xor)
        for (i in 0 until 16) {
            block[i] = block[i] xor roundKeys[9][i]
        }
    }

    // Соль для ключей
    fun generateC(i: Int): ByteArray {
        val Ci = ByteArray(16)
        Ci[0] = i.toByte()
        lTransformation(Ci)
        return Ci
    }

    fun F(
        k1: ByteArray,
        k2: ByteArray,
        Ci: ByteArray
    ): Pair<ByteArray, ByteArray> {
        var tmp = ByteArray(16)

        for (i in Ci.indices) {
            tmp[i] = k1[i] xor Ci[i]
        }

        tmp = sBoxTransformation(tmp, PI)
        lTransformation(tmp)

        for (i in tmp.indices) {
            tmp[i] = tmp[i] xor k2[i]
        }

        return Pair(tmp, k1)
    }

    // Развёртка ключей
    fun generateRoundKey() {
        // разбиваем мастер-ключ
        var k1 = cipherKey.copyOfRange(0, 16)
        var k2 = cipherKey.copyOfRange(16, 32)

        // сохраняем первые два раундовых ключа
        roundKeys[0] = k1.copyOf()
        roundKeys[1] = k2.copyOf()

        var roundIndex = 2

        // 32 итерации F
        for (i in 1..32) {
            val Ci = generateC(i)
            val result = F(k1, k2, Ci)

            k1 = result.first
            k2 = result.second

            // каждые 8 итераций сохраняем ключи
            if (i % 8 == 0) {
                roundKeys[roundIndex] = k1.copyOf()
                roundKeys[roundIndex + 1] = k2.copyOf()
                roundIndex += 2
            }
        }
    }

    fun sBoxInverse(block: ByteArray) {
        val PI_INV: IntArray = IntArray(256).also { inv ->
            for (x in 0..255) {
                val y = PI[x]
                inv[y] = x
            }
        }

        for (i in block.indices) {
            val block_value = block[i].toInt() and 0xFF
            block[i] = PI_INV[block_value].toByte()
        }
    }

    fun rInverseTransformation(block: ByteArray) {
        if (block.size != 16) {
            throw IllegalArgumentException("block must be 16 bytes")
        }

        val x = block[0]
        var s: Byte = 0

        val rCoefficient = byteArrayOf(
            148.toByte(), 32.toByte(), 133.toByte(), 16.toByte(),
            194.toByte(), 192.toByte(), 1.toByte(), 251.toByte(),
            1.toByte(), 192.toByte(), 194.toByte(), 16.toByte(),
            133.toByte(), 32.toByte(), 148.toByte(), 1.toByte()
        )

        for (i in 1 until 16) {
            s = s xor gfMultiplication(block[i], rCoefficient[i - 1])
        }

        val a15 = x xor s

        for (i in 0 until 15) {
            block[i] = block[i + 1]
        }

        block[15] = a15
    }

    fun lInverseTransformation(block: ByteArray) {
        for (i in 0 until 16) {
            rInverseTransformation(block)
        }
    }

    fun decryptBlock(
        block: ByteArray,
        roundKeys: Array<ByteArray>,
        viewLogs: Boolean,
        writer: BufferedWriter? = null
    ) {
        for (i in 0 until 16) {
            block[i] = block[i] xor roundKeys[9][i]
        }

        for (round in 8 downTo 0) {
            lInverseTransformation(block)

            sBoxInverse(block)

            for (i in 15 downTo 0) {
                val saveLast = block[i]
                block[i] = block[i] xor roundKeys[round][i]
                if (viewLogs) println(
                    "decrypt with round-key №$round: ${"%02x".format(saveLast)} -> ${
                        "%02x".format(
                            block[i]
                        )
                    }"
                )
                writer?.write("decrypt with round-key №$round: ${"%02x".format(saveLast)} -> ${"%02x".format(block[i])}\n")
            }
        }
    }
}