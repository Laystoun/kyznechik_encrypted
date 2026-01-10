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
    val view_logs_change = readln().lowercase()
    println("")
    val viewLogs = is_view_logs(view_logs_change)

    if (viewLogs) println("Create 10 rounded key (128bit) ")

    val start_key_timer = System.currentTimeMillis()
    kuz.generate_round_key()
    val generate_key_time = System.currentTimeMillis() - start_key_timer

    if (viewLogs) {
        for (i in kuz.round_keys.indices) {
            print("$i) ")
            for (j in kuz.round_keys.indices) {
                print("%02x".format(kuz.round_keys[i][j]))
            }
            println()
        }

        print("Create master-key encrypted (256 bit): ")
        kuz.cipherKey.forEach { print("%02x".format(it)) }
        println()
        if (viewLogs) println("round key generation time: ${generate_key_time}ms\n")
    }

    println("Choise data for encrypted\n1 Text\n2 File\nEnter 1 or 2: ")

    val choise = readln()   // Text or File?

    println("")

    if (choise == "1") {
        println("Enter your text: ")
        val input_text = readln()
        val input_bytes = input_text.toByteArray()
        val pkcs7_padding = pkcs7Pad(input_bytes)
        val blockCount = pkcs7_padding.size / 16
        val block16 = Array(blockCount) { ByteArray(16) }

        println("")

        for (blockIndex in 0 until blockCount) {
            for (byteIndex in 0 until 16) {
                block16[blockIndex][byteIndex] =
                    pkcs7_padding[blockIndex * 16 + byteIndex]
            }
        }

        val start_encrypted_time = System.currentTimeMillis()
        for (i in block16.indices) {
            kuz.encrypt_block(block16[i], kuz.round_keys, viewLogs)
        }
        val end_encrypted_time = (System.currentTimeMillis() - start_encrypted_time).toFloat()

        val encrypted_block = ByteArray(block16.size * 16)
        for (i in block16.indices) {
            for (j in 0 until 16) {
                encrypted_block[i * 16 + j] = block16[i][j]
            }
        }

        val base64 = Base64.getEncoder().encodeToString(encrypted_block)

        val encryptedOutput = StringBuilder()
        for (i in block16.indices) {
            encryptedOutput.append("encrypted block $i: [")
            for (j in 0 until 16) {
                encryptedOutput.append("%02x".format(block16[i][j]))
            }
            encryptedOutput.append("]\n")
        }
        encryptedOutput.append("encrypted string (base64): $base64\n\n")

        val start_decrypted_time = System.currentTimeMillis()

        for (i in block16.indices) {
            kuz.decrypt_block(block16[i], kuz.round_keys, viewLogs)
        }

        val end_decrypted_time = (System.currentTimeMillis() - start_decrypted_time).toFloat()

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
                    "encrypted time: ${end_encrypted_time}ms \n" +
                    "decryption time: ${end_decrypted_time}ms"
        )

    }
    else if (choise == "2") {
        print("enter file path\nexample: C:\\Users\\User\\Desktop\\image.png\npath: ")
        val path = readln()
        val fileBytes = getFileBytes(path)
        var finalEncryptedBlock: ByteArray? = null

        if (fileBytes != null) {
            println("Start encrypted...")
            val logFile = File("C:\\Users\\${System.getProperty("user.name")}\\Desktop\\log_file${UUID.randomUUID().toString().take(8)}.txt")

            logFile.bufferedWriter().use { writeObject ->

                val pkcs7_array = pkcs7Pad(fileBytes)
                writeObject.write("add pkcs7 padding\n")
                val block16 = Array(pkcs7_array.size / 16) { ByteArray(16) }

                // Write padding array with block16
                for (blockIndex in 0 until pkcs7_array.size / 16) {
                    for (byteIndex in 0 until 16) {
                        block16[blockIndex][byteIndex] =
                            pkcs7_array[blockIndex * 16 + byteIndex]
                    }
                }


                val start_encrypted_time = System.currentTimeMillis()
                writeObject.write("start_encrypt\n")
                for (i in block16.indices) {
                    kuz.encrypt_block(block16[i], kuz.round_keys, viewLogs, writeObject)
                }
                val end_encrypted_time = (System.currentTimeMillis() - start_encrypted_time).toFloat()

                val encrypted_block = ByteArray(block16.size * 16)
                for (i in block16.indices) {
                    writeObject.write("encrypted block: [")
                    for (j in 0 until 16) {
                        writeObject.append("%02x".format(block16[i][j]))
                        encrypted_block[i * 16 + j] = block16[i][j]
                    }
                    writeObject.write("]\n")
                }

                val encryptedFileBase64 = Base64
                    .getEncoder()
                    .encodeToString(encrypted_block)   // Encrypted file

                val decrypted_block = ByteArray(block16.size * 16)

                writeObject.write("\nencrypted bytes: $encryptedFileBase64")

                val start_decryption_time = System.currentTimeMillis()
                for (i in block16.indices) {
                    kuz.decrypt_block(block16[i], kuz.round_keys, viewLogs, writeObject)
                }
                val end_decrypted_time = (System.currentTimeMillis() - start_decryption_time).toFloat()

                for (i in block16.indices) {
                    for (j in 0 until 16) {
                        decrypted_block[i * 16 + j] = block16[i][j]
                    }
                }

                for (i in block16.indices) {
                    writeObject.write("decrypted block $i: [")
                    for (j in 0 until 16) {
                        decrypted_block[i * 16 + j] = block16[i][j]
                        writeObject.write("%02x".format(block16[i][j]))
                    }
                    writeObject.write("]\n")
                }

                println(
                    "Congratulations, your file has been successfully encrypted.\n" +
                            "Time encrypted: ${end_encrypted_time}ms\n" +
                            "Time decrypted: ${end_decrypted_time}ms"
                )

                finalEncryptedBlock = encrypted_block
            }
            writeFileBytes(path, finalEncryptedBlock)
        }
    }


}

fun is_view_logs(change: String):  Boolean {
    if (change == "y") return true
    if (change == "n") return false
    else return true
}

fun getFileBytes(path: String): ByteArray? {
    return try {
        File(path).readBytes()
    } catch (e: Exception) {
        print("Error read file...\n${e.message}")
        null
    }
}

fun writeFileBytes(path: String, byteArray: ByteArray? = null) {
    try {
        val file = File(path)

        val fileExtension = file.extension
        val endNameFile = "encrypted_file${UUID.randomUUID().toString().take(8)}.$fileExtension"
        val endPathFile = "C:\\Users\\${System.getProperty("user.name")}\\Desktop\\$endNameFile"
        val outputFile = File(endPathFile)
        val base64 = Base64.getEncoder().encodeToString(byteArray)
        if (byteArray != null) outputFile.writeBytes(base64.toByteArray())

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
    val round_keys = Array(10) { ByteArray(16) }

    init {
        fill_out(rnd, cipherKey)
    }

    val PI = arrayOf<Int>(
        252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250,
        218,  35, 197,   4,  77, 233, 119, 240, 219, 147,  46,
        153, 186,  23,  54, 241, 187,  20, 205,  95, 193, 249,
        24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66,
        139,   1, 142,  79,   5, 132,   2, 174, 227, 106, 143,
        160,   6,  11, 237, 152, 127, 212, 211,  31, 235,  52,
        44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,
        58, 206, 204, 181, 112,  14,  86,   8,  12, 118,  18,
        191, 114,  19,  71, 156, 183,  93, 135,  21, 161, 150,
        41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
        178, 177,  50, 117,  25,  61, 255,  53, 138, 126, 109,
        84, 198, 128, 195, 189,  13,  87, 223, 245,  36, 169,
        62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,
        3, 224,  15, 236, 222, 122, 148, 176, 188, 220, 232,
        40,  80,  78,  51,  10,  74, 167, 151,  96, 115,  30,
        0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
        173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165,
        125, 105, 213, 149,  59,   7,  88, 179,  64, 134, 172,
        29, 247,  48,  55, 107, 228, 136, 217, 231, 137, 225,
        27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144,
        202, 216, 133,  97,  32, 113, 103, 164,  45,  43,   9,
        91, 203, 155,  37, 208, 190, 229, 108,  82,  89, 166,
        116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,
        75,  99, 182
    )

    // Генерация мастер ключа
    private fun fill_out(rnd: SecureRandom, cipherArray: ByteArray) {
        rnd.nextBytes(cipherArray)
    }

    // Нелинейное S-преобразование
    fun s_box_transformation(byte_array: ByteArray, pi_table: Array<Int>): ByteArray {
        val output_encrypted_bytes = mutableListOf<Byte>()
        for (i in byte_array) {
            val pi_table_value = pi_table[i.toInt() and 0xFF].toByte()
            output_encrypted_bytes.add(pi_table_value)
        }
        return output_encrypted_bytes.toByteArray()
    }

    // Сдвиги влево и вправо / xor
    // (GF умножение) для ограничения выхода за 1 байт + обратимости
    fun GF_multiplication(block: Byte, coefficient: Byte): Byte {
        var result: Int = 0
        var inner_a = block.toInt()
        var inner_b = coefficient.toInt()
        var senior_a = false

        for (i in 0..7) {
            senior_a = (inner_a and 0x80) != 0
            if ((inner_b and 1) == 1) {
                result = result xor inner_a
            }
            inner_a *= 2
            inner_a = inner_a and 0xFF
            if (senior_a) inner_a = inner_a xor 0xC3    // Граница 255
            inner_b /= 2
        }

        return result.toByte()
    }

    // Сжатие всех байтов в один
    fun R_transformation(block: ByteArray) {
        if (block.size != 16) {
            print("data block is > 16 byte...")
            return
        }
        var x: Byte = 0

        val r_coefficient = byteArrayOf(
            148.toByte(), 32.toByte(), 133.toByte(), 16.toByte(),
            194.toByte(), 192.toByte(), 1.toByte(), 251.toByte(),
            1.toByte(), 192.toByte(), 194.toByte(), 16.toByte(),
            133.toByte(), 32.toByte(), 148.toByte(), 1.toByte()
        )

        for (i in 0..15) {
            x = x xor GF_multiplication(block[i], r_coefficient[i])
        }

        for (i in 15 downTo 1) {    // Сдвиг вправо
            block[i] = block[i - 1]
        }

        block[0] = x
    }

    // Усиление R-перемешивания
    fun L_transformation(block: ByteArray) {
        for (i in 0..15) {
            R_transformation(block)
        }
    }

    fun encrypt_block(block: ByteArray, roundKeys: Array<ByteArray>, viewLogs: Boolean, writer: BufferedWriter? = null) {
        if (block.size != 16) {
            throw IllegalArgumentException("block must be 16 bytes")
        }

        // 9 основных раундов
        for (round in 0 until 9) {
            // xor с раундовым ключом
            for (i in 0 until 16) {
                val save_last = block[i]
                block[i] = block[i] xor roundKeys[round][i]
                if (viewLogs) println("xor with round-key №$round: ${"%02x".format(save_last)} -> ${"%02x".format(block[i])}")
                writer?.write("xor with round-key №$round: ${"%02x".format(save_last)} -> ${"%02x".format(block[i])}\n")
            }

            // S-преобразование
            val s = s_box_transformation(block, PI)
            for (i in 0 until 16) {
                val save_last = block[i]
                block[i] = s[i]
                if (viewLogs) println("s_box_moving: ${"%02x".format(save_last)} -> ${"%02x".format(block[i])}")
                writer?.write("s_box_moving: ${"%02x".format(save_last)} -> ${"%02x".format(block[i])}\n")
            }

            // L-преобразование
            L_transformation(block)
        }

        // финальный раунд (только xor)
        for (i in 0 until 16) {
            block[i] = block[i] xor roundKeys[9][i]
        }
    }

    // Соль для ключей
    fun generate_C(i: Int): ByteArray {
        val Ci = ByteArray(16)
        Ci[0] = i.toByte()
        L_transformation(Ci)
        return Ci
    }

    fun F(
        k1: ByteArray,
        k2: ByteArray,
        Ci: ByteArray): Pair<ByteArray, ByteArray> {
        var tmp = ByteArray(16)

        for (i in Ci.indices) {
            tmp[i] = k1[i] xor Ci[i]
        }

        tmp = s_box_transformation(tmp, PI)
        L_transformation(tmp)

        for (i in tmp.indices) {
            tmp[i] = tmp[i] xor k2[i]
        }

        return Pair(tmp, k1)
    }

    // Развёртка ключей
    fun generate_round_key() {
        // разбиваем мастер-ключ
        var k1 = cipherKey.copyOfRange(0, 16)
        var k2 = cipherKey.copyOfRange(16, 32)

        // сохраняем первые два раундовых ключа
        round_keys[0] = k1.copyOf()
        round_keys[1] = k2.copyOf()

        var roundIndex = 2

        // 32 итерации F
        for (i in 1..32) {
            val Ci = generate_C(i)
            val result = F(k1, k2, Ci)

            k1 = result.first
            k2 = result.second

            // каждые 8 итераций сохраняем ключи
            if (i % 8 == 0) {
                round_keys[roundIndex] = k1.copyOf()
                round_keys[roundIndex + 1] = k2.copyOf()
                roundIndex += 2
            }
        }
    }

    fun s_box_inverse(block: ByteArray) {
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

    fun r_inverse_transformation(block: ByteArray) {
        if (block.size != 16) {
            throw IllegalArgumentException("block must be 16 bytes")
        }

        val x = block[0]
        var s: Byte = 0

        val r_coefficient = byteArrayOf(
            148.toByte(), 32.toByte(), 133.toByte(), 16.toByte(),
            194.toByte(), 192.toByte(), 1.toByte(), 251.toByte(),
            1.toByte(), 192.toByte(), 194.toByte(), 16.toByte(),
            133.toByte(), 32.toByte(), 148.toByte(), 1.toByte()
        )

        for (i in 1 until 16) {
            s = s xor GF_multiplication(block[i], r_coefficient[i - 1])
        }

        val a15 = x xor s

        for (i in 0 until 15) {
            block[i] = block[i + 1]
        }

        block[15] = a15
    }

    fun l_inverse_transformation(block: ByteArray) {
        for (i in 0 until 16) {
            r_inverse_transformation(block)
        }
    }

    fun decrypt_block(block: ByteArray, roundKeys: Array<ByteArray>, view_logs: Boolean, writer: BufferedWriter? = null) {
        for (i in 0 until 16) {
            block[i] = block[i] xor roundKeys[9][i]
        }

        for (round in 8 downTo 0) {
            l_inverse_transformation(block)

            s_box_inverse(block)

            for (i in 15 downTo 0) {
                val save_last = block[i]
                block[i] = block[i] xor roundKeys[round][i]
                if (view_logs) println("decrypt with round-key №$round: ${"%02x".format(save_last)} -> ${"%02x".format(block[i])}")
                writer?.write("decrypt with round-key №$round: ${"%02x".format(save_last)} -> ${"%02x".format(block[i])}\n")
            }
        }
    }
}