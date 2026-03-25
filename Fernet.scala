/** 
  * Copyright 2026 Denis Shelemekh
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
  * https://www.apache.org/licenses/LICENSE-2.0
  * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
  * See the License for the specific language governing permissions and limitations under the License.
 */

package com.dshelem

import java.nio.{ByteBuffer, ByteOrder}
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.{Cipher, Mac}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

/**
 * Fernet Implementation (https://github.com/fernet/spec/blob/master/Spec.md)
 *
 * Token format:
 *   Version (1 byte) || Timestamp (8 byte, big-endian) || IV (16 byte) || Ciphertext (length varies) || HMAC (32 bytes)
 *
 * Fernet Key = 16 byte signing key + 16 byte encryption key, URL-safe Base64 encoded.
 */
object Fernet {

  private val Version: Byte = 0x80.toByte
  private val IvLength = 16
  private val HmacLength = 32
  private val BlockSize = 16

  // ======================= Key =======================

  case class FernetKey(signingKey: Array[Byte], encryptionKey: Array[Byte]) {
    require(signingKey.length == BlockSize, s"Signing key must be ${BlockSize} bytes")
    require(encryptionKey.length == BlockSize, s"Encryption key must be ${BlockSize} bytes")

    /** URL-safe Base64 serialization (Fernet standard) */
    private def serialise: String = {
      val combined = signingKey ++ encryptionKey
      Base64.getUrlEncoder.withoutPadding.encodeToString(combined)
    }

    override def toString: String = serialise
  }

  object FernetKey {
    /** Random key generation */
    def generate(): FernetKey = {
      val random = new SecureRandom()
      val signing = new Array[Byte](BlockSize)
      val encryption = new Array[Byte](BlockSize)
      random.nextBytes(signing)
      random.nextBytes(encryption)
      FernetKey(signing, encryption)
    }

    /** Key construction from URL-safe Base64 string */
    def fromString(encoded: String): FernetKey = {
      // Fernet specification allows for both padded and unpadded key
      val decoded = Base64.getUrlDecoder.decode(addPadding(encoded))
      require(decoded.length == 2 * BlockSize, s"Key must decode to ${2 * BlockSize} bytes, got ${decoded.length}")
      FernetKey(decoded.take(BlockSize), decoded.drop(BlockSize))
    }
  }

  // ======================= Токен =======================

  case class FernetToken(
                          version: Byte,
                          timestamp: Long,
                          iv: Array[Byte],
                          ciphertext: Array[Byte],
                          hmac: Array[Byte]
                        ) {
    /** Token serialization to URL-safe Base64 */
    private def serialise: String = {
      val buf = ByteBuffer.allocate(1 + 8 + IvLength + ciphertext.length + HmacLength)
      buf.order(ByteOrder.BIG_ENDIAN)
      buf.put(version)
      buf.putLong(timestamp)
      buf.put(iv)
      buf.put(ciphertext)
      buf.put(hmac)
      Base64.getUrlEncoder.withoutPadding.encodeToString(buf.array())
    }

    override def toString: String = serialise
  }

  object FernetToken {
    /** Token construction from URL-safe Base64 string */
    def fromString(encoded: String): FernetToken = {
      val decoded = Base64.getUrlDecoder.decode(addPadding(encoded))
      val buf = ByteBuffer.wrap(decoded)
      buf.order(ByteOrder.BIG_ENDIAN)

      val version = buf.get()
      val timestamp = buf.getLong()
      val iv = new Array[Byte](IvLength)
      buf.get(iv)

      val ciphertextLen = decoded.length - 1 - 8 - IvLength - HmacLength
      require(ciphertextLen > 0, "Invalid token: ciphertext is empty")
      val ciphertext = new Array[Byte](ciphertextLen)
      buf.get(ciphertext)

      val hmac = new Array[Byte](HmacLength)
      buf.get(hmac)

      FernetToken(version, timestamp, iv, ciphertext, hmac)
    }
  }

  // ======================= Encryption =======================

  def encrypt(key: FernetKey, plaintext: String): FernetToken = {
    val random = new SecureRandom()
    val iv = new Array[Byte](IvLength)
    random.nextBytes(iv)

    val timestamp = System.currentTimeMillis() / 1000L
    val plaintextBytes = plaintext.getBytes("UTF-8")

    // AES-128-CBC with PKCS7 padding
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = new SecretKeySpec(key.encryptionKey, "AES")
    val ivSpec = new IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
    val ciphertext = cipher.doFinal(plaintextBytes)

    // Build payload for HMAC: version || timestamp || iv || ciphertext
    val hmacPayload = buildHmacPayload(Version, timestamp, iv, ciphertext)
    val hmac = computeHmac(key.signingKey, hmacPayload)

    FernetToken(Version, timestamp, iv, ciphertext, hmac)
  }

  // ======================= Decryption =======================

  /**
   * Token decryption and verification.
   *
   * @param key        key Fernet
   * @param token      token (object or string)
   * @param ttlSeconds TTL in seconds (None - without TTL checking)
   * @return decrypted text
   */
  def decrypt(key: FernetKey, token: FernetToken, ttlSeconds: Option[Long] = None): String = {
    // 1. Version check
    if (token.version != Version) {
      throw new RuntimeException(s"Unsupported version: ${token.version}")
    }

    // 2. HMAC check
    val hmacPayload = buildHmacPayload(token.version, token.timestamp, token.iv, token.ciphertext)
    val expectedHmac = computeHmac(key.signingKey, hmacPayload)
    if (!java.security.MessageDigest.isEqual(expectedHmac, token.hmac))
      throw new RuntimeException(s"HMAC verification failed - token is corrupted or wrong key")

    // 3. TTL check
    ttlSeconds.foreach { ttl =>
      val age = System.currentTimeMillis() / 1000L - token.timestamp
      if (age > ttl)
        throw new RuntimeException(s"Token expired: age=${age}s, ttl=${ttl}s")
      if (age < 0)
        throw new RuntimeException("Token timestamp is in the future")
    }

    // 4. AES-128-CBC decryption
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val keySpec = new SecretKeySpec(key.encryptionKey, "AES")
    val ivSpec = new IvParameterSpec(token.iv)
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    val decrypted = cipher.doFinal(token.ciphertext)
    new String(decrypted, "UTF-8")
  }

  /** Comfortable overloading: takes token string */
  def decrypt(key: FernetKey, tokenString: String): String =
    decrypt(key, FernetToken.fromString(tokenString), None)

  def decrypt(key: FernetKey, tokenString: String, ttlSeconds: Long): String =
    decrypt(key, FernetToken.fromString(tokenString), Some(ttlSeconds))

  // ======================= Private methods =======================

  private def buildHmacPayload(version: Byte, timestamp: Long, iv: Array[Byte], ciphertext: Array[Byte]): Array[Byte] = {
    val buf = ByteBuffer.allocate(1 + 8 + IvLength + ciphertext.length)
    buf.order(ByteOrder.BIG_ENDIAN)
    buf.put(version)
    buf.putLong(timestamp)
    buf.put(iv)
    buf.put(ciphertext)
    buf.array()
  }

  private def computeHmac(signingKey: Array[Byte], data: Array[Byte]): Array[Byte] = {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(signingKey, "HmacSHA256"))
    mac.doFinal(data)
  }

  /** Adds Base64-padding '=' if required */
  private def addPadding(s: String): String = {
    val pad = (4 - s.length % 4) % 4
    s + ("=" * pad)
  }
}
