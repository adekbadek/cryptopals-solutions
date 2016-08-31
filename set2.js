const xor = require('bitwise-xor')
const aesjs = require('aes-js')

const set1 = require('./set1')

const PKCSPad = (buffer, length) => {
  if (buffer.length >= length) {
    return buffer
  }

  const diff = length - buffer.length
  let diffBuffBytes = []
  for (var i = 0; i < diff; i++) {
    diffBuffBytes.push(`0x${diff}`)
  }
  return Buffer.concat([buffer, Buffer.from(diffBuffBytes)])
}

const decryptCBC = (filePath, key, iv, callback) => {
  const aes = new aesjs.AES(Buffer.from(key))

  set1.breakIntoBlocks(filePath, 16, 'base64', (chunks) => {
    let plaintext = ''
    let lastBuffer = iv
    chunks.map((chunk) => {
      const currBuff = Buffer.from(chunk, 'base64')
      // 1. decrypt the current chunk
      const decryptedBytes = aes.decrypt(currBuff)
      // 2. xor the current with last (first time, the last is IV)
      const xored = xor(lastBuffer, decryptedBytes)
      // 3. update the last buffer
      lastBuffer = currBuff
      // 4. plaintext is XOR of lastBuffer and the decrypted bytes
      plaintext += Buffer.from(xored).toString('ascii')
    })
    callback(plaintext)
  })
}

const encryptCBC = (filePath, key, iv, callback) => {
  const aes = new aesjs.AES(Buffer.from(key))

  set1.breakIntoBlocks(filePath, 16, 'ascii', (chunks) => {
    let ciphertext
    let lastBuffer = iv
    chunks.map((chunk, i) => {
      const currBuff = PKCSPad(Buffer.from(chunk, 'ascii'), 16)
      // 1. xor lastBuffer with plaintext (first time it's the IV)
      const xored = xor(lastBuffer, currBuff)
      // 2. encrypt that
      const encryptedBytes = aes.encrypt(xored)
      // 3. update lastBuffer
      lastBuffer = encryptedBytes
      // 4. update ciphertext
      ciphertext = i === 0 ? encryptedBytes : Buffer.concat([ciphertext, encryptedBytes])
    })
    callback(ciphertext.toString('base64'))
  })
}

//
// Challenge 11
//

const getRandomInt = (min, max) => {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

const randomBuffer = (length = 16) => {
  let buffer = []
  for (var i = 0; i < length; i++) {
    buffer.push(getRandomInt(0, 255))
  }
  return Buffer.from(buffer)
}

const splitBuffer = (buffer, chunkSize = 16) => {
  const chunks = []
  const byteArray = Array.from(buffer)
  while (byteArray.length > 0) { chunks.push(byteArray.splice(0, chunkSize)) }
  return chunks
}

const encryptAES128CBCECBRandomly = (filePath, callback) => {
  const aes = new aesjs.AES(randomBuffer())
  const mapping = {ECB: [], CBC: []}

  set1.readBytesFromFile(filePath, 'ascii', (file) => {
    // prepend and append bytes
    const fileBuff = Buffer.concat([
      randomBuffer(getRandomInt(5, 10)),
      Buffer.from(file, 'ascii'),
      randomBuffer(getRandomInt(5, 10))
    ])

    let cipherBuff

    // encrypt each chunk in ECB or CBC
    splitBuffer(fileBuff).map((chunk, i) => {
      const currBuff = PKCSPad(Buffer.from(chunk, 'ascii'), 16)
      const mode = Math.random() > 0.5 ? 'CBC' : 'ECB'
      mapping[mode].push(i)
      const encryptedBytes = mode === 'CBC' ? aes.encrypt(xor(randomBuffer(), currBuff)) : aes.encrypt(currBuff)

      cipherBuff = i === 0 ? encryptedBytes : Buffer.concat([cipherBuff, encryptedBytes])
    })

    callback(cipherBuff, mapping)
  })
}

// detects ECB in a buffer (searches for same blocks of blockSize in a given buffer)
const detectECB = (cipherBuff, blockSize = 16) => {
  const chunks = splitBuffer(cipherBuff, blockSize)

  const found = {}
  chunks.map((chunk1, i) => {
    chunks.map((chunk2, k) => {
      if (k !== i && found[i] !== k && found[k] !== i && Array.from(chunk1).toString() === Array.from(chunk2).toString()) { found[i] = k }
    })
  })
  return found
}

// encryptAES128CBCECBRandomly('aux/vanilla.txt', (cipherBuff, mapping) => {
//   const found = detectECB(cipherBuff)
//
//   for (let index in found) {
//     if (mapping.ECB.indexOf(parseInt(index)) >= 0) {
//       console.log(`chunks no. ${index}, ${found[index]} are definitely in ECB, rest is either CBC or ECB`)
//     }
//   }
// })

//
// Challenge 12
//

const encryptAES128ECB = (buffer, key, callback) => {
  const aes = new aesjs.AES(key)
  let cipherBuff

  splitBuffer(buffer, 16).map((chunk, i) => {
    const currBuff = PKCSPad(Buffer.from(chunk, 'ascii'), 16)
    const encryptedBytes = aes.encrypt(currBuff)
    cipherBuff = i === 0 ? encryptedBytes : Buffer.concat([cipherBuff, encryptedBytes])
  })

  callback(cipherBuff)
}

// create buffer that has size buffSize and every byte is of value byteVal
const sameByteBuff = (byteVal, buffSize) => {
  const byteArr = []
  for (var i = 0; i < buffSize; i++) { byteArr.push(byteVal) }
  return Buffer.from(byteArr)
}

// just wrapper around encryptAES128ECB, just first appends bytes from secretBuff
const encryptAES128ECBPlusBuff = (key, buffer, secretBuff, callback) => {
  encryptAES128ECB(Buffer.concat([buffer, secretBuff]), key, (cipherBuff) => {
    callback(cipherBuff)
  })
}

// try every possible byte value (0-255)
const tryEveryLastByte = (sameByteVal, key, secretBuff, oneByteShortInputFirstBlock, callback) => {
  for (var i = 0; i < 255; i++) {
    // encrypt a block of 15 same values and 1 of value i
    const buffToEncrypt = Buffer.concat([
      sameByteBuff(sameByteVal, 15),
      Buffer.from([i])
    ])

    encryptAES128ECBPlusBuff(key, buffToEncrypt, secretBuff, (cipherBuff) => {
      if (Array.from(cipherBuff.slice(0, 16)).toString() === oneByteShortInputFirstBlock.toString()) {
        callback(i)
      }
    })
  }
}

const decryptAES128ECB = (mostSecretBuff, callback) => {
  let decodedMsg = ''
  const key = randomBuffer()
  const sameByteVal = 65 // 'A' here, can by any byte val, it's just for consistency

  // for evert byte in mostSecretBuff
  for (var i = 0; i < Array.from(mostSecretBuff).length; i++) {
    const tmpSecretBuff = mostSecretBuff.slice(i, i + 16)

    // 1st step: get the value of byte '0x01' (effect of padding a one-byte-short block) AES'd against key (?)
    encryptAES128ECBPlusBuff(key, sameByteBuff(sameByteVal, 15), tmpSecretBuff, (cipherBuff) => {
      // this last missing byte will be the first byte of mostSecretBuff
      // 'output of the one-byte-short input':
      let oneByteShortInputFirstBlock = Array.from(cipherBuff.slice(0, 16))

      // 2nd step: find the first byte of secretBuff
      // only the first block of mostSecretBuff's bytes is needed, the first byte of this block is what we're looking for
      tryEveryLastByte(sameByteVal, key, tmpSecretBuff, oneByteShortInputFirstBlock, (byteDecVal) => {
        decodedMsg += Buffer.from([byteDecVal]).toString('ascii')
      })
    })
  }

  callback(decodedMsg)
}

module.exports = {
  PKCSPad,
  decryptCBC,
  encryptCBC,
  randomBuffer,
  splitBuffer,
  detectECB,
  encryptAES128ECB,
  decryptAES128ECB
}
