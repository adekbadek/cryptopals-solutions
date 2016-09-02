const xor = require('bitwise-xor')
const aesjs = require('aes-js')

const set1 = require('./set1')

const PKCSPad = (buffer, length = 16) => {
  if (buffer.length >= length) {
    return buffer
  }

  const diff = length - buffer.length
  let diffBuffBytes = []
  for (var i = 0; i < diff; i++) {
    diffBuffBytes.push(`0x${(diff).toString(16)}`)
  }
  return Buffer.concat([buffer, Buffer.from(diffBuffBytes)])
}

//
// Challenge 15
//

// if the last byte is in range (0 - buff.length), then there's padding
const PKCSValidateAndUnPad = (buff) => {
  const padSize = buff[buff.length - 1]
  if (padSize >= buff.length) {
    return buff // there is no padding
  } else {
    // there is padding, let's validate
    Array.from(buff.slice(buff.length - padSize, buff.length)).reduce((previusValue, currentValue) => {
      if (previusValue !== currentValue) { throw new Error('invalid PKCS#7 padding') }
      return currentValue
    })
    return buff.slice(0, buff.length - padSize)
  }
}

// helper function, so that decryption/encryption funcs can take filePath of buffer
const parseInputFileORBuffer = (input, callback) => {
  if (typeof input === 'string') {
    set1.breakIntoBlocks(input, 16, 'base64', (chunksFromFile) => {
      callback(chunksFromFile)
    })
  } else if (input instanceof Buffer) {
    callback(input.length > 16 ? splitBuffer(input) : [PKCSPad(input)])
  } else {
    throw new Error('invalid input (must be filePath (String) or Buffer)')
  }
}

const decryptCBC = (input, key, iv, callback) => {
  const aes = new aesjs.AES(Buffer.from(key))

  parseInputFileORBuffer(input, (chunks) => {
    let plaintext = ''
    let lastBuffer = PKCSPad(iv)
    chunks.map((chunk) => {
      const currBuff = Buffer.from(chunk, 'base64')
      // 1. decrypt the current chunk
      const decryptedBytes = aes.decrypt(currBuff)
      // 2. xor the current with last (first time, the last is IV)
      const xored = xor(lastBuffer, decryptedBytes)
      // 3. update the last buffer
      lastBuffer = currBuff
      // 4. plaintext is XOR of lastBuffer and the decrypted bytes, unpad and return ASCII
      plaintext += PKCSValidateAndUnPad(Buffer.from(xored)).toString('ascii')
    })
    callback(plaintext)
  })
}

const encryptCBC = (input, key, iv, callback) => {
  const aes = new aesjs.AES(Buffer.from(key))

  parseInputFileORBuffer(input, (chunks) => {
    let ciphertext
    let lastBuffer = PKCSPad(iv)
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
    callback(ciphertext)
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
// Challenge 12 & 14
//

// code will work for both 12 and 14
// in 12, the paddingValue will be 0 (target-bytes sits in its own block)
// in 14, target-bytes will not end with cipherBuff length, there will (as long as randoms buffer is not divisible by 16) be padding after the bytes of target-bytes

const writeLine = (str) => {
  process.stdout.clearLine()
  process.stdout.cursorTo(0)
  process.stdout.write(str)
}

// just AES-128-ECB
const AES128ECB = (buffer, key, shouldEncrypt, callback) => {
  const aes = new aesjs.AES(key)
  let cipherBuff

  splitBuffer(buffer, 16).map((chunk, i) => {
    const currBuff = PKCSPad(Buffer.from(chunk, 'ascii'), 16)
    const encryptedBytes = shouldEncrypt ? aes.encrypt(currBuff) : aes.decrypt(currBuff)
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

// just wrapper around AES128ECB, just first appends bytes from secretBuff
// ch14: and prepends random number of random bytes
// random, but same over calls (so padding stays the same)
const AES128ECBPlusBuff = (key, randoms, buffer, secretBuff, callback) => {
  let toConcat = randoms ? [randoms, buffer, secretBuff] : [buffer, secretBuff]
  AES128ECB(Buffer.concat(toConcat), key, true, (cipherBuff) => {
    callback(cipherBuff)
  })
}

const tryEveryByte = (key, randoms, sameByteVal, i, sameByteBuffPrepend, secretBuff, oneByteShortInputFirstBlock, callback) => {
  const buffToEncrypt = Buffer.concat([
    sameByteBuff(sameByteVal, sameByteBuffPrepend),
    sameByteBuff(sameByteVal, 15),
    Buffer.from([i])
  ])

  AES128ECBPlusBuff(key, randoms, buffToEncrypt, secretBuff, (cipherBuff) => {
    if (Array.from(cipherBuff.slice(cipherBuff.length - 32, cipherBuff.length - 16)).toString() === oneByteShortInputFirstBlock.toString()) {
      callback(i, sameByteBuffPrepend)
    }
  })
}

// try every possible byte value (0-255)
const tryEveryLastByte = (paddingValue, randoms, sameByteVal, key, secretBuff, oneByteShortInputFirstBlock, callback) => {
  for (var i = 0; i < 255; i++) {
    // encrypt a block of 15 same values and 1 of value i
    if (paddingValue) {
      tryEveryByte(key, randoms, sameByteVal, i, paddingValue, secretBuff, oneByteShortInputFirstBlock, (i, paddingValue) => {
        callback(i, paddingValue)
      })
    } else {
      for (var sameByteBuffPrepends = 0; sameByteBuffPrepends < 15; sameByteBuffPrepends++) {
        tryEveryByte(key, randoms, sameByteVal, i, sameByteBuffPrepends, secretBuff, oneByteShortInputFirstBlock, (i, sameByteBuffPrepends) => {
          callback(i, sameByteBuffPrepends)
        })
      }
    }
  }
}

const decryptAES128ECBPlusBuff = (key, randoms, sameByteVal, mostSecretBuff, paddingValue, callback) => {
  // const key = randomBuffer()
  let decodedMsg = ''

  // for evert byte in mostSecretBuff
  const bytesLength = Array.from(mostSecretBuff).length
  for (var i = 0; i < bytesLength; i++) {
  // for (var i = 0; i < 1; i++) {
    // only the first block of mostSecretBuff's bytes is needed, the first byte of this block is what we're looking for
    const tmpSecretBuff = mostSecretBuff.slice(i, i + 16)
    let decodedMsgChar = ''

    writeLine(`check  ${Math.floor(i / bytesLength * 100)}%  (${i}/${bytesLength})`)

    // prepend bytes (one by one) to sameByteBuff to fill it so it's not padded

    // 1st step: get the value of byte '0x01' (effect of padding a one-byte-short block) AES'd against key (?)

    const toPrepend = Buffer.concat([
      sameByteBuff(sameByteVal, paddingValue), // ch14 - padding offset, for ch12 it's empty buffer
      sameByteBuff(sameByteVal, 15)
    ])
    AES128ECBPlusBuff(key, randoms, toPrepend, tmpSecretBuff, (cipherBuff) => {
      // last block is part of secretBuff + (1 - 15) bytes of padding
      // second-to-last block - the 'attacker-controlled' (last is the secretBuff)

      let oneByteShortInputFirstBlock = Array.from(cipherBuff.slice(cipherBuff.length - 32, cipherBuff.length - 16))

      // 2nd step: find the first byte of secretBuff
      tryEveryLastByte(paddingValue, randoms, sameByteVal, key, tmpSecretBuff, oneByteShortInputFirstBlock, (byteDecVal, paddingVal) => {
        if (byteDecVal !== sameByteVal) {
          decodedMsgChar = Buffer.from([byteDecVal]).toString('ascii')
        }
      })
    })

    writeLine('')
    decodedMsg += decodedMsgChar
  }

  callback(decodedMsg)
}

// NOTE not very DRY ^
const decryptAES128ECBPlusBuffGetPadding = (key, randoms, sameByteVal, mostSecretBuff, callback) => {
  const bytesLength = Array.from(mostSecretBuff).length
  let foundPaddingVal = false
  for (var i = 0; i < bytesLength; i++) {
    const tmpSecretBuff = mostSecretBuff.slice(i, i + 16)

    for (var sameByteBuffPrepends = 0; sameByteBuffPrepends < 15; sameByteBuffPrepends++) {
      if (!foundPaddingVal) {
        writeLine(`searching for padding size... ${sameByteBuffPrepends}`)
        const toPrepend = Buffer.concat([
          sameByteBuff(sameByteVal, sameByteBuffPrepends),
          sameByteBuff(sameByteVal, 15)
        ])
        AES128ECBPlusBuff(key, randoms, toPrepend, tmpSecretBuff, (cipherBuff) => {
          let oneByteShortInputFirstBlock = Array.from(cipherBuff.slice(cipherBuff.length - 32, cipherBuff.length - 16))

          // 2nd step: find the first byte of secretBuff
          tryEveryLastByte(null, randoms, sameByteVal, key, tmpSecretBuff, oneByteShortInputFirstBlock, (byteDecVal, paddingVal) => {
            if (byteDecVal !== sameByteVal) {
              // return here, padding is sameByteBuffPrepends
              foundPaddingVal = true
              writeLine('found!', paddingVal)
              callback(paddingVal)
            }
          })
        })
      }
    }
    writeLine('')
  }
}

//
// Challenge 13
//

const parseToObj = (str) => {
  const res = {}
  str.split('&').map((keyval) => { res[keyval.split('=')[0]] = keyval.split('=')[1] })
  return res
}

const parseToStr = (obj) => {
  let str = ''
  for (var key in obj) { str += `${key}=${obj[key]}&` }
  return str.replace(/&$/, '')
}

const profileFor = (email) => {
  return parseToStr({email: email.replace(/[=&]/g, ''), uid: 10, role: 'user'})
}

//
// Challenge 15
//

// if the last byte is in range (0 - buff.length), then there's padding
const PKCSValidateAndUnPad = (buff) => {
  const padSize = buff[buff.length - 1]
  if (padSize >= buff.length) {
    return buff // there is no padding
  } else {
    // there is padding, let's validate
    Array.from(buff.slice(buff.length - padSize, buff.length)).reduce((previusValue, currentValue) => {
      if (previusValue !== currentValue) { throw new Error('invalid PKCS#7 padding') }
      return currentValue
    })
    return buff.slice(0, buff.length - padSize)
  }
}

module.exports = {
  getRandomInt,
  PKCSPad,
  PKCSValidateAndUnPad,
  decryptCBC,
  encryptCBC,
  randomBuffer,
  splitBuffer,
  detectECB,
  AES128ECB,
  sameByteBuff,
  decryptAES128ECBPlusBuff,
  decryptAES128ECBPlusBuffGetPadding,
  parseToObj,
  profileFor
}
