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

// Challenge 11
const encryptInAFunkyWay = (filePath, callback) => {
  const aes = new aesjs.AES(randomBuffer())
  const mapping = {ECB: [], CBC: []}

  set1.readBytesFromFile(filePath, 'ascii', (file) => {
    // prepend and append bytes
    const fileBuff = Buffer.concat([
      randomBuffer(getRandomInt(5, 10)),
      Buffer.from(file, 'ascii'),
      randomBuffer(getRandomInt(5, 10))
    ])

    const byteArray = Array.from(fileBuff)
    // split these bytes into chunks of length 16
    const chunks = []
    while (byteArray.length > 0) {
      chunks.push(byteArray.splice(0, 16))
    }

    let cipherBuff

    chunks.map((chunk, i) => {
      const currBuff = PKCSPad(Buffer.from(chunk, 'ascii'), 16)
      const mode = Math.random() > 0.5 ? 'CBC' : 'ECB'
      mapping[mode].push(i)
      const encryptedBytes = mode === 'CBC' ? aes.encrypt(xor(randomBuffer(), currBuff)) : aes.encrypt(currBuff)

      cipherBuff = i === 0 ? encryptedBytes : Buffer.concat([cipherBuff, encryptedBytes])
    })

    callback(cipherBuff, mapping)
  })
}

encryptInAFunkyWay('aux/vanilla.txt', (cipherBuff, mapping) => {
  const chunks = []
  const byteArray = Array.from(cipherBuff)
  while (byteArray.length > 0) { chunks.push(byteArray.splice(0, 16)) }
  const found = {}
  chunks.map((chunk1, i) => {
    chunks.map((chunk2, k) => {
      if (k !== i && found[i] !== k && found[k] !== i && Array.from(chunk1).toString() === Array.from(chunk2).toString()) { found[i] = k }
    })
  })
  for (var index in found) {
    if (mapping.ECB.indexOf(parseInt(index)) >= 0) {
      console.log(`chunks no. ${index}, ${found[index]} are definitely in ECB, rest is either CBC or ECB`)
    }
  }
})

module.exports = {
  PKCSPad,
  decryptCBC,
  encryptCBC
}
