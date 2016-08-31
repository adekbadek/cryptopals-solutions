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
  const aes = new aesjs.AES(Array.from(Buffer.from(key)))

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
  const aes = new aesjs.AES(Array.from(Buffer.from(key)))

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

module.exports = {
  PKCSPad,
  decryptCBC,
  encryptCBC
}
