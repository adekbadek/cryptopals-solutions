const fs = require('fs')
const xor = require('bitwise-xor')
const leftPad = require('left-pad')

// encode message (hex or utf8) with key (ascii)
const encode = (input, key, encodings) => {
  const outputBuffArray = [] // array to collect results of xor
  const inputBuff = Buffer.from(input, encodings.inputEnc) // input as buffer
  const keyBuff = Buffer.from(key, 'ascii') // key as buffer, always ASCII

  // for each byte in input
  inputBuff.map((byte, i) => {
    // get hex values (and pad them)
    const val1 = leftPad(byte.toString(16), 2, 0)
    const val2 = leftPad(keyBuff[i % keyBuff.length].toString(16), 2, 0)

    // xor two buffers, each is a single byte - one from input, one from key
    // NOTE XORing - a lot like a lock mechanism (pins ⊕ key = alignment on shear line)
    let xored = xor(
      Buffer.from(val1, 'hex'),
      Buffer.from(val2, 'hex')
    ).toString('hex')

    // console.log(`${val1} ⊕ ${val2} = ${xored}`)

    outputBuffArray.push(`0x${xored}`) // format to hex
  })
  // create buffer from hex byte values in array and output as string
  return Buffer.from(outputBuffArray, 'hex').toString(encodings.outputEnc || 'ascii')
}

// score the string for english language letters frequency
const freqEngPerc = {'e': 12.702, 't': 9.056, 'a': 8.167, 'o': 7.507, 'i': 6.966, 'n': 6.749, 's': 6.327, 'h': 6.094, 'r': 5.987, 'd': 4.253, 'l': 4.025, 'c': 2.782, 'u': 2.758, 'm': 2.406, 'w': 2.361, 'f': 2.228, 'g': 2.015, 'y': 1.974, 'p': 1.929, 'b': 1.492, 'v': 0.978, 'k': 0.772, 'j': 0.153, 'x': 0.150, 'q': 0.095, 'z': 0.074}
const scoreString = (str) => {
  let score = 0
  str.split('').map((letter) => {
    letter = letter.toLowerCase()
    score += freqEngPerc[letter] === undefined ? 0 : freqEngPerc[letter]
    if (str.length > 10 && letter === ' ') {
      // extra points for spaces!
      score += 5
    }
  })
  return score
}

// from array of objects ({decoded: String, score: Number}), get x objects with highest scores (head of sorted array)
const getTheBest = (scoredStrings, howManyToReturn) => {
  return scoredStrings.sort((a, b) => { return b.score - a.score }).splice(0, howManyToReturn)
}

// for an encoded string, decode it using every letter and single digit as one-character key; return all possibilities along with a score of englishness
const getAllForSingleKeys = (endcodedString, encoding) => {
  let all = []

  // check against any byte value
  for (let i = 0; i < 255; i++) {
    let possibleKey = Buffer.from([i], 'ascii')
    let decoded = encode(endcodedString, possibleKey.toString('ascii'), {inputEnc: encoding})
    // let decoded = encode(endcodedString, possibleKey, {inputEnc: encoding}).replace(/[\x00-\x1F\x7F-\x9F]/g, "") // remove control chars
    all.push({
      decoded,
      key: possibleKey,
      score: scoreString(decoded)
    })

    // console.log(`${possibleKey} => ${decoded}`)
  }
  return all
}

// read file as bytes and pass it, encoded, to callback
const readBytesFromFile = (filePath, encoding, callback) => {
  fs.open(filePath, 'r', function (err, fd) {
    if (err) { return console.log(err.message) }
    const buffer = Buffer.alloc(99999)
    fs.read(fd, buffer, 0, 99999, 0, function (err, num) {
      if (err) { return err }
      callback(buffer.toString(encoding, 0, num))
    })
  })
}

// calculate Hamming distance (edit distance)
const calculateHammingDistance = (val1, val2) => {
  let distance = 0

  const buf1 = Buffer.from(val1)
  const buf2 = Buffer.from(val2)

  // compare each byte from val1 to corresponding byte in val2
  for (let i = 0; i < buf1.length; i++) {
    const binary1 = buf1[i].toString(2)
    const binary2 = buf2[i].toString(2)
    const maxLen = Math.max(binary1.length, binary2.length)
    xor(
      Buffer.from(leftPad(binary1, maxLen, 0), 'binary'),
      Buffer.from(leftPad(binary2, maxLen, 0), 'binary')
    ).toString('hex')
     .replace(/1/g, () => { distance += 1 }) // increase distance for each '1'
  }

  return distance
}

// https://dbjergaard.github.io/posts/matasano_set_1.html (no spoilers)
// NOTE if the key is 'ICE', then Hamming distance between first two occurences of key ('ICEICE') is 0. So, "when we find the hamming distance between parts of our cipher text using the correct key length, we are only finding the hamming distance between parts of the plain text" -> Choose the key length with smallest Hamming distance
// NOTE it won't be perfect, but correct keysize should be in first ~5 results
const findkeySize = (filePath, maxkeySize, callback) => {
  let possiblekeySizes = []
  readBytesFromFile(filePath, 'ascii', (file) => {
    const bytesArr = Array.from(Buffer.from(file, 'base64'))

    for (let i = 1; i < maxkeySize; i++) {
      const keySize = i + 1
      const toAverage = 6

      const chunks = []
      for (let j = 0; j < toAverage; j++) {
        chunks.push(bytesArr.slice(keySize * j, keySize * (j + 1)))
      }

      let hammings = 0
      for (let k = 0; k < toAverage - 1; k++) {
        hammings += calculateHammingDistance(Buffer.from(chunks[k], 'hex'), Buffer.from(chunks[k + 1], 'hex'))
      }

      possiblekeySizes.push({
        keySize,
        hammingAvg: (hammings / toAverage - 1) / keySize
      })
    }

    callback(possiblekeySizes.sort((a, b) => { return a.hammingAvg - b.hammingAvg }))
  })
}

// helper function for findKey
const breakIntoBlocksAndTranspose = (filePath, blockSize, encoding, callback) => {
  readBytesFromFile(filePath, 'ascii', (file) => {
    let transposed = []

    // raw bytes as array of unsigned integers (decimal)
    const byteArray = Array.from(Buffer.from(file, encoding))

    // split these bytes into chunks of blockSize length
    const chunkArrays = []
    while (byteArray.length > 0) {
      chunkArrays.push(byteArray.splice(0, blockSize))
    }

    // transpose - "make a block that is the first byte of every block, and a block that is the second byte of every block, and so on."
    chunkArrays.map((chunk) => {
      const byteArr = Array.from(Buffer.from(chunk, encoding))

      byteArr.map((byte, ind) => {
        if (transposed[ind] === undefined) {
          transposed[ind] = [byteArr[ind]]
        } else {
          transposed[ind].push(byteArr[ind])
        }
      })
    })

    // convert arrays of bytes into buffers
    transposed.map((tr, i) => {
      transposed[i] = Buffer.from(tr)
    })

    // returns array of buffers
    callback(transposed)
  })
}

const findKey = (filePath, keyLength, encoding, callback) => {
  breakIntoBlocksAndTranspose(filePath, keyLength, encoding, (transposed) => {
    let keyBytes = []

    transposed.map((buffer) => {
      const sortedOutput = getAllForSingleKeys(buffer.toString(encoding), encoding)
      const hexCode = getTheBest(sortedOutput, 1)[0].key.toString('hex')
      keyBytes.push(`0x${hexCode}`)
    })

    // returns key in ASCII
    callback(Buffer.from(keyBytes, 'ascii'))
  })
}

module.exports = {
  encode,
  scoreString,
  getTheBest,
  getAllForSingleKeys,
  readBytesFromFile,
  calculateHammingDistance,
  findkeySize,
  findKey
}
