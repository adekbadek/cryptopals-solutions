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
const getAllForSingleKeys = (endcodedString, encoding, possibleKeys = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890') => {
  // check against every key in A-B, 0-9 (hex)
  let all = []
  for (var i = 0; i < possibleKeys.length; i++) {
    let decoded = encode(endcodedString, possibleKeys[i], {inputEnc: encoding})
    all.push({
      decoded,
      key: possibleKeys[i],
      score: scoreString(decoded)
    })
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

// calculate Hamming distance
const calculateHammingDistance = (val1, val2) => {
  let distance = 0

  const buf1 = Buffer.from(val1)
  const buf2 = Buffer.from(val2)

  // compare each byte from val1 to corresponding byte in val2
  for (var i = 0; i < buf1.length; i++) {
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
    }

    xor(new Buffer(char1Bits, 'binary'), new Buffer(char2Bits, 'binary'))
      .toString('hex')
      .replace(/1/g, () => { distance += 1 }) // increase distance for each '1'
  })
  return distance
}

module.exports = {
  encode,
  scoreString,
  getTheBest,
  getAllForSingleKeys,
  readBytesFromFile,
  calculateHammingDistance
}
