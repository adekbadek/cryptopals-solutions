const fs = require('fs')
const xor = require('bitwise-xor')
const leftPad = require('left-pad')

// encode meassage (hex or utf8) with key (ascii)
const encode = (message, key, encodings) => {
  let str = ''
  let i = 0
  let bytes = []
  if (encodings.inputEnc !== 'ascii') {
    // hex and base64 'bytes' are 2 chars long
    bytes = message.match(/\w{2}/g)
  } else {
    bytes = message.split('')
  }
  bytes.map((symbol) => {
    // key is always ascii, so to XOR same encodings, turn symbol into ascii
    symbol = Buffer.from(symbol, encodings.inputEnc).toString('ascii')
    let xored = xor(
      symbol,
      key[i % key.length]
    ).toString(encodings.inputEnc === 'ascii' ? encodings.outputEnc : encodings.inputEnc).replace(/=/g, '')
    str += Buffer.from(xored, encodings.inputEnc).toString('ascii')
    i++

    // console.log(`${Buffer.from(symbol).toString(encodings.inputEnc === 'ascii' ? encodings.outputEnc : encodings.inputEnc).replace(/=/g, '')} (${symbol}) ⊕ ${Buffer.from(key[i % key.length]).toString('base64').replace(/=/g, '')} (${key[i % key.length]}) = ${xored}`)
  })
  return str
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

// calculate Hamming distance between two strings
const calculateHammingDistance = (str1, str2) => {
  let distance = 0
  str1.split('').map((char, i) => {
    let char1Bits = char.charCodeAt(0).toString(2)
    let char2Bits = str2[i].charCodeAt(0).toString(2)

    if (char1Bits.length < char2Bits.length) {
      char1Bits = leftPad(char1Bits, char2Bits.length, 0)
    }
    if (char1Bits.length > char2Bits.length) {
      char2Bits = leftPad(char2Bits, char1Bits.length, 0)
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
