const fs = require('fs')
const xor = require('bitwise-xor')
const leftPad = require('left-pad')

// decode ciphertext (hex) with key (ascii)
const decode = (ciphertext, key, encoding) => {
  let str = ''
  let i = 0
  // a char in hex string is represented by two symbols
  ciphertext.replace(/\w{2}/g, (charInHex) => {
    // decoding is xor'ing the ciphertext char against the key char
    // when we run out of key chars, start at key char of index 0
    const res = xor(
      new Buffer(charInHex, encoding),
      new Buffer(key[i % key.length].charCodeAt(0).toString(16), encoding)
    )
    const asDecimal = parseInt(res.toString('hex'), 16)
    str += String.fromCharCode(asDecimal)
    i++
  })
  return str
}

// encode meassage (hex or utf8) with key (ascii)
const encode = (message, key, inputFormat) => {
  let str = ''
  let i = 0
  let symbols = []
  if (inputFormat === 'hex') {
    // group by two characters
    message.replace(/\w{2}/g, (hexChar) => { symbols.push(hexChar) })
  } else if (inputFormat === 'utf8') {
    symbols = message.split('')
  }
  symbols.map((symbol) => {
    // console.log(symbol, symbol.charCodeAt(0))
    const currKey = key[i % key.length]
    const currChar = inputFormat === 'hex' ? symbol : symbol.charCodeAt(0).toString(16)
    str += xor(
      new Buffer(currChar, 'hex'),
      new Buffer(currKey.charCodeAt(0).toString(16), 'hex')
    ).toString('hex')
    i++
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
const getTheBest = (scoredStrings, howMany) => {
  let res = []
  scoredStrings.sort((a, b) => { return b.score - a.score })
  for (var i = 0; i < howMany; i++) {
    res.push(scoredStrings[i])
  }
  return res
}

// for an encoded string, decode it using every letter and single digit as one-character key; return all possibilities along with a score of englishness
const getAllForSingleKeys = (endcodedString, encoding) => {
  const possibleKeys = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
  // check against every key in A-B, 0-9 (hex)
  let all = []
  for (var i = 0; i < possibleKeys.length; i++) {
    let decoded = decode(endcodedString, possibleKeys[i], encoding)
    all.push({
      decoded,
      score: scoreString(decoded)
    })
  }
  return all
}

// read file as bytes and pass it, encoded, to callback
const readBytesFromFile = (filePath, encoding, callback) => {
  fs.open(filePath, 'r', function (err, fd) {
    if (err) { return console.log(err.message) }
    const buffer = new Buffer(2048)
    fs.read(fd, buffer, 0, 2048, 0, function (err, num) {
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
  decode,
  encode,
  scoreString,
  getTheBest,
  getAllForSingleKeys,
  readBytesFromFile,
  calculateHammingDistance
}
