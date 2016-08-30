const https = require('https')
const xor = require('bitwise-xor')

const utils = require('./utils')

const expect = require('chai').expect

describe('challenge 1', function () {
  it('convert hex to base64', function () {
    let hexStr = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    let base64Str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    expect(Buffer.from(hexStr, 'hex').toString('base64')).to.equal(base64Str)
  })
})

describe('challenge 2', function () {
  it('produce XOR combination of two equal-length buffers', function () {
    const strHexA = '1c0111001f010100061a024b53535009181c'
    const strHexB = '686974207468652062756c6c277320657965'
    const result = xor(Buffer.from(strHexA, 'hex'), Buffer.from(strHexB, 'hex')).toString('hex')
    expect(result).to.equal('746865206b696420646f6e277420706c6179')
  })
})

describe('challenge 3', function () {
  it('break a single-byte XOR cipher (hex)', function () {
    const sortedOutput = utils.getAllForSingleKeys('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 'hex')
    const actual = utils.getTheBest(sortedOutput, 1)[0]
    expect(actual.decoded).to.equal(`Cooking MC's like a pound of bacon`)
  })
  it('break a single-byte XOR cipher (base64)', function () {
    const sortedOutput = utils.getAllForSingleKeys('OSo9Nm88Kiw9KjtvIio8PC4oKg', 'base64')
    const actual = utils.getTheBest(sortedOutput, 1)[0]
    expect(actual.decoded).to.equal('very secret message')
  })
})

describe.skip('challenge 4', function () {
  it('detect single-character XOR', function (done) {
    this.timeout(20000)

    https.get('https://cryptopals.com/static/challenge-data/4.txt', function (response) {
      let body = ''
      response
        .on('data', function (chunk) {
          body += chunk
        })
        .on('end', function (chunk) {
          body = body.split('\n')

          // for each line, collect best scored
          let bestForEachLine = []

          for (let i = 0; i < body.length; i++) {
            let sorted = utils.getAllForSingleKeys(body[i], 'hex')
            let bestOne = utils.getTheBest(sorted, 1)[0]
            bestForEachLine.push(bestOne)
          }

          // get the best scores for the whole file
          let bestOfFile = utils.getTheBest(bestForEachLine, 1)
          expect(bestOfFile[0].decoded).to.equal('Now that the party is jumping\n')
          done()
        })
    })
  })
})

describe('challenge 5', function () {
  const testStr = 'Kuropatwa'
  const mostSecretKey = 'butter'
  const testEncHex = utils.encode(testStr, mostSecretKey, {inputEnc: 'ascii', outputEnc: 'hex'})
  const testEncBase64 = utils.encode(testStr, mostSecretKey, {inputEnc: 'ascii', outputEnc: 'base64'})
  it('encode message to hex', function () {
    expect(testEncHex).to.equal('2900061b1513160215')
  })
  it('decode ciphertext from hex', function () {
    expect(utils.encode(testEncHex, mostSecretKey, {inputEnc: 'hex'})).to.equal(testStr)
  })
  it('encode message to base64', function () {
    expect(testEncBase64).to.equal('KQAGGxUTFgIV')
  })
  it('decode ciphertext from base64', function () {
    expect(utils.encode(testEncBase64, mostSecretKey, {inputEnc: 'base64'})).to.equal(testStr)
  })
  it('implement a repeating-key  XOR', function (done) {
    const hexStrFromCryptopals = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    utils.readBytesFromFile('aux/c5.txt', 'ascii', (fileContents) => {
      const encoded = utils.encode(fileContents, 'ICE', {inputEnc: 'ascii', outputEnc: 'hex'})
      expect(encoded).to.equal(hexStrFromCryptopals)
      done()
    })
  })
})

describe('challenge 6', function () {
  it('calculate Hamming distance', function () {
    expect(utils.calculateHammingDistance('this is a test', 'wokka wokka!!!')).to.equal(37)
  })
  it('find key size', function (done) {
    utils.findKeySize('aux/c6.txt', 40, (lengths) => {
      // keysize should be in first 5 results
      expect(lengths.slice(0, 5)).to.include({ keySize: 29, hammingAvg: 2.3275862068965516 })
      done()
    })
  })
  it('find key', function (done) {
    this.timeout(10000)
    let keySize = 29

    utils.findKey('aux/c6.txt', keySize, 'base64', (key) => {
      expect(key.toString('ascii')).to.equal(`Terminator X: Bring the noise`)
      done()
    })
  })
  it('decode repeating-key XOR ciphertext', function (done) {
    let key = 'Terminator X: Bring the noise'

    utils.readBytesFromFile('aux/c6.txt', 'ascii', (fileContents) => {
      const plaintext = utils.encode(fileContents, key, {inputEnc: 'base64'})
      expect(plaintext).to.contain(`I'm back and I'm ringin' the bell`)
      done()
    })
  })
})

describe('challenge 7', function () {
  // OpenSSL CLI:
  // $ openssl enc -aes-128-ecb -a -d -K "59454c4c4f57205355424d4152494e45" -in aux/c7.txt -out aux/plaintext.txt
  // where: -d = decrypt, -a = -base64, -K = key in hex is the next arg

  it('implement ECB mode for AES', function (done) {
    const aesjs = require('aes-js')

    const key = Array.from(Buffer.from('YELLOW SUBMARINE'))
    const aes = new aesjs.AES(key)

    utils.breakIntoBlocks('aux/c7.txt', 16, 'base64', (chunks) => {
      let plaintext = ''
      chunks.map((chunk) => {
        const decryptedBytes = aes.decrypt(Buffer.from(chunk, 'base64'))
        plaintext += Buffer.from(decryptedBytes).toString('ascii')
      })
      done()
      expect(plaintext.split('\n')[0]).to.equal(`I'm back and I'm ringin' the bell `)
    })
  })
})

describe('challenge 8', function () {
  it('detect AES in ECB mode', function (done) {
    utils.readBytesFromFile('aux/c8.txt', 'ascii', (file) => {
      file.split('\n').map((line) => {
        if (utils.detectECB(Buffer.from(line, 'hex'))) {
          expect(line).to.equal('d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a')
        }
      })
      done()
    })
  })
})
