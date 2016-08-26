const https = require('https')
const xor = require('bitwise-xor')

const utils = require('./utils')

const expect = require('chai').expect

describe('challenge 1', function () {
  it('convert hex to base64', function () {
    let hexStr = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    let base64Str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    expect(new Buffer(hexStr, 'hex').toString('base64')).to.equal(base64Str)
  })
})

describe('challenge 2', function () {
  it('produce XOR combination of two equal-length buffers', function () {
    const strHexA = '1c0111001f010100061a024b53535009181c'
    const strHexB = '686974207468652062756c6c277320657965'
    const result = xor(new Buffer(strHexA, 'hex'), new Buffer(strHexB, 'hex')).toString('hex')
    expect(result).to.equal('746865206b696420646f6e277420706c6179')
  })
})

describe('challenge 3', function () {
  it('break a single-byte XOR cipher', function () {
    const sortedOutput = utils.getAllForSingleKeys('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    const actual = utils.getTheBest(sortedOutput, 1)[0]
    expect(actual.decoded).to.equal(`Cooking MC's like a pound of bacon`)
  })
})

describe('challenge 4', function () {
  it('detect single-character XOR', function (done) {
    this.timeout(5000)

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

          for (var i = 0; i < body.length; i++) {
            let sorted = utils.getAllForSingleKeys(body[i])
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
  const testEnc = utils.encode(testStr, mostSecretKey, 'utf8')
  it('encode a message', function () {
    expect(testEnc).to.equal('2900061b1513160215')
  })
  it('decode a message', function () {
    expect(utils.decode(testEnc, mostSecretKey)).to.equal(testStr)
  })
  it('implement a repeating-key  XOR', function (done) {
    const hexStrFromCryptopals = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    utils.readBytesFromFile('aux/c5.txt', 'hex', (asHex) => {
      const encoded = utils.encode(asHex, 'ICE', 'hex')
      expect(encoded).to.equal(hexStrFromCryptopals)
      done()
    })
  })
})
