const expect = require('chai').expect

describe('set 1', function () {
  const set1 = require('./set1')

  describe('challenge 1', function () {
    it('convert hex to base64', function () {
      let hexStr = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
      let base64Str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
      expect(Buffer.from(hexStr, 'hex').toString('base64')).to.equal(base64Str)
    })
  })

  describe('challenge 2', function () {
    it('produce XOR combination of two equal-length buffers', function () {
      const xor = require('bitwise-xor')
      const strHexA = '1c0111001f010100061a024b53535009181c'
      const strHexB = '686974207468652062756c6c277320657965'
      const result = xor(Buffer.from(strHexA, 'hex'), Buffer.from(strHexB, 'hex')).toString('hex')
      expect(result).to.equal('746865206b696420646f6e277420706c6179')
    })
  })

  describe('challenge 3', function () {
    it('break a single-byte XOR cipher (hex)', function () {
      const sortedOutput = set1.getAllForSingleKeys('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 'hex')
      const actual = set1.getTheBest(sortedOutput, 1)[0]
      expect(actual.decoded).to.equal(`Cooking MC's like a pound of bacon`)
    })
    it('break a single-byte XOR cipher (base64)', function () {
      const sortedOutput = set1.getAllForSingleKeys('OSo9Nm88Kiw9KjtvIio8PC4oKg', 'base64')
      const actual = set1.getTheBest(sortedOutput, 1)[0]
      expect(actual.decoded).to.equal('very secret message')
    })
  })

  describe('challenge 4', function () {
    it('detect single-character XOR', function (done) {
      this.timeout(20000)

      const https = require('https')

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
              let sorted = set1.getAllForSingleKeys(body[i], 'hex')
              let bestOne = set1.getTheBest(sorted, 1)[0]
              bestForEachLine.push(bestOne)
            }

            // get the best scores for the whole file
            let bestOfFile = set1.getTheBest(bestForEachLine, 1)
            expect(bestOfFile[0].decoded).to.equal('Now that the party is jumping\n')
            done()
          })
      })
    })
  })

  describe('challenge 5', function () {
    const testStr = 'Kuropatwa'
    const mostSecretKey = 'butter'
    const testEncHex = set1.encode(testStr, mostSecretKey, {inputEnc: 'ascii', outputEnc: 'hex'})
    const testEncBase64 = set1.encode(testStr, mostSecretKey, {inputEnc: 'ascii', outputEnc: 'base64'})
    it('encode message to hex', function () {
      expect(testEncHex).to.equal('2900061b1513160215')
    })
    it('decode ciphertext from hex', function () {
      expect(set1.encode(testEncHex, mostSecretKey, {inputEnc: 'hex'})).to.equal(testStr)
    })
    it('encode message to base64', function () {
      expect(testEncBase64).to.equal('KQAGGxUTFgIV')
    })
    it('decode ciphertext from base64', function () {
      expect(set1.encode(testEncBase64, mostSecretKey, {inputEnc: 'base64'})).to.equal(testStr)
    })
    it('implement a repeating-key  XOR', function (done) {
      const hexStrFromCryptopals = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
      set1.readBytesFromFile('aux/c5.txt', 'ascii', (fileContents) => {
        const encoded = set1.encode(fileContents, 'ICE', {inputEnc: 'ascii', outputEnc: 'hex'})
        expect(encoded).to.equal(hexStrFromCryptopals)
        done()
      })
    })
  })

  describe('challenge 6', function () {
    it('calculate Hamming distance', function () {
      expect(set1.calculateHammingDistance('this is a test', 'wokka wokka!!!')).to.equal(37)
    })
    it('find key size', function (done) {
      set1.findKeySize('aux/c6.txt', 40, (lengths) => {
        // keysize should be in first 5 results
        expect(lengths.slice(0, 5)).to.include({ keySize: 29, hammingAvg: 2.3275862068965516 })
        done()
      })
    })
    it('find key', function (done) {
      this.timeout(10000)
      let keySize = 29

      set1.findKey('aux/c6.txt', keySize, 'base64', (key) => {
        expect(key.toString('ascii')).to.equal(`Terminator X: Bring the noise`)
        done()
      })
    })
    it('decode repeating-key XOR ciphertext', function (done) {
      let key = 'Terminator X: Bring the noise'

      set1.readBytesFromFile('aux/c6.txt', 'ascii', (fileContents) => {
        const plaintext = set1.encode(fileContents, key, {inputEnc: 'base64'})
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

      set1.breakIntoBlocks('aux/c7.txt', 16, 'base64', (chunks) => {
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
      set1.readBytesFromFile('aux/c8.txt', 'ascii', (file) => {
        file.split('\n').map((line) => {
          if (set1.detectECB(Buffer.from(line, 'hex'))) {
            expect(line).to.equal('d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a')
          }
        })
        done()
      })
    })
  })
})

describe.only('set 2', function () {
  const set2 = require('./set2')

  describe('challenge 9', function () {
    it('Implement PKCS#7 padding', function () {
      expect(set2.PKCSPad(Buffer.from('YELLOW SUBMARINE'), 20).length).to.equal(20)
    })
  })

  describe('challenge 10', function () {
    const key = 'YELLOW SUBMARINE'
    // IV is 16 bytes of value 0
    const iv = set2.sameByteBuff(0, 16)

    it('decrypt AES in CBC mode - file', function () {
      set2.decryptCBC('aux/c10.txt', key, Buffer.from(iv), (result) => {
        expect(result.split('\n')[0]).to.equal(`I'm back and I'm ringin' the bell `)
      })
    })
    it('encrypt AES in CBC mode - file', function () {
      set2.encryptCBC('aux/vanilla.txt', key, Buffer.from(iv), (result) => {
        expect(result.toString('base64').substring(0, 60)).to.equal(`CRIwqt4+szDbqkNY+I0qbNXPg1XLaCM5etQ5Bt9DRFV/xIN2k8Go7jtArLIy`)
      })
    })
    it('encrypt AES in CBC mode - buffer', function () {
      set2.encryptCBC(Buffer.from('hello everyone', 'ascii'), key, iv, (cipher) => {
        expect(cipher.toString('base64')).to.equal('itkrUkWKow6len1YfrbKFg==')
      })
    })
    it('decrypt AES in CBC mode - buffer', function () {
      set2.decryptCBC(Buffer.from('itkrUkWKow6len1YfrbKFg==', 'base64'), key, iv, (plaintext) => {
        expect(plaintext.replace(/[^ -~]+/g, '')).to.equal('hello everyone')
      })
    })
  })

  describe('challenge 11', function () {
    it('create a buffer (of n length) of random bytes', function () {
      expect(set2.randomBuffer(16).length).to.equal(16)
    })
    it('split a buffer into chunks', function () {
      expect(set2.splitBuffer(set2.randomBuffer(32), 16).length).to.equal(2)
    })
    const plaintext = 'NOWSZE KRZYTYNKINOWSZE KRZYTYNKINOWSZE KRZYTYNKI'
    const key = 'YELLOW SUBMARINE'
    it('encrypt in AES-128-ECB', function () {
      set2.AES128ECB(Buffer.from(plaintext), Buffer.from(key), true, (cipherBuff) => {
        expect(cipherBuff.toString('base64')).to.equal('Qose4glninTcJP2rI6ip10KLHuIJZ4p03CT9qyOoqddCix7iCWeKdNwk/asjqKnX')
      })
    })
    it('detect ECB', function () {
      set2.AES128ECB(Buffer.from(plaintext), Buffer.from(key), true, (cipherBuff) => {
        expect(Object.keys(set2.detectECB(cipherBuff)).length).to.equal(2)
      })
    })
  })

  describe('challenge 12', function () {
    it('detect block size of encrypting function', function () {
      // detect block size
      // feed the function increasing amounts of bytes, when it produces more bytes than last time, that's a new block
      let size = 0
      let blockSize = 0
      for (var i = 1; i < 40; i++) {
        const byteArr = []
        for (var k = 0; k < i; k++) { byteArr.push('0x00') }
        set2.AES128ECB(Buffer.from(byteArr), set2.randomBuffer(), true, (cipherBuff) => {
          const newSize = Array.from(cipherBuff).length
          if (i !== 1 && size !== newSize) { blockSize = newSize - size }
          size = newSize
        })
      }
      expect(blockSize).to.equal(16)
    })
    // after ch14, this will take long time. Efficient func. in commits before 14.
    it.skip('byte-at-a-time ECB decryption', function (done) {
      this.timeout(100000)
      const randomBuff = false
      const sameByteVal = 0 // can by any byte val, it's just for consistency - but it can't be a byte that can appear in plaintext
      const key = set2.randomBuffer()
      const mostSecretBuff = Buffer.from('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK', 'base64')
      // set2.decryptAES128ECBPlusBuff(mostSecretBuff, (decrypt) => {
      set2.decryptAES128ECBPlusBuff(key, randomBuff, sameByteVal, mostSecretBuff, 0, (decrypt) => {
        expect(decrypt.split('\n')[0]).to.equal(`Rollin' in my 5.0`)
        done()
      })
    })
  })

  describe('challenge 13', function () {
    it('ECB cut-and-paste', function () {
      const key = set2.randomBuffer()

      // char from code 11
      let padding = ''
      for (var i = 0; i < 11; i++) { padding += String.fromCharCode(11) }

      // email=nice-usern|admin--PADDING--|ame&uid=10&role=|user
      const input = set2.profileFor(`nice-usernadmin${padding}ame`)

      set2.AES128ECB(Buffer.from(input, 'ascii'), key, true, (cipherBuff) => {
        const blocks = set2.splitBuffer(cipherBuff)

        // block tranposition and omission
        cipherBuff = Buffer.concat([
          Buffer.from(blocks[0]),
          Buffer.from(blocks[2]),
          Buffer.from(blocks[1])
        ])

        set2.AES128ECB(cipherBuff, key, false, (plaintextBuff) => {
          expect(set2.parseToObj(set2.PKCSValidateAndUnPad(plaintextBuff).toString('ascii')).role).to.equal('admin')
        })
      })
    })
  })

  // it may sometimes get randoms that fail test
  describe('challenge 14', function () {
    it('Byte-at-a-time ECB decryption (Harder)', function (done) {
      this.timeout(100000)

      // TODO sometimes looks for padding size indefinietely - maybe that's padding size 0?

      const randomBuff = set2.randomBuffer(set2.getRandomInt(5, 20))
      const sameByteVal = 0 // can by any byte val, it's just for consistency - but it can't be a byte that can appear in plaintext
      const mostSecretBuff = Buffer.from('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK', 'base64')
      const key = set2.randomBuffer()

      // first time to get the padding - just try every padding and see what returns a letter from target-bytes
      set2.decryptAES128ECBPlusBuffGetPadding(key, randomBuff, sameByteVal, mostSecretBuff, (padd) => {
        set2.decryptAES128ECBPlusBuff(key, randomBuff, sameByteVal, mostSecretBuff, padd, (decrypt) => {
          expect(decrypt.split('\n')[0]).to.equal(`Rollin' in my 5.0`)
          done()
        })
      })
    })
  })

  describe('challenge 15', function () {
    it('PKCS#7 padding validation', function () {
      expect(set2.PKCSValidateAndUnPad(Buffer.from([89, 98, 61, 4, 4, 4, 4])).toString('hex')).to.equal('59623d')
    })
  })

  describe('challenge 16', function () {
    it('CBC bitflipping attacks', function () {
      let padding = ''
      for (var i = 0; i < 4; i++) { padding += String.fromCharCode(4) }
      // can be anything, but must be target length of bytes + padding
      const INPUT_STRING = `oooooooooooo${padding}`.replace(/([;=])/g, '"$1"')

      // ---------------|---------------|---------------|---------------|---------------|
      //                |scrambled block|changed block
      // comment1=cooking%20MCs;userdata=oooooooooooooooo;comment2=%20like%20a%20pound%20of%20bacon

      const prepStr = 'comment1=cooking%20MCs;userdata='
      const appStr = ';comment2=%20like%20a%20pound%20of%20bacon'
      const config = {
        key: set2.randomBuffer(),
        iv: set2.sameByteBuff(0, 16),
        INPUT_BUFF: Buffer.from(`${prepStr}${INPUT_STRING}${appStr}`, 'ascii')
      }

      // first, detect how the bits have to be flipped
      const target = ';admin=true;'
      let flips = []
      for (var k = 0; k < target.length; k++) {
        set2.tryEveryFlip(config, target[k], k, flips)
      }

      // now for real, flip the bits and check if it's admin
      set2.flipBitsAndDecrypt(config, flips, null, (plaintext) => {
        expect(plaintext.indexOf(target) > 0).to.be.true
      })
    })
  })
})
