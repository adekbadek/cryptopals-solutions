const PKCSPad = (buffer, length) => {
  if (buffer.length >= length) {
    return 'invalid length'
  }

  const diff = length - buffer.length
  let diffBuffBytes = []
  for (var i = 0; i < diff; i++) {
    diffBuffBytes.push(`0x${diff}`)
  }
  return Buffer.concat([buffer, Buffer.from(diffBuffBytes)])
}

module.exports = {
  PKCSPad
}
