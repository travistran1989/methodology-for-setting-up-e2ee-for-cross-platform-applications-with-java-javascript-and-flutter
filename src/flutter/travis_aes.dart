import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:pointycastle/block/aes_fast.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/padded_block_cipher/padded_block_cipher_impl.dart';
import 'package:pointycastle/paddings/pkcs7.dart';
import 'package:pointycastle/pointycastle.dart';

class TravisAES {
  static const int _keySize = 256;
  static const int _saltLength = _keySize ~/ 8;
  static const int _ivSize = 128;
  static const int _ivLength = _ivSize ~/ 8;
  static const int _iterationCount = 1989;
  DataTypeEnum _dataType = DataTypeEnum.base64;

  TravisAES();

  Uint8List _generateRandom(int length) {
    final secureRandom = math.Random.secure();
    final bytes = Uint8List(length);
    for (int i = 0; i < length; i++) {
      bytes[i] = secureRandom.nextInt(256);
    }
    return bytes;
  }

  PaddedBlockCipher _generateCipher(
      bool encryptMode, Uint8List key, Uint8List iv) {
    final blockCipher = CBCBlockCipher(AESFastEngine());
    final paddedCipher = PaddedBlockCipherImpl(PKCS7Padding(), blockCipher);
    paddedCipher.init(
      encryptMode,
      PaddedBlockCipherParameters(
          ParametersWithIV(KeyParameter(key), iv), null),
    );
    return paddedCipher;
  }

  KeyDerivator _generateKeyDerivator() {
    return PBKDF2KeyDerivator(HMac(SHA1Digest(), 64));
  }

  Uint8List _generateKey(String passphrase, String salt) {
    final keyDerivator = _generateKeyDerivator();
    keyDerivator
        .init(Pbkdf2Parameters(_fromHex(salt), _iterationCount, _keySize ~/ 8));
    return keyDerivator.process(utf8.encoder.convert(passphrase));
  }

  String encryptWithSalt(
      String salt, String iv, String passphrase, String plaintext) {
    final key = _generateKey(passphrase, salt);
    final cipher = _generateCipher(true, key, _fromHex(iv));
    final encrypted = cipher.process(utf8.encoder.convert(plaintext));
    if (_dataType == DataTypeEnum.hex) {
      return _toHex(encrypted);
    } else {
      return base64Encode(encrypted);
    }
  }

  String encrypt(String passphrase, String plaintext) {
    final salt = _toHex(_generateRandom(_saltLength));
    final iv = _toHex(_generateRandom(_ivLength));
    final cipherText = encryptWithSalt(salt, iv, passphrase, plaintext);
    return salt + iv + cipherText;
  }

  String decryptWithSalt(
      String salt, String iv, String passphrase, String cipherText) {
    final key = _generateKey(passphrase, salt);
    final cipher = _generateCipher(false, key, _fromHex(iv));
    final Uint8List encrypted;
    if (_dataType == DataTypeEnum.hex) {
      encrypted = _fromHex(cipherText);
    } else {
      encrypted = base64Decode(cipherText);
    }
    final decrypted = cipher.process(encrypted);
    return utf8.decode(decrypted);
  }

  String decrypt(String passphrase, String cipherText) {
    String salt = cipherText.substring(0, _saltLength * 2);
    String iv =
        cipherText.substring(_saltLength * 2, _saltLength * 2 + _ivLength * 2);
    String ct = cipherText.substring(_saltLength * 2 + _ivLength * 2);
    return decryptWithSalt(salt, iv, passphrase, ct);
  }

  String _toHex(Uint8List bytes) {
    return hex.encode(bytes);
  }

  Uint8List _fromHex(String hexString) {
    return Uint8List.fromList(hex.decode(hexString));
  }

  DataTypeEnum get dataType => _dataType;

  set dataType(DataTypeEnum dataType) => _dataType = dataType;
}

enum DataTypeEnum {
  hex,
  base64,
}
