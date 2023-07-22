import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:convert/convert.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';

class TravisRSA {
  final int keySize;
  DataTypeEnum _dataType = DataTypeEnum.base64;
  ModeEnum _mode = ModeEnum.pkcs1;
  late PublicKey _publicKey;
  late PrivateKey _privateKey;

  TravisRSA({this.keySize = 2048}) {
    final keyPair = _generateKeyPair();
    _publicKey = keyPair.publicKey;
    _privateKey = keyPair.privateKey;
  }

  AsymmetricKeyPair<PublicKey, PrivateKey> _generateKeyPair() {
    final keyGen = RSAKeyGenerator()
      ..init(ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.parse('65537'), keySize, 64),
          _secureRandom()));
    return keyGen.generateKeyPair();
  }

  static SecureRandom _secureRandom() {
    final secureRandom = FortunaRandom();
    final random = Random.secure();
    final seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(random.nextInt(256));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  static String getBase64PublicKey(PublicKey publicKey) {
    final topLevel = ASN1Sequence();
    topLevel.add(ASN1Integer((publicKey as RSAPublicKey).modulus!));
    topLevel.add(ASN1Integer((publicKey as RSAPublicKey).exponent!));
    final data = topLevel.encodedBytes;
    return base64Encode(data);
  }

  static String getBase64PrivateKey(PrivateKey privateKey) {
    final rsaPrivateKey = privateKey as RSAPrivateKey;
    final topLevel = ASN1Sequence();
    topLevel.add(ASN1Integer(BigInt.from(0))); // Version
    topLevel.add(ASN1Integer(rsaPrivateKey.modulus!));
    topLevel.add(ASN1Integer(rsaPrivateKey.publicExponent!));
    topLevel.add(ASN1Integer(rsaPrivateKey.privateExponent!));
    topLevel.add(ASN1Integer(rsaPrivateKey.p!));
    topLevel.add(ASN1Integer(rsaPrivateKey.q!));
    final data = topLevel.encodedBytes;
    return base64Encode(data);
  }

  static PublicKey publicKeyFromBase64(String base64PublicKey) {
    final decodedBytes = base64Decode(base64PublicKey);
    final asn1Parser = ASN1Parser(decodedBytes);
    final topLevelSequence = asn1Parser.nextObject() as ASN1Sequence;
    final publicKeyBitString = topLevelSequence.elements[1] as ASN1BitString;
    final publicKeyBytes = publicKeyBitString.contentBytes();

    final publicKeyAsn = ASN1Parser(publicKeyBytes);
    final publicKeySequence = publicKeyAsn.nextObject() as ASN1Sequence;
    final modulus = publicKeySequence.elements[0] as ASN1Integer;
    final exponent = publicKeySequence.elements[1] as ASN1Integer;

    return RSAPublicKey(modulus.valueAsBigInteger as BigInt,
        exponent.valueAsBigInteger as BigInt);
  }

  static PrivateKey privateKeyFromBase64(String base64PrivateKey) {
    final decodedBytes = base64Decode(base64PrivateKey);
    final asn1Parser = ASN1Parser(decodedBytes);
    final topLevelSequence = asn1Parser.nextObject() as ASN1Sequence;
    final version = topLevelSequence.elements[0] as ASN1Integer;
    final modulus = topLevelSequence.elements[1] as ASN1Integer;
    final publicExponent = topLevelSequence.elements[2] as ASN1Integer;
    final privateExponent = topLevelSequence.elements[3] as ASN1Integer;
    final p = topLevelSequence.elements[4] as ASN1Integer;
    final q = topLevelSequence.elements[5] as ASN1Integer;
    final exp1 = topLevelSequence.elements[6] as ASN1Integer;
    final exp2 = topLevelSequence.elements[7] as ASN1Integer;
    final crtCoefficient = topLevelSequence.elements[8] as ASN1Integer;
    return RSAPrivateKey(
      modulus.valueAsBigInteger as BigInt,
      privateExponent.valueAsBigInteger as BigInt,
      p.valueAsBigInteger,
      q.valueAsBigInteger,
    );
  }

  getEncryptCipher() {
    if (_mode == ModeEnum.pkcs1) {
      return PKCS1Encoding(RSAEngine())
        ..init(
            true, PublicKeyParameter<RSAPublicKey>(publicKey as RSAPublicKey));
    } else {
      return OAEPEncoding(RSAEngine())
        ..init(
            true, PublicKeyParameter<RSAPublicKey>(publicKey as RSAPublicKey));
    }
  }

  Uint8List encryptByPublicKey(Uint8List plainText, PublicKey publicKey) {
    final cipher = getEncryptCipher();
    return cipher.process(plainText);
  }

  String encryptByPublicKeyGetByDataType(
      String plainText, PublicKey publicKey) {
    final cipherText =
        encryptByPublicKey(Uint8List.fromList(plainText.codeUnits), publicKey);
    if (_dataType == DataTypeEnum.base64) {
      return base64Encode(cipherText);
    } else {
      return _toHex(cipherText);
    }
  }

  String encryptByBase64PublicKey(String plainText, String base64PublicKey) {
    final publicKey = publicKeyFromBase64(base64PublicKey);
    return encryptByPublicKeyGetByDataType(plainText, publicKey);
  }

  String encrypt(String plainText) {
    return encryptByPublicKeyGetByDataType(plainText, _publicKey);
  }

  getDecryptCipher() {
    if (_mode == ModeEnum.pkcs1) {
      return PKCS1Encoding(RSAEngine())
        ..init(false,
            PrivateKeyParameter<RSAPrivateKey>(privateKey as RSAPrivateKey));
    } else {
      return OAEPEncoding(RSAEngine())
        ..init(false,
            PrivateKeyParameter<RSAPrivateKey>(privateKey as RSAPrivateKey));
    }
  }

  Uint8List decryptByPrivateKey(Uint8List cipherText, PrivateKey privateKey) {
    final cipher = getDecryptCipher();
    return cipher.process(cipherText);
  }

  String decryptByPrivateKeyAndDataType(
      String cipherText, PrivateKey privateKey) {
    final Uint8List decodedCipherText;
    if (_dataType == DataTypeEnum.base64) {
      decodedCipherText = base64Decode(cipherText);
    } else {
      decodedCipherText = _fromHex(cipherText);
    }
    return utf8.decode(decryptByPrivateKey(decodedCipherText, privateKey));
  }

  String decryptByBase64PrivateKeyAndDataType(
      String cipherText, String base64PrivateKey) {
    final privateKey = privateKeyFromBase64(base64PrivateKey);
    return decryptByPrivateKeyAndDataType(cipherText, privateKey);
  }

  String decrypt(String cipherText) {
    return decryptByPrivateKeyAndDataType(cipherText, _privateKey);
  }

  String _toHex(Uint8List bytes) {
    return hex.encode(bytes);
  }

  Uint8List _fromHex(String hexString) {
    return Uint8List.fromList(hex.decode(hexString));
  }

  PublicKey get publicKey => _publicKey;

  set publicKey(PublicKey value) => _publicKey = value;

  PrivateKey get privateKey => _privateKey;

  set privateKey(PrivateKey value) => _privateKey = value;

  DataTypeEnum get dataType => _dataType;

  set dataType(DataTypeEnum dataType) => _dataType = dataType;

  ModeEnum get mode => _mode;

  set mode(ModeEnum value) => _mode = value;
}

enum DataTypeEnum {
  hex,
  base64,
}

enum ModeEnum {
  pkcs1,
  oaep,
}
