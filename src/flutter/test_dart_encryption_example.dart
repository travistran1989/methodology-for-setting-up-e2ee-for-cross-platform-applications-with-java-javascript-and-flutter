import 'package:pointycastle/api.dart';
import 'package:test_dart_encryption/travis_aes.dart';
import 'package:test_dart_encryption/travis_rsa.dart';

void main() {
  testAes();
  // testRsa();
}

void testAes() {
  TravisAES aes = TravisAES();

  String passphrase = 'my-secret-passphrase';
  String plaintext = 'Dữ liệu UTF8';

  print('Original text: $plaintext');

  String encrypted = aes.encrypt(passphrase, plaintext);
  print('Encrypted text: $encrypted');

  String decrypted = aes.decrypt(passphrase, encrypted);
  print('Decrypted text: $decrypted');
}

void testRsa() {
  TravisRSA rsa = TravisRSA();
  // rsa.publicKey = Rsa.publicKeyFromBase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlOjkG2RjvfvLewejvhnn0O/QPE3+FX5KysMjsrL2JsSTWkAu8PPHq1y/OsEvS7pYJoW3/w4j6Hf2G256mytrRnRy9bAmyDLh44/9GytiuzldgcvVnkWVhwK+IfX6K2nyjlj6vlA9eEVgMjUV4p8PlkROSUHoJfoidb3QBKsqgcYJsrzRdzUqX6pyCvH2LnDGKlYYbfhNAqkflYeGygKNd3R9Nw+j4pmeebOhlmF6ysChx22CrJOpengk0rUcapn3ULRG4CVNLrDLNCh/3x68zVc09+AErAKfmAcW2lIlPHsaSkaigwomQuqZlokGII/U13bi1LSOHfw71mIcIgTFmwIDAQAB");
  String publicKey = TravisRSA.getBase64PublicKey(rsa.publicKey);
  print('Public Key: $publicKey');
  String privateKey = TravisRSA.getBase64PrivateKey(rsa.privateKey);
  print('Private Key: $privateKey');
  // PublicKey publicKey = rsa.publicKeyFromBase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlOjkG2RjvfvLewejvhnn0O/QPE3+FX5KysMjsrL2JsSTWkAu8PPHq1y/OsEvS7pYJoW3/w4j6Hf2G256mytrRnRy9bAmyDLh44/9GytiuzldgcvVnkWVhwK+IfX6K2nyjlj6vlA9eEVgMjUV4p8PlkROSUHoJfoidb3QBKsqgcYJsrzRdzUqX6pyCvH2LnDGKlYYbfhNAqkflYeGygKNd3R9Nw+j4pmeebOhlmF6ysChx22CrJOpengk0rUcapn3ULRG4CVNLrDLNCh/3x68zVc09+AErAKfmAcW2lIlPHsaSkaigwomQuqZlokGII/U13bi1LSOHfw71mIcIgTFmwIDAQAB");
  String plainText = 'my-secret-passphrase';
  String encrypted = rsa.encrypt(plainText);
  // String encrypted = rsa.encrypt(plainText, publicKey);
  print('Encrypted text: $encrypted');
  String decrypted = rsa.decrypt(encrypted);
  print('Decrypted text: $decrypted');
}
