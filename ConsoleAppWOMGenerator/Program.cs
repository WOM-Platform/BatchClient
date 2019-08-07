using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using RestSharp;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleAppWOMGenerator {
    class Program {

        private static T LoadKeyFromFile<T>(string path) where T : class {
            using (var fstr = new FileStream(path, FileMode.Open)) {
                using (var sr = new StreamReader(fstr)) {
                    var reader = new PemReader(sr);
                    return reader.ReadObject() as T;
                }
            }
        }

        private static byte[] EncryptCore(byte[] payload, AsymmetricKeyParameter key) {
            var engine = new Pkcs1Encoding(new RsaEngine());
            engine.Init(true, key);

            int inBlockSize = engine.GetInputBlockSize();
            int outBlockSize = engine.GetOutputBlockSize();
            int blocks = (int)Math.Ceiling(payload.Length / (double)inBlockSize);
            int outputLength = 0;
            byte[] output = new byte[blocks * outBlockSize];
            for (int i = 0; i < blocks; ++i) {
                int offset = i * inBlockSize;
                int blockLength = Math.Min(inBlockSize, payload.Length - offset);
                var cryptoBlock = engine.ProcessBlock(payload, offset, blockLength);
                cryptoBlock.CopyTo(output, i * outBlockSize);
                outputLength += cryptoBlock.Length;
            }

            if (outputLength != output.Length) {
                // Rescale output array
                byte[] tmp = new byte[outputLength];
                Array.Copy(output, tmp, outputLength);
                output = tmp;
            }

            return output;
        }

        private static string Encrypt<T>(T payload, AsymmetricKeyParameter receiverPublicKey) {
            if (receiverPublicKey.IsPrivate) {
                throw new ArgumentException("Public key of receiver required for encryption", nameof(receiverPublicKey));
            }

            var payloadBytes = Encoding.UTF8.GetBytes(SimpleJson.SerializeObject(payload));
            var signedBytes = EncryptCore(payloadBytes, receiverPublicKey);

            return Convert.ToBase64String(signedBytes, Base64FormattingOptions.None);
        }

        private static byte[] DecryptCore(byte[] payload, AsymmetricKeyParameter key) {
            var engine = new Pkcs1Encoding(new RsaEngine());
            engine.Init(false, key);

            int inBlockSize = engine.GetInputBlockSize();
            int outBlockSize = engine.GetOutputBlockSize();
            int blocks = (int)Math.Ceiling(payload.Length / (double)inBlockSize);
            int outputLength = 0;
            byte[] output = new byte[blocks * outBlockSize];
            for (int i = 0; i < blocks; ++i) {
                int offset = i * inBlockSize;
                int blockLength = Math.Min(inBlockSize, payload.Length - offset);
                var cryptoBlock = engine.ProcessBlock(payload, offset, blockLength);
                cryptoBlock.CopyTo(output, i * outBlockSize);
                outputLength += cryptoBlock.Length;
            }

            if (outputLength != output.Length) {
                // Rescale output array
                byte[] tmp = new byte[outputLength];
                Array.Copy(output, tmp, outputLength);
                output = tmp;
            }

            return output;
        }

        private static T Decrypt<T>(string payload, AsymmetricKeyParameter receiverPrivateKey) {
            if (!receiverPrivateKey.IsPrivate) {
                throw new ArgumentException("Private key of receiver required for decryption", nameof(receiverPrivateKey));
            }

            var payloadBytes = Convert.FromBase64String(payload);
            var decryptedBytes = DecryptCore(payloadBytes, receiverPrivateKey);

            return SimpleJson.DeserializeObject<T>(Encoding.UTF8.GetString(decryptedBytes));
        }

        static int Main(string[] args) {
            Console.WriteLine("Hello World!");

            if(args.Length != 2) {
                Console.Error.WriteLine("EXE <privKey> <pubKey>");
                return 1;
            }

            var privKey = LoadKeyFromFile<AsymmetricCipherKeyPair>(args[0]).Private;
            var pubKey = LoadKeyFromFile<AsymmetricKeyParameter>(args[1]);

            (var otc, var pwd) = CreateGeneration(privKey, pubKey);

            Console.WriteLine("Voucher generation: {0}", otc);
            Console.WriteLine("Password: {0}", pwd);

            VerifyGeneration(otc, pubKey);

            return 0;
        }

        private static (Guid otc, string passwrd) CreateGeneration(AsymmetricKeyParameter privKey, AsymmetricKeyParameter pubKey) {
            var nonce = Guid.NewGuid().ToString("N");

            var payload = Encrypt(new VoucherCreatePayload.Content {
                SourceId = 2,
                Nonce = nonce,
                Vouchers = new VoucherCreatePayload.VoucherInfo[] {
                    new VoucherCreatePayload.VoucherInfo {
                        Aim = "H",
                        Count = 60,
                        Timestamp = new DateTime(2019, 08, 07, 21, 00, 00, DateTimeKind.Local).ToUniversalTime(),
                        Latitude = 43.676943,
                        Longitude = 12.6452312
                    }
                }
            }, pubKey);

            var client = new RestClient("http://dev.wom.social");
            var request = new RestRequest("/api/v1/voucher/create", Method.POST, DataFormat.Json);
            request.AddJsonBody(new VoucherCreatePayload {
                SourceId = 2,
                Nonce = nonce,
                Payload = payload
            });

            var response = client.Post<VoucherCreateResponse>(request);
            if(response.StatusCode != System.Net.HttpStatusCode.OK) {
                throw new InvalidOperationException();
            }
            var responsePayload = Decrypt<VoucherCreateResponse.Content>(response.Data.Payload, privKey);

            return (responsePayload.Otc, responsePayload.Password);
        }

        private static void VerifyGeneration(Guid otc, AsymmetricKeyParameter pubKey) {
            var payload = Encrypt(new VoucherVerifyPayload.Content {
                Otc = otc
            }, pubKey);

            var client = new RestClient("http://dev.wom.social");
            var request = new RestRequest("/api/v1/voucher/verify", Method.POST, DataFormat.Json);
            request.AddJsonBody(new VoucherVerifyPayload {
                Payload = payload
            });

            var response = client.Post(request);
            if(response.StatusCode != System.Net.HttpStatusCode.OK) {
                throw new InvalidOperationException();
            }
        }

    }
}
