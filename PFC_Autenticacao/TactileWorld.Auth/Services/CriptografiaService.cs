using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TactileWorld.Auth.Services
{
    public class CriptografiaService
    {
        // Puxar a chave das variáveis de ambiente do sistema.
        // Se não encontrar, usar uma chave padrão forte.
        private readonly byte[] _chaveMestra;

        public CriptografiaService()
        {
            string chaveAmbiente = Environment.GetEnvironmentVariable("TACTILE_AES_KEY") 
                                   ?? "T4ct1l3W0rldCh4v3Ultr4S3cr3t4AES";
            
            // Garantir matematicamente que a chave tenha exatamente 32 bytes (256 bits) para o AES.
            _chaveMestra = Encoding.UTF8.GetBytes(chaveAmbiente.PadRight(32).Substring(0, 32));
        }

        public string Criptografar(string textoLimpo)
        {
            if (string.IsNullOrEmpty(textoLimpo)) return textoLimpo;

            using (Aes aes = Aes.Create())
            {
                aes.Key = _chaveMestra;
                aes.GenerateIV(); // Gerar um IV aleatório.
                byte[] iv = aes.IV;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    // Gravar o IV no início.
                    memoryStream.Write(iv, 0, iv.Length);

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(textoLimpo);
                        }
                    }
                    return Convert.ToBase64String(memoryStream.ToArray());
                }
            }
        }

        public string Descriptografar(string textoCriptografado)
        {
            if (string.IsNullOrEmpty(textoCriptografado)) return textoCriptografado;

            byte[] bufferCompleto = Convert.FromBase64String(textoCriptografado);

            using (Aes aes = Aes.Create())
            {
                aes.Key = _chaveMestra;

                // O IV do AES tem exatamente 16 bytes.
                byte[] iv = new byte[16];
                Array.Copy(bufferCompleto, 0, iv, 0, iv.Length);
                aes.IV = iv;

                // Ler o restante.
                using (MemoryStream memoryStream = new MemoryStream(bufferCompleto, iv.Length, bufferCompleto.Length - iv.Length))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}