namespace Authenticator.HttpModule
{
    #region using statements
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    #endregion
    /// <summary>
    /// crypto helper functions
    /// </summary>
    public static class CryptoHelper
    {
        /// <summary>
        /// The password hash.
        /// </summary>
        private const string PasswordHash = @"S@@@@";

        /// <summary>
        /// The salt key.
        /// </summary>
        private const string SaltKey = @"H####";

        /// <summary>
        /// The vi key.
        /// </summary>
        private const string ViKey = @"D@#@#@#";

        /// <summary>
        /// Encrypt plain 
        /// </summary>
        /// <param name="plaintext"></param>
        /// <returns> base64 string format, otherwise empty</returns>
        /// <exception cref="ArgumentNullException"><paramref /> is <see langword="null" />.</exception>
        /// <exception cref="EncoderFallbackException">A fallback occurred (see Character Encoding in the .NET Framework for complete explanation)-and-<see cref="P:System.Text.Encoding.EncoderFallback" /> is set to <see cref="T:System.Text.EncoderExceptionFallback" />.</exception>
        /// <exception cref="InvalidOperationException">This class is not compliant with the FIPS algorithm.</exception>
        /// <exception cref="ArgumentException">The specified salt size is smaller than 8 bytes or the iteration count is less than 1. </exception>
        /// <exception cref="ArgumentOutOfRangeException">The <paramref /> parameter is less than zero.-or- The <paramref /> parameter is less than zero. </exception>
        /// <exception cref="CryptographicException">The value of the <see cref="P:System.Security.Cryptography.SymmetricAlgorithm.Mode" /> property is not <see cref="F:System.Security.Cryptography.CipherMode.ECB" />, <see cref="F:System.Security.Cryptography.CipherMode.CBC" />, or <see cref="F:System.Security.Cryptography.CipherMode.CFB" />.</exception>
        /// <exception cref="NotSupportedException">The <see cref="T:System.Security.Cryptography.CryptoStreamMode" /> associated with current <see cref="T:System.Security.Cryptography.CryptoStream" /> object does not match the underlying stream.  For example, this exception is thrown when using <see cref="F:System.Security.Cryptography.CryptoStreamMode.Write" />  with an underlying stream that is read only.  </exception>
        /// <exception cref="OverflowException">The array is multidimensional and contains more than <see cref="F:System.Int32.MaxValue" /> elements.</exception>
        public static string Encrypt(string plaintext)
        {
            if (string.IsNullOrWhiteSpace(plaintext))
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            string base64String;
            using (var memoryStream = new MemoryStream())
            {
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.Zeros;

                    using (var keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)))
                    {
                        var encryptor = symmetricKey.CreateEncryptor(
                            keyBytes.GetBytes(256 / 8),
                            Encoding.ASCII.GetBytes(ViKey));

#pragma warning disable CC0022 // Should dispose object
                        var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
#pragma warning restore CC0022 // Should dispose object
                        var plainTextBytes = Encoding.UTF8.GetBytes(plaintext);
                        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                        //Flush the data out so it is fully written to the underlying stream.
                        cryptoStream.FlushFinalBlock();
                        base64String = Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }


            return base64String;
        }

        /// <summary>
        /// Decrypt the chiper text into plain text
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <returns>plaintext, otherwise empty </returns>
        /// <exception cref="ArgumentNullException"><paramref /> is <see langword="null" />.</exception>
        /// <exception cref="InvalidOperationException">This class is not compliant with the FIPS algorithm.</exception>
        /// <exception cref="ArgumentException">The specified salt size is smaller than 8 bytes or the iteration count is less than 1. </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///         <paramref />is out of range. This parameter requires a non-negative number.</exception>
        /// <exception cref="CryptographicException">The key is corrupt which can cause invalid padding to the stream. </exception>
        /// <exception cref="DecoderFallbackException">A fallback occurred (see Character Encoding in the .NET Framework for complete explanation)-and-<see cref="P:System.Text.Encoding.DecoderFallback" /> is set to <see cref="T:System.Text.DecoderExceptionFallback" />.</exception>
        /// <exception cref="NotSupportedException">The current stream is not writable.-or- The final block has already been transformed. </exception>
        /// <exception cref="EncoderFallbackException">A fallback occurred (see Character Encoding in the .NET Framework for complete explanation)-and-<see cref="P:System.Text.Encoding.EncoderFallback" /> is set to <see cref="T:System.Text.EncoderExceptionFallback" />.</exception>
        /// <exception cref="FormatException">The length of <paramref />, ignoring white-space characters, is not zero or a multiple of 4. -or-The format of <paramref /> is invalid. <paramref /> contains a non-base-64 character, more than two padding characters, or a non-white space-character among the padding characters.</exception>
        /// <exception cref="OverflowException">The array is multidimensional and contains more than <see cref="F:System.Int32.MaxValue" /> elements.</exception>
        public static string Decrypt(string encryptedText)
        {
            if (string.IsNullOrWhiteSpace(encryptedText))
            {
                throw new ArgumentNullException(nameof(encryptedText));
            }

            string plaintext;
            var cipherTextBytes = Convert.FromBase64String(encryptedText);
            using (var memoryStream = new MemoryStream(cipherTextBytes))
            {
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.None;

                    using (var keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)))
                    {
                        var decryptor = symmetricKey.CreateDecryptor(keyBytes.GetBytes(256 / 8), Encoding.ASCII.GetBytes(ViKey));
#pragma warning disable CC0022 // Should dispose object
                        var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
#pragma warning restore CC0022 // Should dispose object
                        var decryptedByteCount = cryptoStream.Read(cipherTextBytes, 0, cipherTextBytes.Length);
                        plaintext = Encoding.UTF8.GetString(memoryStream.ToArray(), 0, decryptedByteCount)
                                .TrimEnd(@" ".ToCharArray());
                    }
                }
            }
            return plaintext.Replace("\0", string.Empty);
        }
    }
}
