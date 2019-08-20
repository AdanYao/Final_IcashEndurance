using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Web;
using ICP.KeyExchange.TestLibrary.Helpers;
using ICP.KeyExchange.TestLibrary.Models;
using LinqToExcel;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Data.OleDb;
using System.Data;


namespace ICP.KeyExchange.TestLibrary.Test


{

    [TestClass]
    public class CertificateApiTest
    {
        //  int i = 0;

        string post;
        string post1;
        string post11;
        string post2;
        string post21;
        string aeskeyiv;
        private readonly HttpClient _httpClient = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")
            //BaseAddress = new Uri("http://icp-member-beta.ecpay.com.tw/")
             BaseAddress = new Uri("https://icp-member-stage.ecpay.com.tw/")
            //  BaseAddress = new Uri("https://icp-member-beta.opay.tw/")
        };
        private readonly RsaCryptoHelper _rsaCryptoHelper = new RsaCryptoHelper();
        private readonly AesCryptoHelper _aesCryptoHelper = new AesCryptoHelper();

        private string _serverPublicKey = null;
        private string _clientPublicKey = null;
        private string _clientPrivateKey = null;
        private long _aesClientCertId = -1;
        private string _aesKey = null;
        private string _aesIv = null;

        [TestMethod]
        public void GetDefaultPucCert()
        {
            getDefaultPucCert();
        }

        [TestMethod]
        public void ExchangePucCert()
        {
            exchangePucCert();
        }

        [TestMethod]
        public void GenerateAES()
        {
            generateAES();
        }



        private (string Content, string Signature) callCertificateApi(string action, long certId, string serverPublicKey, string clientPrivateKey, object obj, string certHeaderName)
        {
            string json = JsonConvert.SerializeObject(obj);

            _rsaCryptoHelper.ImportPemPublicKey(serverPublicKey);
            string encData = _rsaCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(clientPrivateKey);
            //Console.WriteLine("CP1");
            //Console.WriteLine(clientPrivateKey);


            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            //Console.WriteLine("CP2");
            //Console.WriteLine(signature);

            //Console.WriteLine("CP3");
            //Console.WriteLine(encData);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);

            var content = new FormUrlEncodedContent(form);
            content.Headers.Add(certHeaderName, certId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
            //Console.WriteLine("X-iCP-S0");
            //Console.WriteLine(signature);

            var postResult = _httpClient.PostAsync(action, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;



            //Console.WriteLine("post1");
            //Console.WriteLine(postResult);


            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            string resultSignature = headerSignature.Value?.FirstOrDefault();

            //Console.WriteLine("X-iCP-S1");
            //Console.WriteLine(resultSignature);

            //Console.WriteLine("X-iCP-S1-1");
            //Console.WriteLine(stringResult);
            return (stringResult, resultSignature);



        }

        private void checkTimestamp(string timestamp)
        {
            if (!DateTime.TryParse(timestamp, out DateTime dt))
            {
                throw new Exception("Timestamp 有誤");
            }

            double subSec = DateTime.Now.Subtract(dt).TotalSeconds;
            if (subSec > 15 || subSec < -15)
            {
                throw new Exception("Timestamp 誤差過大");
            }
        }

        private (long CertId, string PublicKey) getDefaultPucCert()
        {
            string url = "/api/member/Certificate/GetDefaultPucCert";

            var postResult = _httpClient.PostAsync(url, null).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;

            Console.WriteLine($"回傳：{stringResult}");

            JObject jObj = JObject.Parse(stringResult);
            int rtnCode = jObj.Value<int>("RtnCode");
            Assert.AreEqual(1, rtnCode);

            long certId = jObj.Value<long>("DefaultPubCertID");
            string publicKey = jObj.Value<string>("DefaultPubCert");

            return (certId, publicKey);
        }

        private (ExchangePucCertResult Result, string ClientPrivateKey) exchangePucCert()
        {
            var getDefaultPucCertResult = getDefaultPucCert();

            var key = _rsaCryptoHelper.GeneratePemKey();
            var result = callCertificateApi("/api/member/Certificate/ExchangePucCert",
                                 getDefaultPucCertResult.CertId,
                                 getDefaultPucCertResult.PublicKey,


                                 key.PrivateKey,
                                 new ExchangePucCertRequest
                                 {
                                     ClientPubCert = key.PublicKey,
                                     Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                                 },
                                 "X-iCP-DefaultPubCertID");


            //Console.WriteLine("PUBC");
            //Console.WriteLine(key.PublicKey);



            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }

            _rsaCryptoHelper.ImportPemPrivateKey(key.PrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);

            var exchangePucCertResult = JsonConvert.DeserializeObject<ExchangePucCertResult>(json);

            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }

            checkTimestamp(exchangePucCertResult.Timestamp);

            _clientPrivateKey = key.PrivateKey;
            _clientPublicKey = key.PublicKey;
            _serverPublicKey = exchangePucCertResult.ServerPubCert;

            //Console.WriteLine("PUBC1");
            //Console.WriteLine(json);

            return (exchangePucCertResult, key.PrivateKey);
        }




        private void generateAES()
        {
            var exchangePucCertResult = exchangePucCert();
            var result = callCertificateApi("/api/member/Certificate/GenerateAES",
                                 exchangePucCertResult.Result.ServerPubCertID,
                                 exchangePucCertResult.Result.ServerPubCert,
                                 exchangePucCertResult.ClientPrivateKey,



            new BaseAuthorizationApiRequest
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
            },
                                 "X-iCP-ServerPubCertID");

            //Console.WriteLine("aescp");
            //Console.WriteLine(exchangePucCertResult.ClientPrivateKey);

            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }

            _rsaCryptoHelper.ImportPemPrivateKey(exchangePucCertResult.ClientPrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);
            // if (i == 1)
            {
                aeskeyiv = aeskeyiv + json + '\n';

                using (StreamWriter writer = new StreamWriter("keyiv1.txt"))


                {
                    // writer.WriteLine("");

                    writer.WriteLine(aeskeyiv);

                }


            }
            //else if (i == 2)
            //{

            //    using (StreamWriter writer = new StreamWriter("keyiv2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        writer.WriteLine(json);

            //    }

            //}



            // Console.WriteLine("third result===================================================");
            //Console.WriteLine(json);

            var generateAesResult = JsonConvert.DeserializeObject<GenerateAesResult>(json);

            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.Result.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);

            //Console.WriteLine("isV");
            //Console.WriteLine(isValid);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            //Console.WriteLine("aespubk");
            //Console.WriteLine(_clientPublicKey);

            //Console.WriteLine("=======================================");
            //Console.WriteLine(_serverPublicKey);


            checkTimestamp(generateAesResult.Timestamp);

            _aesClientCertId = generateAesResult.EncKeyID;
            _aesKey = generateAesResult.AES_Key;
            _aesIv = generateAesResult.AES_IV;
        }

        private string callNormalApi(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            //Console.WriteLine("555555===================================================");
            //Console.WriteLine(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            //Console.WriteLine("fouth result==============================================");
            //Console.WriteLine(signature);
            // IDictionary<string, string> form = new Dictionary<string, string>();

            //form.Add("EncData", encData);
            //enc = enc+encData+','+'\n';

            //    using (StreamWriter writer = new StreamWriter("encall.txt"))


            //   {
            ////        // writer.WriteLine("");

            //        writer.WriteLine(enc);

            //    }

            // if (i == 1)
            // {

            // using (StreamWriter writer = new StreamWriter("enc1.txt"))



            // {
            // writer.WriteLine("");

            // writer.WriteLine(encData);

            //    }


            //}
            //else if (i == 2)
            //{

            //    using (StreamWriter writer = new StreamWriter("enc2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        writer.WriteLine(encData);

            //    }

            //}




            // Console.WriteLine("fivth result=================================================");
            // Console.WriteLine(encData);


            //  var content = new FormUrlEncodedContent(form);
            //content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            //content.Headers.Add("X-iCP-Signature", signature);

            string s = _aesClientCertId.ToString();

            string a = signature;
            // var postResult = _httpClient.PostAsync(url, content).Result;
            //  var postResult = _httpClient.PostAsync(url, content).Result;
            //            string stringResult = postResult.Content.ReadAsStringAsync().Result;

            post = post + s + ',' + a + ',' + encData + '\n';

            // using (StreamWriter writer = new StreamWriter("SetRegisterInfo2.txt"))


            //  using (StreamWriter writer = new StreamWriter("SendAuthSMS2.txt"))

            // using (StreamWriter writer = new StreamWriter("CheckRegisterAuthSMS2.txt"))
            using (StreamWriter writer = new StreamWriter("loginaccount2.txt"))





            {
                //        // writer.WriteLine("");

                writer.WriteLine(post);

            }



            //if (i == 1)
            //{

            //    using (StreamWriter writer = new StreamWriter("post1-1.txt"))



            //    {
            //        //writer.WriteLine("");

            //        //  writer.WriteLine(content.Headers);

            //        writer.WriteLine(s);

            //    }

            //    using (StreamWriter writer = new StreamWriter("post1-2.txt"))


            //    {
            //        //writer.WriteLine("");

            //        // writer.WriteLine(content.Headers);

            //        writer.WriteLine(a);

            //    }

            //}



            //Console.WriteLine("post2");
            //Console.WriteLine(content.Headers);

            //Console.WriteLine("X-iCP-S2");
            //Console.WriteLine(stringResult);

            // var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            //    string resultSignature = headerSignature.Value?.FirstOrDefault();
            // Console.WriteLine("X-iCP-S3");
            Console.WriteLine("X-iCP-123");
            return post;
            //   Console.WriteLine(resultSignature);

            // _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            //bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            //if (!isValid)
            //{
            //    throw new Exception("簽章驗證失敗");
            //}

            //JToken jToken = JToken.Parse(stringResult);
            //if (jToken["RtnCode"].Value<int>() != 1)
            //{
            //    throw new Exception(jToken["RtnMsg"].Value<string>());
            //}

            //decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());


            //var jObj = JObject.Parse(decryptContent);

            //string Timestamp = jObj.Value<string>("Timestamp");
            //Console.WriteLine("X-iCP-456");

            //checkTimestamp(Timestamp);

        }

        [TestMethod]
        private string callNormalApi2(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            //Console.WriteLine("555555===================================================");
            //Console.WriteLine(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            //Console.WriteLine("fouth result==============================================");
            //Console.WriteLine(signature);
            // IDictionary<string, string> form = new Dictionary<string, string>();

            //form.Add("EncData", encData);
            //enc = enc+encData+','+'\n';

            //    using (StreamWriter writer = new StreamWriter("encall.txt"))


            //   {
            ////        // writer.WriteLine("");

            //        writer.WriteLine(enc);

            //    }

            // if (i == 1)
            // {

            // using (StreamWriter writer = new StreamWriter("enc1.txt"))



            // {
            // writer.WriteLine("");

            // writer.WriteLine(encData);

            //    }


            //}
            //else if (i == 2)
            //{

            //    using (StreamWriter writer = new StreamWriter("enc2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        writer.WriteLine(encData);

            //    }

            //}




            // Console.WriteLine("fivth result=================================================");
            // Console.WriteLine(encData);


            //  var content = new FormUrlEncodedContent(form);
            //content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            //content.Headers.Add("X-iCP-Signature", signature);

            string s = _aesClientCertId.ToString();

            string a = signature;
            // var postResult = _httpClient.PostAsync(url, content).Result;
            //  var postResult = _httpClient.PostAsync(url, content).Result;
            //            string stringResult = postResult.Content.ReadAsStringAsync().Result;

            post1 = post1 + s + ',' + a + ',' + encData + '\n';

            // using (StreamWriter writer = new StreamWriter("SetRegisterInfo2.txt"))


            //  using (StreamWriter writer = new StreamWriter("SendAuthSMS2.txt"))

            // using (StreamWriter writer = new StreamWriter("CheckRegisterAuthSMS2.txt"))
            using (StreamWriter writer = new StreamWriter("loginaccount23.txt"))





            {
                //        // writer.WriteLine("");

                writer.WriteLine(post1);

            }



            //if (i == 1)
            //{

            //    using (StreamWriter writer = new StreamWriter("post1-1.txt"))



            //    {
            //        //writer.WriteLine("");

            //        //  writer.WriteLine(content.Headers);

            //        writer.WriteLine(s);

            //    }

            //    using (StreamWriter writer = new StreamWriter("post1-2.txt"))


            //    {
            //        //writer.WriteLine("");

            //        // writer.WriteLine(content.Headers);

            //        writer.WriteLine(a);

            //    }

            //}
            //else if (i == 2)
            //{
            //    using (StreamWriter writer = new StreamWriter("post2-1.txt"))


            //    {
            //        // writer.WriteLine("");

            //        //writer.WriteLine(content.Headers);


            //        writer.WriteLine(s);



            //        //writer.WriteLine(a);
            //    }
            //    using (StreamWriter writer = new StreamWriter("post2-2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        //writer.WriteLine(content.Headers);


            //        //writer.WriteLine(s);



            //        writer.WriteLine(a);
            //    }
            //}


            //Console.WriteLine("post2");
            //Console.WriteLine(content.Headers);

            //Console.WriteLine("X-iCP-S2");
            //Console.WriteLine(stringResult);

            // var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            //    string resultSignature = headerSignature.Value?.FirstOrDefault();
            // Console.WriteLine("X-iCP-S3");
            Console.WriteLine("X-iCP-123");
            return post1;
            //   Console.WriteLine(resultSignature);

            // _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            //bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            //if (!isValid)
            //{
            //    throw new Exception("簽章驗證失敗");
            //}

            //JToken jToken = JToken.Parse(stringResult);
            //if (jToken["RtnCode"].Value<int>() != 1)
            //{
            //    throw new Exception(jToken["RtnMsg"].Value<string>());
            //}

            //decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());


            //var jObj = JObject.Parse(decryptContent);

            //string Timestamp = jObj.Value<string>("Timestamp");
            //Console.WriteLine("X-iCP-456");

            //checkTimestamp(Timestamp);

        }

        private string callNormalApi11(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            //Console.WriteLine("555555===================================================");
            //Console.WriteLine(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            //Console.WriteLine("fouth result==============================================");
            //Console.WriteLine(signature);
            // IDictionary<string, string> form = new Dictionary<string, string>();

            //form.Add("EncData", encData);
            //enc = enc+encData+','+'\n';

            //    using (StreamWriter writer = new StreamWriter("encall.txt"))


            //   {
            ////        // writer.WriteLine("");

            //        writer.WriteLine(enc);

            //    }

            // if (i == 1)
            // {

            // using (StreamWriter writer = new StreamWriter("enc1.txt"))



            // {
            // writer.WriteLine("");

            // writer.WriteLine(encData);

            //    }


            //}
            //else if (i == 2)
            //{

            //    using (StreamWriter writer = new StreamWriter("enc2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        writer.WriteLine(encData);

            //    }

            //}




            // Console.WriteLine("fivth result=================================================");
            // Console.WriteLine(encData);


            //  var content = new FormUrlEncodedContent(form);
            //content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            //content.Headers.Add("X-iCP-Signature", signature);

            string s = _aesClientCertId.ToString();

            string a = signature;
            // var postResult = _httpClient.PostAsync(url, content).Result;
            //  var postResult = _httpClient.PostAsync(url, content).Result;
            //            string stringResult = postResult.Content.ReadAsStringAsync().Result;

            post21 = post21 + s + ',' + a + ',' + encData + '\n';

            // using (StreamWriter writer = new StreamWriter("SetRegisterInfo2.txt"))


            //  using (StreamWriter writer = new StreamWriter("SendAuthSMS2.txt"))

            // using (StreamWriter writer = new StreamWriter("CheckRegisterAuthSMS2.txt"))
            using (StreamWriter writer = new StreamWriter("loginaccount232.txt"))





            {
                //        // writer.WriteLine("");

                writer.WriteLine(post21);

            }



            //if (i == 1)
            //{

            //    using (StreamWriter writer = new StreamWriter("post1-1.txt"))



            //    {
            //        //writer.WriteLine("");

            //        //  writer.WriteLine(content.Headers);

            //        writer.WriteLine(s);

            //    }

            //    using (StreamWriter writer = new StreamWriter("post1-2.txt"))


            //    {
            //        //writer.WriteLine("");

            //        // writer.WriteLine(content.Headers);

            //        writer.WriteLine(a);

            //    }

            //}
            //else if (i == 2)
            //{
            //    using (StreamWriter writer = new StreamWriter("post2-1.txt"))


            //    {
            //        // writer.WriteLine("");

            //        //writer.WriteLine(content.Headers);


            //        writer.WriteLine(s);



            //        //writer.WriteLine(a);
            //    }
            //    using (StreamWriter writer = new StreamWriter("post2-2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        //writer.WriteLine(content.Headers);


            //        //writer.WriteLine(s);



            //        writer.WriteLine(a);
            //    }
            //}


            //Console.WriteLine("post2");
            //Console.WriteLine(content.Headers);

            //Console.WriteLine("X-iCP-S2");
            //Console.WriteLine(stringResult);

            // var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            //    string resultSignature = headerSignature.Value?.FirstOrDefault();
            // Console.WriteLine("X-iCP-S3");
            Console.WriteLine("X-iCP-123");
            return post21;
            //   Console.WriteLine(resultSignature);

            // _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            //bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            //if (!isValid)
            //{
            //    throw new Exception("簽章驗證失敗");
            //}

            //JToken jToken = JToken.Parse(stringResult);
            //if (jToken["RtnCode"].Value<int>() != 1)
            //{
            //    throw new Exception(jToken["RtnMsg"].Value<string>());
            //}

            //decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());


            //var jObj = JObject.Parse(decryptContent);

            //string Timestamp = jObj.Value<string>("Timestamp");
            //Console.WriteLine("X-iCP-456");

            //checkTimestamp(Timestamp);

        }


        private string callNormalApi21(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            //Console.WriteLine("555555===================================================");
            //Console.WriteLine(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            //Console.WriteLine("fouth result==============================================");
            //Console.WriteLine(signature);
            // IDictionary<string, string> form = new Dictionary<string, string>();

            //form.Add("EncData", encData);
            //enc = enc+encData+','+'\n';

            //    using (StreamWriter writer = new StreamWriter("encall.txt"))


            //   {
            ////        // writer.WriteLine("");

            //        writer.WriteLine(enc);

            //    }

            // if (i == 1)
            // {

            // using (StreamWriter writer = new StreamWriter("enc1.txt"))



            // {
            // writer.WriteLine("");

            // writer.WriteLine(encData);

            //    }


            //}
            //else if (i == 2)
            //{

            //    using (StreamWriter writer = new StreamWriter("enc2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        writer.WriteLine(encData);

            //    }

            //}




            // Console.WriteLine("fivth result=================================================");
            // Console.WriteLine(encData);


            //  var content = new FormUrlEncodedContent(form);
            //content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            //content.Headers.Add("X-iCP-Signature", signature);

            string s = _aesClientCertId.ToString();

            string a = signature;
            // var postResult = _httpClient.PostAsync(url, content).Result;
            //  var postResult = _httpClient.PostAsync(url, content).Result;
            //            string stringResult = postResult.Content.ReadAsStringAsync().Result;

            post11 = post11 + s + ',' + a + ',' + encData + '\n';

            // using (StreamWriter writer = new StreamWriter("SetRegisterInfo2.txt"))


            //  using (StreamWriter writer = new StreamWriter("SendAuthSMS2.txt"))

            // using (StreamWriter writer = new StreamWriter("CheckRegisterAuthSMS2.txt"))
            using (StreamWriter writer = new StreamWriter("loginaccount231.txt"))





            {
                //        // writer.WriteLine("");

                writer.WriteLine(post11);

            }



            //if (i == 1)
            //{

            //    using (StreamWriter writer = new StreamWriter("post1-1.txt"))



            //    {
            //        //writer.WriteLine("");

            //        //  writer.WriteLine(content.Headers);

            //        writer.WriteLine(s);

            //    }

            //    using (StreamWriter writer = new StreamWriter("post1-2.txt"))


            //    {
            //        //writer.WriteLine("");

            //        // writer.WriteLine(content.Headers);

            //        writer.WriteLine(a);

            //    }

            //}
            //else if (i == 2)
            //{
            //    using (StreamWriter writer = new StreamWriter("post2-1.txt"))


            //    {
            //        // writer.WriteLine("");

            //        //writer.WriteLine(content.Headers);


            //        writer.WriteLine(s);



            //        //writer.WriteLine(a);
            //    }
            //    using (StreamWriter writer = new StreamWriter("post2-2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        //writer.WriteLine(content.Headers);


            //        //writer.WriteLine(s);



            //        writer.WriteLine(a);
            //    }
            //}


            //Console.WriteLine("post2");
            //Console.WriteLine(content.Headers);

            //Console.WriteLine("X-iCP-S2");
            //Console.WriteLine(stringResult);

            // var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            //    string resultSignature = headerSignature.Value?.FirstOrDefault();
            // Console.WriteLine("X-iCP-S3");
            Console.WriteLine("X-iCP-123");
            return post11;
            //   Console.WriteLine(resultSignature);

            // _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            //bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            //if (!isValid)
            //{
            //    throw new Exception("簽章驗證失敗");
            //}

            //JToken jToken = JToken.Parse(stringResult);
            //if (jToken["RtnCode"].Value<int>() != 1)
            //{
            //    throw new Exception(jToken["RtnMsg"].Value<string>());
            //}

            //decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());


            //var jObj = JObject.Parse(decryptContent);

            //string Timestamp = jObj.Value<string>("Timestamp");
            //Console.WriteLine("X-iCP-456");

            //checkTimestamp(Timestamp);

        }

        private string callNormalApi3(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            //Console.WriteLine("555555===================================================");
            //Console.WriteLine(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            //Console.WriteLine("fouth result==============================================");
            //Console.WriteLine(signature);
            // IDictionary<string, string> form = new Dictionary<string, string>();

            //form.Add("EncData", encData);
            //enc = enc+encData+','+'\n';

            //    using (StreamWriter writer = new StreamWriter("encall.txt"))


            //   {
            ////        // writer.WriteLine("");

            //        writer.WriteLine(enc);

            //    }

            // if (i == 1)
            // {

            // using (StreamWriter writer = new StreamWriter("enc1.txt"))



            // {
            // writer.WriteLine("");

            // writer.WriteLine(encData);

            //    }


            //}
            //else if (i == 2)
            //{

            //    using (StreamWriter writer = new StreamWriter("enc2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        writer.WriteLine(encData);

            //    }

            //}




            // Console.WriteLine("fivth result=================================================");
            // Console.WriteLine(encData);


            //  var content = new FormUrlEncodedContent(form);
            //content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            //content.Headers.Add("X-iCP-Signature", signature);

            string s = _aesClientCertId.ToString();

            string a = signature;
            // var postResult = _httpClient.PostAsync(url, content).Result;
            //  var postResult = _httpClient.PostAsync(url, content).Result;
            //            string stringResult = postResult.Content.ReadAsStringAsync().Result;

            post2 = post2 + s + ',' + a + ',' + encData + '\n';

            // using (StreamWriter writer = new StreamWriter("SetRegisterInfo2.txt"))


            //  using (StreamWriter writer = new StreamWriter("SendAuthSMS2.txt"))

            // using (StreamWriter writer = new StreamWriter("CheckRegisterAuthSMS2.txt"))
            using (StreamWriter writer = new StreamWriter("loginaccount24.txt"))



            {
                //        // writer.WriteLine("");

                writer.WriteLine(post2);

            }



            //if (i == 1)
            //{

            //    using (StreamWriter writer = new StreamWriter("post1-1.txt"))



            //    {
            //        //writer.WriteLine("");

            //        //  writer.WriteLine(content.Headers);

            //        writer.WriteLine(s);

            //    }

            //    using (StreamWriter writer = new StreamWriter("post1-2.txt"))


            //    {
            //        //writer.WriteLine("");

            //        // writer.WriteLine(content.Headers);

            //        writer.WriteLine(a);

            //    }

            //}
            //else if (i == 2)
            //{
            //    using (StreamWriter writer = new StreamWriter("post2-1.txt"))


            //    {
            //        // writer.WriteLine("");

            //        //writer.WriteLine(content.Headers);


            //        writer.WriteLine(s);



            //        //writer.WriteLine(a);
            //    }
            //    using (StreamWriter writer = new StreamWriter("post2-2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        //writer.WriteLine(content.Headers);


            //        //writer.WriteLine(s);



            //        writer.WriteLine(a);
            //    }
            //}


            //Console.WriteLine("post2");
            //Console.WriteLine(content.Headers);

            //Console.WriteLine("X-iCP-S2");
            //Console.WriteLine(stringResult);

            // var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            //    string resultSignature = headerSignature.Value?.FirstOrDefault();
            // Console.WriteLine("X-iCP-S3");
            Console.WriteLine("X-iCP-124");
            return post2;
            //   Console.WriteLine(resultSignature);

            // _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            //bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            //if (!isValid)
            //{
            //    throw new Exception("簽章驗證失敗");
            //}

            //JToken jToken = JToken.Parse(stringResult);
            //if (jToken["RtnCode"].Value<int>() != 1)
            //{
            //    throw new Exception(jToken["RtnMsg"].Value<string>());
            //}

            //decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());


            //var jObj = JObject.Parse(decryptContent);

            //string Timestamp = jObj.Value<string>("Timestamp");
            //Console.WriteLine("X-iCP-456");

            //checkTimestamp(Timestamp);

        }




        public void GetCellphone()
        {

            int ta = 0;
            //for (i = 1; i <= 20; i++)
            //{

            //    generateAES();
            //    //  string url = "/api/member/MemberInfo/getCellphone";
            //    string url = "/api/Member/MemberInfo/UserCodeLogin";
            //    //  string url = "/api/Member/MemberInfo/SetRegisterInfo";
            //    //  string url = "/api/Member/MemberInfo/SendAuthSMS";
            //    // string url = "/api/Member/MemberInfo/CheckRegisterAuthSMS";


            //var request = new
            //{
            //    Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
            ////    AuthV = "115C5234523452F54235423B54235545"
            //AuthV = "905C3384838D4765A9591130A7B5D890"
            //};

            //for (int i = 0; i < 3; i++)
            //{

            //updategetToken0530110



            // Console.WriteLine("Test1111");


            ////設定讀取的Excel屬性
            string strCon = "Provider=Microsoft.Jet.OLEDB.4.0;" +

            //路徑(檔案讀取路徑)
            "Data Source=C:\\Test01S.xls;" +

            //選擇Excel版本
            //Excel 12.0 針對Excel 2010、2007版本(OLEDB.12.0)
            //Excel 8.0 針對Excel 97-2003版本(OLEDB.4.0)
            //Excel 5.0 針對Excel 97(OLEDB.4.0)
            "Extended Properties='Excel 8.0;" +

            //開頭是否為資料
            //若指定值為 Yes，代表 Excel 檔中的工作表第一列是欄位名稱，oleDB直接從第二列讀取
            //若指定值為 No，代表 Excel 檔中的工作表第一列就是資料了，沒有欄位名稱，oleDB直接從第一列讀取
            "HDR=NO;" +

            //IMEX=0 為「匯出模式」，能對檔案進行寫入的動作。
            //IMEX=1 為「匯入模式」，能對檔案進行讀取的動作。
            //IMEX=2 為「連結模式」，能對檔案進行讀取與寫入的動作。
            "IMEX=1'";



            /*步驟2：依照Excel的屬性及路徑開啟檔案*/

            //Excel路徑及相關資訊匯入
            OleDbConnection GetXLS = new OleDbConnection(strCon);

            //打開檔案
            GetXLS.Open();



            /*步驟3：搜尋此Excel的所有工作表，找到特定工作表進行讀檔，並將其資料存入List*/

            //搜尋xls的工作表(工作表名稱需要加$字串)
            DataTable Table = GetXLS.GetOleDbSchemaTable(OleDbSchemaGuid.Tables, null);

            //查詢此Excel所有的工作表名稱
            string SelectSheetName = "";
            foreach (DataRow row in Table.Rows)
            {
                //抓取Xls各個Sheet的名稱(+'$')-有的名稱需要加名稱''，有的不用
                SelectSheetName = (string)row["TABLE_NAME"];

                //工作表名稱有特殊字元、空格，需加'工作表名稱$'，ex：'Sheet_A$'
                //工作表名稱沒有特殊字元、空格，需加工作表名稱$，ex：SheetA$
                //所有工作表名稱為Sheet1，讀取此工作表的內容
                if (SelectSheetName == "SheetA$")
                {
                    //select 工作表名稱
                    OleDbCommand cmSheetA = new OleDbCommand(" SELECT * FROM [SheetA$] ", GetXLS);
                    OleDbDataReader drSheetA = cmSheetA.ExecuteReader();

                    //讀取工作表SheetA資料
                    List<string> ListSheetA = new List<string>();
                    int cnt = 0;

                    while (drSheetA.Read())
                    {

                        //for (i = 1; i <= 20; i++)
                        //{

                        generateAES();
                        //  string url = "/api/member/MemberInfo/getCellphone";
                        string url = "/api/Member/MemberInfo/UserCodeLogin";
                        // string url = "/api/Member/MemberInfo/SetRegisterInfo";
                        //  string url = "/api/Member/MemberInfo/SendAuthSMS";
                        // string url = "/api/Member/MemberInfo/CheckRegisterAuthSMS";
                        // string url = "app/Payment/CreateBarcode";
                        //工作表SheetA的資料存入List

                        //{Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

                        //    string AA =Convert.ToString(unixTimestamp);

                        //    string A1= "1000000000"+00001;

                        ListSheetA.Add(drSheetA[0].ToString());
                        ListSheetA.Add(drSheetA[1].ToString());
                        ListSheetA.Add(drSheetA[2].ToString());
                        ListSheetA.Add(drSheetA[3].ToString());
                        ListSheetA.Add(drSheetA[4].ToString());
                        ListSheetA.Add(drSheetA[5].ToString());

                        var request1 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                           // Timestamp = DateTime.Now.ToString("2019/07/23 10:25:00"),

                            LoginTokenID = ListSheetA[2],
                            // LoginTokenID = "B7EE967048284D9BB44315295F3C657D",

                            // AuthV = ListSheetA[0],
                            //CellPhone = "0"+ ListSheetA[1],
                            // AuthCode = "111111"
                            UserCode = ListSheetA[3],
                            UserPwd = "Aa1234"

                            // SMSAuthType = "1"
                        };
                        string decryptContent1 = null;
                        string response1 = callNormalApi(url, request1, ref decryptContent1);
                        using (StreamWriter writer = new StreamWriter("AuthIDNOLogin.txt"))
                        {
                            writer.WriteLine(response1);
                            writer.Dispose();
                        }

                       // for (int j1 = 0; j1 < 1000; j1++)


                       // {

                            //var request11 = new
                            //{
                            //    Timestamp = DateTime.Now.ToString("2019/06/26 17:21:00"),

                            //    // Timestamp = DateTime.Now.ToString("2019/06/20 15:30:00")
                            //    //Timestamp1 = j1
                            //    //Timestamp = DateTime.Now.ToString("2019/06/19 11:10:00"),
                            //    // LoginTokenID = ListSheetA[2],
                            //    // LoginTokenID = "B7EE967048284D9BB44315295F3C657D",

                            //    // AuthV = ListSheetA[0],

                            //    //CellPhone = "0"+ ListSheetA[1],
                            //    // AuthCode = "111111"
                            //    // UserCode = ListSheetA[3],
                            //    // UserPwd = "Aa1234"

                            //    // SMSAuthType = "1"
                            //};


                            //string decryptContent11 = null;
                            //string response11 = callNormalApi11(url, request11, ref decryptContent11);
                            //using (StreamWriter writer = new StreamWriter("important22.txt"))
                            //{

                            //    writer.WriteLine(response11);
                            //    writer.Dispose();


                            //}


                            var request2 = new
                            {
                                //Timestamp = DateTime.Now.ToString("2019/07/23 10:25:00"),
                                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                                CName ="李小強",
                                BirthDay = ("1989-01-01"),
                                NationalityID ="1206",
                                AreaID ="101010",
                                Address ="三重路19-2號5樓",
                               // Email ="test0625@ecpay.com.tw",
                                idno = ListSheetA[5],

                                issueDate = ("2011-06-10"),
                               issueLoc ="63000",
                                issueType ="3"
                                //Timestamp = DateTime.Now.ToString("2019/06/19 11:10:00"),
                                // LoginTokenID = ListSheetA[2],
                                // LoginTokenID = "B7EE967048284D9BB44315295F3C657D",

                                // AuthV = ListSheetA[0],

                                //CellPhone = "0"+ ListSheetA[1],
                                // AuthCode = "111111"
                                // UserCode = ListSheetA[3],
                                // UserPwd = "Aa1234"

                                // SMSAuthType = "1"
                            };


                            string decryptContent2 = null;
                            string response2 = callNormalApi2(url, request2, ref decryptContent2);
                            using (StreamWriter writer = new StreamWriter("AuthIDNO.txt"))
                            {

                                writer.WriteLine(response2);
                                writer.Dispose();


                            }


                            //var request21 = new
                            //{
                            //    Timestamp = DateTime.Now.ToString("2019/06/26 15:28:00"),
                            //    TopUpSwitch ="1"

                            //    // Timestamp = DateTime.Now.ToString("2019/06/20 15:30:00")
                            //    //Timestamp1 = j1
                            //    //Timestamp = DateTime.Now.ToString("2019/06/19 11:10:00"),
                            //    // LoginTokenID = ListSheetA[2],
                            //    // LoginTokenID = "B7EE967048284D9BB44315295F3C657D",

                            //    // AuthV = ListSheetA[0],

                            //    //CellPhone = "0"+ ListSheetA[1],
                            //    // AuthCode = "111111"
                            //    // UserCode = ListSheetA[3],
                            //    // UserPwd = "Aa1234"

                            //    // SMSAuthType = "1"
                            //};


                            //string decryptContent21 = null;
                            //string response21 = callNormalApi21(url, request21, ref decryptContent21);
                            //using (StreamWriter writer = new StreamWriter("important23.txt"))
                            //{

                            //    writer.WriteLine(response21);
                            //    writer.Dispose();


                            //}

                            //    Console.WriteLine(j1);


                            // }



                            //for (int j2 = 0; j2 < 100; j2++)

                           // {
                                //var request3 = new
                                //{
                                //    Timestamp = DateTime.Now.ToString("2019/06/26 17:21:00"),
                                //    //BankCode = "007",
                                //     Amount = "1000"
                                //    //  PaymentType = "1",
                                //    //  PayID = "11681911000033036"
                                //    // Timestamp = DateTime.Now.ToString("2019/06/20 15:30:00")

                                //    //Timestamp = DateTime.Now.ToString("2019/06/19 11:10:00"),
                                //    // LoginTokenID = ListSheetA[2],
                                //    // LoginTokenID = "B7EE967048284D9BB44315295F3C657D",

                                //    // AuthV = ListSheetA[0],

                                //    //CellPhone = "0"+ ListSheetA[1],
                                //    // AuthCode = "111111"
                                //    // UserCode = ListSheetA[3],
                                //    // UserPwd = "Aa1234"

                                //    // SMSAuthType = "1"
                                //};


                                //string decryptContent3 = null;
                                //string response3 = callNormalApi3(url, request3, ref decryptContent3);


                                //using (StreamWriter writer = new StreamWriter("important33.txt"))
                                //{
                                //    writer.WriteLine(response3);
                                //    writer.Dispose();

                                //}

                               // Console.WriteLine(j1);


                            //}
                        //}

                            //string test = _rsaCryptoHelper.Decrypt(response);
                            //Console.WriteLine(test);



                            //StreamReader sr = new StreamReader("300020190603.csv");

                            //string line;
                            //while ((line = sr.ReadLine()) != null)
                            //{

                            //    Console.WriteLine(line.ToString());

                            //}

                            //using (StreamWriter sw = new StreamWriter("importall.txt"))
                            //{
                            //    sw.WriteLine(response1);
                            //}


                            //using (StreamWriter writer = new StreamWriter("importantall.txt"))
                            //{
                            //    writer.WriteLine(response1);

                            //    //    //     //   writer.WriteLine(test);
                            //    }




                            //ListSheetA.Add(drSheetA[0].ToString());
                            //ListSheetA.Add(drSheetA[1].ToString());
                            //ListSheetA.Add(drSheetA[2].ToString());
                            //ListSheetA.Add(drSheetA[3].ToString());
                            //ListSheetA.Add(drSheetA[4].ToString());
                            // Console.WriteLine(ListSheetA[0]+" "+ListSheetA[1]+" "+ ListSheetA[2]+" "+ ListSheetA[3]+" "+ ListSheetA[4]);
                            using (StreamWriter writer = new StreamWriter("end.txt"))
                            {
                                writer.WriteLine(ListSheetA[0] + " " + "0" + ListSheetA[1] + " " + ListSheetA[2] + " " + ListSheetA[3] + " " + ListSheetA[4]+" "+ ListSheetA[5]);

                            }
                            ListSheetA.Clear();
                            cnt++;
                            ta++;
                            Console.WriteLine(ta);

                        }
                        //Console.WriteLine(ListSheetA[1]);
                        /*步驟4：關閉檔案*/
                        //結束關閉讀檔(必要，不關會有error)
                        drSheetA.Close();
                        GetXLS.Close();
                        Console.ReadLine();
                    }
                }
                //if (i == 1)


                //{
                //    //{Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

                //    //    string AA =Convert.ToString(unixTimestamp);

                //    //    string A1= "1000000000"+00001;


                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //        LoginTokenID = "E2E0F05D63824B13AE080B36B9CDB1CB",
                //        // LoginTokenID = "B7EE967048284D9BB44315295F3C657D",

                //        // AuthV = "110C5234523452F54235423B54235545",
                //        // AuthV = "1000000000"+AA,
                //        //  CellPhone = "0900000001",
                //        // AuthCode = "111111"
                //        UserCode = "adan00001",
                //        UserPwd = "Aa1234"


                //        // SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important1.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }

                //    //string test = _rsaCryptoHelper.Decrypt(response);
                //    //Console.WriteLine(test);



                //    //StreamReader sr = new StreamReader("300020190603.csv");

                //    //string line;
                //    //while ((line = sr.ReadLine()) != null)
                //    //{

                //    //    Console.WriteLine(line.ToString());

                //    //}

                //    using (StreamWriter sw = new StreamWriter("importall.txt"))
                //    {
                //        sw.WriteLine(response1);
                //    }
                //    //using (StreamWriter writer = new StreamWriter("importantall.txt"))
                //    //{
                //    //    writer.WriteLine(response1);

                //    //    //    //     //   writer.WriteLine(test);
                //    //    }



                //}


                //Console.WriteLine("second result==================================================");
                //Console.WriteLine(response);



            }










        }






    
}

