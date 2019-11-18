using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Web;
using ICP.KeyExchange.TestLibrary.Helpers;
using ICP.KeyExchange.TestLibrary.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


namespace ICP.KeyExchange.TestLibrary.Test


{
    [TestClass]
    public class CertificateApiTest
    {
        int i = 0;
        string enc;
        private readonly HttpClient _httpClient = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")
          //  BaseAddress = new Uri("http://icp-member-beta.ecpay.com.tw/")
              //BaseAddress = new Uri("https://icp-member-stage.ecpay.com.tw/")
            BaseAddress = new Uri("https://icp-socket-stage.icashpay.com.tw")
            // BaseAddress = new Uri("https://icp-member-beta.opay.tw/")



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
            Console.WriteLine("CP1");
            Console.WriteLine(clientPrivateKey);


            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            Console.WriteLine("CP2");
            Console.WriteLine(signature);

            Console.WriteLine("CP3");
            Console.WriteLine(encData);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);

            var content = new FormUrlEncodedContent(form);
            content.Headers.Add(certHeaderName, certId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
            //Console.WriteLine("X-iCP-S0");
            //Console.WriteLine(signature);

            var postResult = _httpClient.PostAsync(action, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;



            Console.WriteLine("post1");
            Console.WriteLine(postResult);


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
            if (subSec > 30 || subSec < -30)
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


            Console.WriteLine("PUBC");
            Console.WriteLine(key.PublicKey);



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

            Console.WriteLine("PUBC1");
            Console.WriteLine(json);

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

            Console.WriteLine("aescp");
            Console.WriteLine(exchangePucCertResult.ClientPrivateKey);

            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }

            _rsaCryptoHelper.ImportPemPrivateKey(exchangePucCertResult.ClientPrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);
            if (i == 1)
            {

                using (StreamWriter writer = new StreamWriter("keyiv1.txt"))


                {
                    // writer.WriteLine("");

                    writer.WriteLine(json);

                }


            }
           

            var generateAesResult = JsonConvert.DeserializeObject<GenerateAesResult>(json);

            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.Result.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);

            //Console.WriteLine("isV");
            //Console.WriteLine(isValid);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            Console.WriteLine("aespubk");
            Console.WriteLine(_clientPublicKey);

            Console.WriteLine("=======================================");
            Console.WriteLine(_serverPublicKey);


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
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);
            // enc = enc+encData+',';

            //    using (StreamWriter writer = new StreamWriter("enc111.txt"))


            //   {
            ////        // writer.WriteLine("");

            //        writer.WriteLine(encData);

            //    }

            if (i == 1)
            {

                using (StreamWriter writer = new StreamWriter("enc1.txt"))



                {
                    writer.WriteLine("");

                    writer.WriteLine(encData);
                    //StreamReader sr = new StreamReader("all.txt");
                    //string line;
                    //while ((line = sr.ReadLine()) != null)
                    //{

                    //    Console.WriteLine(line.ToString());



                    //}


                    Console.WriteLine("Test1111");
                }


            }
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


            var content = new FormUrlEncodedContent(form);
            content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);

            string s = _aesClientCertId.ToString();
            string a = signature;
            var postResult = _httpClient.PostAsync(url, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
           

         

            if (i == 1)
            {

                using (StreamWriter writer = new StreamWriter("post1-1.txt"))
                   


                {
                    //writer.WriteLine("");

                    //  writer.WriteLine(content.Headers);

                    writer.WriteLine(s);

                }

                using (StreamWriter writer = new StreamWriter("post1-2.txt"))


                {
                    //writer.WriteLine("");

                    // writer.WriteLine(content.Headers);

                    writer.WriteLine(a);

                }

            }
          

            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            string resultSignature = headerSignature.Value?.FirstOrDefault();
            //Console.WriteLine("X-iCP-S3");
            //Console.WriteLine(resultSignature);

            _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }

            JToken jToken = JToken.Parse(stringResult);
            if (jToken["RtnCode"].Value<int>() != 1)
            {
                throw new Exception(jToken["RtnMsg"].Value<string>());
            }

            decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());
            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }

        [TestMethod]


        public void GetCellphone()
        {
            for (i = 1; i <= 1; i++)
            {
                generateAES();
                 //string url = "/api/member/MemberInfo/getCellphone";
             // string url = "/api/Member/MemberInfo/UserCodeLogin";
            // string url = "/api/Member/MemberInfo/SetRegisterInfo";
            //  string url = "/api/Member/MemberInfo/SendAuthSMS";
            // string url = "/api/Member/MemberInfo/CheckRegisterAuthSMS";

            // string url = "/api/Member/Payment/CreateBarcode";

           // string url ="/app/certificate/bindMerchantCert";
                string url = "/api/notification";


                if (i == 1)


                { 
              

                    var request1 = new
                    {
                        to = "10000290",
                        actionID = "102",
                        data =""

                        //Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                        // MerchantID = "10000290",
                        // Token = "BA7FB0E96D02427C86C7D8480587AEB8"
                        // PaymentType = "1" ,
                        //  PayID ="1"
                       // LoginTokenID = "8DF577C23C5049EA882840FD64D0622D",

                        //  AuthV = "62DEEED78C9F448080DB4307AF6CF4A1",

                        // AuthV = "20888234523452F54235423B54235545",
                        //  AuthV = "69D1076AD6E948ECAE7678DE156756D6",

                        //CellPhone = "0915093833",
                        //AuthCode = "111111"
                        //UserCode = "adan20888",
                        //UserPwd = "Aa1234"
                        // SMSAuthType = "1"
                    };
                    string decryptContent1 = null;
                    string response1 = callNormalApi(url, request1, ref decryptContent1);
                    //string test = _rsaCryptoHelper.Decrypt(response);
                    //Console.WriteLine(test);

                    using (StreamWriter writer = new StreamWriter("important1.txt"))
                    {
                        writer.WriteLine(response1);

                        //     //   writer.WriteLine(test);
                    }



                        }


                //Console.WriteLine("second result==================================================");
                //Console.WriteLine(response);



                //if (i == 2)


                //{

                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "98BE5F7839D04BF28C0B2EC753348DE0",
                //       // AuthV = "115C5234523452F54235423B54235545"
                //        // CellPhone = "0916092609",
                //        //AuthCode = "806099"
                //        UserCode = "johnny002",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important2.txt"))
                //    {
                //        writer.WriteLine(response1);
                     

                //    }
                //}



                //if (i == 3)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //        LoginTokenID = "410681D33A40471EA93BD7F63C96DC0A",
                //        //AuthV = "120C5234523452F54235423B54235545"
                //        //CellPhone = "0916100856",
                //        //AuthCode = "806099"
                //        UserCode = "johnny003",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important3.txt"))
                //    {
                //        writer.WriteLine(response1);


                //    }
                //}


                //if (i == 4)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "378C8A8C4F424FDD9E448FD56E58D591",
                //        // AuthV = "125C5234523452F54235423B54235545"
                //        // CellPhone = "0916103058",
                //        //AuthCode = "806099"
                //        UserCode = "johnny004",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important4.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}


                //if (i == 5)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "C9B33FD1703648A89AE1B5AFAF5C1531",
                //        //AuthV = "130C5234523452F54235423B54235545"
                //        // CellPhone = "0916104936",
                //        //AuthCode = "806099"
                //        UserCode = "johnny005",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important5.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}



                //if (i == 6)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //        LoginTokenID = "A485A8B2BD884E0ABEABB4919907DEFB",
                //        // AuthV = "135C5234523452F54235423B54235545"
                //        // CellPhone = "0917102141",
                //        //AuthCode = "806099"
                //        UserCode = "johnny006",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important6.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}


                //if (i == 7)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "E704864FEE1C461E8E918BEC0479918F",
                //        // AuthV = "140C5234523452F54235423B54235545"
                //        // CellPhone = "0917104305",
                //        //AuthCode = "806099"
                //        UserCode = "johnny007",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important7.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}


                //if (i == 8)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "150DCA9A0FD847C39DC41758682249D7",
                //        //AuthV = "145C5234523452F54235423B54235545"
                //        //CellPhone = "0917142611",
                //        //AuthCode = "806099"
                //        UserCode = "johnny008",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important8.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}


                //if (i == 9)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "8220612EDDAD4BEEAB310E275FF9CA98",
                //       // AuthV = "155C5234523452F54235423B54235545"
                //        // CellPhone = "0922155513",
                //        //AuthCode = "806099"
                //        UserCode = "johnny010",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important10.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                //if (i == 10)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "18F8F4FAE55F4711A89131F86E1A5C15",
                //        //AuthV = "160C5234523452F54235423B54235545"
                //        // CellPhone = "0922171058",
                //        //AuthCode = "806099"
                //        UserCode = "johnny011",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important11.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                //if (i == 11)

                //{
                //    var request1 = new
                //    {
                //         Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "8BEA67F176F54E7D8E7F64575C022619",
                //       // AuthV = "102C5234523452F54235423B54235545",
                //          CellPhone = "0928102323",
                //         AuthCode = "193973"
                //        // UserCode = "adan101",
                //        //UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important12.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                //if (i == 12)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "E704A827102D4B66BDE75E4BFDA3CA90",
                //       // AuthV = "112C5234523452F54235423B54235545",
                //          CellPhone = "0928110646",
                //         AuthCode = "170496"
                //        //  UserCode = "adan002",
                //        // UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important13.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                //if (i == 13)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "D65978984FAE4E57BE63712B6D84FF93",
                //        //AuthV = "122C5234523452F54235423B54235545",
                //          CellPhone = "0928110650",
                //        AuthCode = "126378"
                //        // UserCode = "adan003",
                //        //UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important14.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                //if (i == 14)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //        LoginTokenID = "D75204B92D94444A9C44E3C1023768EA",
                //        // AuthV = "132C5234523452F54235423B54235545",
                //        CellPhone = "0928110651",
                //         AuthCode = "755166"
                //        // UserCode = "adan004",
                //        //UserPwd = "Aa1234"
                //       // SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important15.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                //if (i == 15)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //        LoginTokenID = "8618BDB33A164DBDA0EB2581FD009641",
                //        // AuthV = "142C5234523452F54235423B54235545",
                //        CellPhone = "0928110654",
                //         AuthCode = "723404"
                //        // UserCode = "adan005",
                //        //UserPwd = "Aa1234"
                //       // SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important16.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                //if (i == 16)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //        LoginTokenID = "FF28413506354AB2BDB107A0215BAFC0",
                //        // AuthV = "152C5234523452F54235423B54235545",
                //        CellPhone = "0928110655",
                //        AuthCode = "357443"
                //        // UserCode = "adan006",
                //        //UserPwd = "Aa1234"
                //       // SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important17.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                //if (i == 17)

                //{
                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //        LoginTokenID = "47441190678C4D0F80DCA5FE420D4614",
                //        // AuthV = "162C5234523452F54235423B54235545",
                //        CellPhone = "0928110658",
                //         AuthCode = "857401"
                //        // UserCode = "adan007",
                //        //UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important18.txt"))
                //    {
                //        writer.WriteLine(response1);

                //    }
                //}

                ////if (i == 18)

                ////{
                ////    var request1 = new
                ////    {
                ////        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                ////        LoginTokenID = "C79FBAC6010B432E83D8C4A531573AC1",
                ////        //uthV = "172C5234523452F54235423B54235545"
                ////        CellPhone = "0928110701",
                ////        //AuthCode = "686745"
                ////        // UserCode = "adan008",
                ////        // UserPwd = "Aa1234"
                ////        SMSAuthType = "1"
                ////    };
                ////    string decryptContent1 = null;
                ////    string response1 = callNormalApi(url, request1, ref decryptContent1);
                ////    using (StreamWriter writer = new StreamWriter("important19.txt"))
                ////    {
                ////        writer.WriteLine(response1);

                ////    }
                ////}

                ////if (i == 19)

                ////{
                ////    var request1 = new
                ////    {
                ////        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                ////        LoginTokenID = "D32DDA730E5F484FB22749F65D79E298",
                ////       //uthV = "182C5234523452F54235423B54235545"
                ////        CellPhone = "0928110703",
                ////        // AuthCode = "232428"
                ////        // UserCode = "adan009",
                ////        // UserPwd = "Aa1234"
                ////        SMSAuthType = "1"
                ////    };
                ////    string decryptContent1 = null;
                ////    string response1 = callNormalApi(url, request1, ref decryptContent1);
                ////    using (StreamWriter writer = new StreamWriter("important20.txt"))
                ////    {
                ////        writer.WriteLine(response1);

                ////    }
                ////}

                ////if (i == 20)

                ////{
                ////    var request1 = new
                ////    {
                ////        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                ////        LoginTokenID = "368465CF9CA540E3ABA0080DF9D4F14F",
                ////        // AuthV = "192C5234523452F54235423B54235545"
                ////        CellPhone = "0928110707",
                ////        //  AuthCode = "204942"
                ////       //  UserCode = "adan010",
                ////       //  UserPwd = "Aa1234"
                ////        SMSAuthType = "1"
                ////    };
                ////    string decryptContent1 = null;
                ////    string response1 = callNormalApi(url, request1, ref decryptContent1);
                ////    using (StreamWriter writer = new StreamWriter("important21.txt"))
                ////    {
                ////        writer.WriteLine(response1);

                ////    }
                ////}


                //Console.WriteLine("third result===================================================");
                //Console.WriteLine(response1);

















            }


        }


        }




    }

