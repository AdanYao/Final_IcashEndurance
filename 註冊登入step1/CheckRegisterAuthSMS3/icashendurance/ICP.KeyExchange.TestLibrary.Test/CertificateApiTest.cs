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
        int i = 0;

        string post;

        private readonly HttpClient _httpClient = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")
              BaseAddress = new Uri("http://icp-member-beta.ecpay.com.tw/")
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
           


            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
           
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);

            var content = new FormUrlEncodedContent(form);
            content.Headers.Add(certHeaderName, certId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
         
            var postResult = _httpClient.PostAsync(action, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;



           


            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            string resultSignature = headerSignature.Value?.FirstOrDefault();

          
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
            

            var generateAesResult = JsonConvert.DeserializeObject<GenerateAesResult>(json);

            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.Result.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);

          
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
           

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
         

            string s = _aesClientCertId.ToString();
           
            string a = signature;
           
            post = post + s + ',' + a + ',' + encData + '\n';

            

           using (StreamWriter writer = new StreamWriter("CheckRegisterAuthSMS2.txt"))
        



            {
              

                writer.WriteLine(post);

            }



           


           

           

           

           
          
          
           
            Console.WriteLine("X-iCP-123");
            return post;
          
        

        }

        [TestMethod]



        public void GetCellphone()
        {

            int ta = 0;
           

                ////設定讀取的Excel屬性
                string strCon = "Provider=Microsoft.Jet.OLEDB.4.0;" +

                //路徑(檔案讀取路徑)
                "Data Source=C:\\Test09Y30.xls;" +

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
                          // string url = "/api/Member/MemberInfo/UserCodeLogin";
                          // string url = "/api/Member/MemberInfo/SetRegisterInfo";
                           // string url = "/api/Member/MemberInfo/SendAuthSMS";
                           string url = "/api/Member/MemberInfo/CheckRegisterAuthSMS";
                        //工作表SheetA的資料存入List

                        //{Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

                        //    string AA =Convert.ToString(unixTimestamp);

                        //    string A1= "1000000000"+00001;

                        ListSheetA.Add(drSheetA[0].ToString());
                        ListSheetA.Add(drSheetA[1].ToString());
                        ListSheetA.Add(drSheetA[2].ToString());
                        ListSheetA.Add(drSheetA[3].ToString());
                        ListSheetA.Add(drSheetA[4].ToString());
                        var request1 = new
                            {
                                 Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                                //Timestamp = DateTime.Now.ToString("2019/07/22 17:30:00"),
                                LoginTokenID = ListSheetA[2],
                            // LoginTokenID = "B7EE967048284D9BB44315295F3C657D",

                              // AuthV = ListSheetA[0],
                            
                               CellPhone = ListSheetA[1],
                               AuthCode = "111111"
                            //UserCode = ListSheetA[3],
                            //UserPwd = "Aa1234"

                           // SMSAuthType = "1"
                        };
                            string decryptContent1 = null;
                            string response1 = callNormalApi(url, request1, ref decryptContent1);
                            using (StreamWriter writer = new StreamWriter("CheckRegisterAuthSMS.txt"))
                            {
                                writer.WriteLine(response1);

                            }

                          



                        
                            //ListSheetA.Add(drSheetA[0].ToString());
                            //ListSheetA.Add(drSheetA[1].ToString());
                            //ListSheetA.Add(drSheetA[2].ToString());
                            //ListSheetA.Add(drSheetA[3].ToString());
                            //ListSheetA.Add(drSheetA[4].ToString());
                            // Console.WriteLine(ListSheetA[0]+" "+ListSheetA[1]+" "+ ListSheetA[2]+" "+ ListSheetA[3]+" "+ ListSheetA[4]);
                            using (StreamWriter writer = new StreamWriter("end.txt"))
                            {
                                writer.WriteLine(ListSheetA[0] + " " + "0" + ListSheetA[1] + " " + ListSheetA[2] + " " + ListSheetA[3] + " " + ListSheetA[4]);

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
               


            }




        }




    

}

