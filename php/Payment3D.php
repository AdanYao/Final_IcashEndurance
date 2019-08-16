<?php

/*信用卡幕後授權3D*/


//介接資訊
$oService = new NetworkService();	// // 初始化網路服務物件。
$oService->ServiceURL = 'https://ecpayment-stage.ecpay.com.tw/1.0.0/Cashier/BackAuth';
$szHashKey = 'pwFHCqoQZGmho4w6';
$szHashIV = 'EkRm7iFT261dpevs';

/*************************************POST參數設置************************************************************/
$szPlatformID = '';
$szMerchantID = '3002607';

/*************************************產生GUID****************************************************************/
function guid(){
    mt_srand((double)microtime()*10000);//optional for php 4.2.0 and up.
    $charid = strtoupper(md5(uniqid(rand(), true)));
    $uuid = substr($charid, 0, 8)
        .substr($charid, 8, 4)
        .substr($charid,12, 4)
        .substr($charid,16, 4)
        .substr($charid,20,12);
    return $uuid;
}

/*************************************要傳遞的 Data 參數******************************************************/
$szData = '';
$arData = array();
$szCheckMacValue = '';
$arParameters = array();
$arFeedback = array();
$Timestamp=time();
$szRqHeader=array();
$RqID= guid();
$Reversion='1.0.0';


date_default_timezone_set("Asia/Taipei");

$szRqHeader=array(
'Timestamp' => $Timestamp,
'RqID' => $RqID,
'Reversion' => $Reversion,
);
$arData = array(
  'TimeStamp'=>date('y/m/d H:m:s'),
  'AuthV'=>'115C5234523452F54235423B54235545',
  'LoginTokenID'=>'437764053D414BF199199EEFDB794452'
);
/******************************************************************************************************************************************/

//轉Json格式
$szData = json_encode($arData);

//做urlencode
$szData = urlencode($szData);
	
//AES
$oCrypter = new AESCrypter($szHashKey, $szHashIV);
	
// 加密 Data 參數內容
$szData = $oCrypter->Encrypt($szData);

echo $szData;
//要POST的參數
$arParameters = array(
	'MerchantID' => $szMerchantID,
	'RqHeader' => $szRqHeader,
	'Data' => $szData
);

//轉Json格式
$arParameters = json_encode($arParameters);

// 傳遞參數至遠端。
$szResult = $oService->ServerPost($arParameters);

//將Data解密並取出3D驗證網址
//$DataDec = $oCrypter->Decrypt($szResult);

//$oURL = new ToURL();

//將網頁跳轉至3D驗證
//$url = $oURL->To3DURL($DataDec);

/************************************服務類別*************************************************/

/**
 * 呼叫網路服務的類別。
 */
class NetworkService {

    /**
     * 網路服務類別呼叫的位址。
     */
    public $ServiceURL = 'ServiceURL';

    /**
     * 網路服務類別的建構式。
     */
    function __construct() {
        $this->NetworkService();
    }
    
    /**
     * 網路服務類別的實體。
     */
    function NetworkService() {

    }

    /**
     * 提供伺服器端呼叫遠端伺服器 Web API 的方法。
     */
    function ServerPost($parameters) {
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, $this->ServiceURL);
        curl_setopt($ch, CURLOPT_HEADER, FALSE);
        //curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13');

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_POST, TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $parameters);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json; charset=utf-8', 'Content-Length: ' . strlen($parameters)));
        $rs = curl_exec($ch);

        curl_close($ch);

        return $rs;
		
    }
	
}

/**
 * AES 加解密服務的類別。
 */
class AesCrypter {

    private $Key = 'MfmpCVjBBsnFcGLyRmSoJjxJiXSbYdaf';
    private $IV = 'IK4NLSEGe21lQwTu';

    /**
     * AES 加解密服務類別的建構式。
     */
    function __construct($key, $iv) {
        $this->AesCrypter($key, $iv);
    }

    /**
     * AES 加解密服務類別的實體。
     */
    function AesCrypter($key, $iv) {
        $this->Key = $key;
        $this->IV = $iv;
    }

    /**
     * 加密服務的方法。
     */
    function Encrypt($data)
    {
        $szBlockSize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $szPad = $szBlockSize - (strlen($data) % $szBlockSize);
        $szData = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->Key, $data. str_repeat(chr($szPad), $szPad), MCRYPT_MODE_CBC, $this->IV);
        $szData = base64_encode($szData);

        return $szData;
    }
	
    /**
     * 解密服務的方法。
     */
    function Decrypt($data)
    {
		$data=mb_split('","TransCode',mb_split('Data":"',$data)[1])[0];
		$encryptedData = base64_decode($data);
		$decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->Key, $encryptedData, MCRYPT_MODE_CBC, $this->IV);
		$decrypted=urldecode($decrypted);
		$THREEDURL=mb_split('","MerchantID',mb_split('"ThreeDURL":"',$decrypted)[1])[0];
		
        return $THREEDURL;
    }
}

/**
 * 網頁跳轉的類別。
 */
class ToURL {
	
	/**
     * 網頁跳轉類別的建構式。
     */
	function __construct() {
        $this->ToURL();
    }
	
	 
    /**
     * 網頁跳轉類別的實體。
     */
    function ToURL() {

    }
    /**
     * 跳轉至3D頁面的方法。
     */
    function To3DURL($data) {
        echo " <script   language = 'javascript'  
		type = 'text/javascript'> ";  
		echo " window.location.href = '$data' ";  
		echo " </script > ";  
	}
}

?>