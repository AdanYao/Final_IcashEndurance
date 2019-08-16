<title>加解密範例</title>
<form method="post">
KEY:<br>
<input type="text" name="key"><br>
IV:<br>
<input type="text" name="iv"><br>
Data:<br>
<input type="text" name="data"><br>
<input type="submit" name="decode" id="decode" value="	解密		" />
<input type="submit" name="encode" id="encode" value="	加密		" /><br/>
</form>

<?php
if(array_key_exists('encode',$_POST)){

   encode();
}


function encode()
{
echo '送出資料<br>';
$key= $_POST["key"];
$iv=$_POST["iv"];
$data=$_POST["data"];
echo "Key: ".$key.'<br>';
echo "IV: ".$iv.'<br>';
echo "Data: ".$data.'<br>';
$encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
echo '<br>';
echo "加密結果:<br>";
echo(base64_encode($encrypted));
echo '<br>';

}

if(array_key_exists('decode',$_POST)){

   decode();
}
function decode()
{
echo '送出資料<br>';
$key= $_POST["key"];
$iv=$_POST["iv"];
$data=$_POST["data"];
echo "Key: ".$key.'<br>';
echo "IV: ".$iv.'<br>';
echo "Data: ".$data.'<br>';
$encryptedData = base64_decode($data);
$decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $encryptedData, MCRYPT_MODE_CBC, $iv);
$decrypted1=urldecode($decrypted);
//echo($decrypted);
echo ('<br>');
echo "解密結果:<br>";
echo($decrypted1);


}
?>
