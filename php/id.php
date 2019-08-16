<?php
#
# 台灣身份字號產生器
# 小學生 scriptmarks.com
# 此程式僅做為教學基礎使用,以最簡單易懂的模式依照身份證字號公式撰寫
#
//預設函數 性別男(sex=1),出生地台北(A),產生筆數5筆(num=5)
function idmake($sex='1',$area='A',$num='100'){
	if(!preg_match("/^[1-9]\d*$/",$num)){$num ='5';}//驗證 $num 是否為正整數
		elseif($num > '1000'){$num = '1000';}//最大筆數限制
	$xi=0;$xj=0;$idarr=array();
	if($area ==''){$rand_c='1';}else{$rand_c='0';}//判斷一開始的地區值,產生英文字母亂數使用
	//筆數迴圈
	while($xi < $num){
		$nx='';$ns='';$chk_id='';$id='';
		if($rand_c =='1'){ $area ='';}//以此控制下面的英文字母"亂數"真的很亂....
	//先判斷要產生的性別是男或女或是不分男女
	if($sex =='1'){$mkid = mt_rand(10000000,19999990);//男生
					}elseif($sex == '2'){
						$mkid = mt_rand(20000000,29999990);//女生
					}else{
						$mkid = mt_rand(10000000,29999990);//隨機性別
					}
					
	//先將字母數字存成陣列
	$alphabet =['A'=>'10','B'=>'11','C'=>'12','D'=>'13','E'=>'14','F'=>'15','G'=>'16','H'=>'17','I'=>'34',
				'J'=>'18','K'=>'19','L'=>'20','M'=>'21','N'=>'22','O'=>'35','P'=>'23','Q'=>'24','R'=>'25',
				'S'=>'26','T'=>'27','U'=>'28','V'=>'29','W'=>'32','X'=>'30','Y'=>'31','Z'=>'33'];
	if(!preg_match("/[A-Za-z]/",$area)){
		//如果預設字母不是A-Z的英文字母,取得隨機字母分數
		$area = chr(mt_rand(65,90));
	}
	//把字母轉大寫
	$area = strtoupper($area);
	//把英文與數字合成一身份證前 9 碼 (包括1英文字及8位數字)
	$chk_id = $area.$mkid;
	 
	//計算英文數字和
	$nx = $alphabet[$area];
		$ns = $nx[0]+$nx[1]*9;//十位數+個位數x9
	
	//N2x8+N3x7+N4x6+N5x5+N6x4+N7x3+N8x2+N9+N10
	$i = 8;$j = 1;$ms =0;
	//先算 N2x8 + N3x7 + N4x6 + N5x5 + N6x4 + N7x3 + N8x2
	while($i >= 2){
		$mx = substr($chk_id,$j,1);//由第j筆每次取一個數字
		$my = $mx * $i;//N*$i
		$ms = $ms + $my;//ms為加總
		$j+=1;
		$i--;
	}
	$ms = $ms + substr($chk_id,8,1);//前八碼數據加總的和
	$ms = $ms + $ns;//再把前八碼加上英文數據的總和
	//ms為已求出的數據 但最後一碼未求出,而又因為要被 10 整除 , 所以我們可先求出餘數後,在用10減去餘數,得到最後一碼的數據
	$remainder = $ms%10;//此為餘數
	if($remainder !='0'){
		$last_num = 10 - $remainder;//這是最後一碼的數字
	}else{
		$last_num ='0';
	}
	
	$id = $chk_id.$last_num;//把前面9碼加上最後碼取得身份字號
	//把產生的 id 丟進陣列,有重複值則捨棄,再跑一次迴圈
	if(!in_array($id,$idarr)){
		$idarr[$xj] = $id;//若此id沒在陣列中,存進陣列
		//echo $idarr[$xj].'<br />';
		$xj++;
		$xi++;
	}else{
		$xi = $xj;//如果取到重複內容,則迴圈的數據給他跳到不重複數的值
	}
	
	}
	//排序陣列
	sort($idarr);
	//印出陣列內容
	foreach($idarr as $value){echo $value .'<br />';}
	
}

idmake();
?>