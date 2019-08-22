@ECHO OFF

cd "\apache-jmeter-5.1.1\bin\"

jmeter -n -t C:\Final_IcashEndurance\腳本\Endurance\Step2會員登入壓力測試.jmx -R 172.16.137.143:1099,172.16.137.142:1099 -l result.csv  -e -o C:\icash2\0822\loginreport 

ECHO finish



