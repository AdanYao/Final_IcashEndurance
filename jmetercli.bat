@ECHO OFF

cd "\apache-jmeter-5.1.1\bin\"

jmeter -n -t C:\Final_IcashEndurance\�}��\Endurance\Step2�|���n�J���O����.jmx -R 172.16.137.143:1099,172.16.137.142:1099 -l result.csv  -e -o C:\icash2\0822\loginreport 

ECHO finish



