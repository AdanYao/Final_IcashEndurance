@ECHO OFF

cd "\jmeter\apache-jmeter-5.1.1\apache-jmeter-5.1.1\bin"

jmeter -n -t C:\Final_IcashEndurance\腳本\Endurance\Step2會員登入壓力測試.jmx -l result.jtl -e -o C:\icash2\0812\loginreport


ECHO finish


