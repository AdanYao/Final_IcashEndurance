@ECHO OFF

cd "\jmeter\apache-jmeter-5.1.1\apache-jmeter-5.1.1\bin"

jmeter -n -t 0606壓力測試計畫.jmx -l result.jtl -e -o C:\Users\adan.yao\Desktop\icash2\0606\report



ECHO finish


