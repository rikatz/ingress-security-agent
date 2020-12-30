git clone git@github.com:coreruleset/coreruleset.git
mkdir conf
wget -c https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended -O - |sed 's/SecRuleEngine.*/SecRuleEngine On/' > conf/modsecurity.conf
wget -c https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/unicode.mapping -O conf/unicode.mapping
echo "Include crs-setup.conf" >> conf/modsecurity.conf
echo "Include RE*.conf" >> conf/modsecurity.conf
#for a in $(ls coreruleset/rules); do
#    grep -Ev "^#|^$" coreruleset/rules/$a > conf/$a;
#done
cp coreruleset/rules/* conf/
cp crs-setup.conf conf/
rm -rf coreruleset
