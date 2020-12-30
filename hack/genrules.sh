git clone https://github.com/coreruleset/coreruleset.git
mkdir rules
wget -c https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended -O - |sed 's/SecRuleEngine.*/SecRuleEngine On/' > rules/modsecurity.conf
sed -i 's/^SecAuditLog .*/SecAuditLog \/dev\/stdout/' rules/modsecurity.conf
echo "SecAuditLogFormat json" >> rules/modsecurity.conf
echo "Include crs-setup.conf" >> rules/modsecurity.conf
echo "Include RE*.conf" >> rules/modsecurity.conf
wget -c https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/unicode.mapping -O rules/unicode.mapping
cp coreruleset/rules/* rules/
cp hack/crs-setup.conf rules/
rm -rf coreruleset
