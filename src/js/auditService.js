const options = {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'User-Agent': 'insomnia/8.4.4'},
    body: '{"name":"npm_audit_test","version":"1.0.0","requires":{"marked":"^0.6.3"},"dependencies":{"marked":{"version":"0.6.3","integrity":"sha1-ebq614r2OLpNUiqecVzf3SQp6UY=234"}}}'
};

fetch('https://registry.npmjs.org/-/npm/v1/security/audits', options)
    .then(response => response.json())
    .then(response => console.log(response))
    .catch(err => console.error(err));

console.log("Report")