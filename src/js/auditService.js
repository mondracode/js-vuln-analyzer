const fs = require('fs');
const fetch = require('node-fetch');

const packageJsonPath = './input/package.json';
const packageJsonContent = fs.readFileSync(packageJsonPath, 'utf8');
const packageJson = JSON.parse(packageJsonContent);

const requestBody = {
    name: packageJson.name,
    version: packageJson.version,
    dependencies: {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
    },
};

const options = {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'insomnia/8.4.4',
    },
    body: JSON.stringify(requestBody),
};

fetch('https://registry.npmjs.org/-/npm/v1/security/audits', options)
    .then(response => response.json())
    .then(response => {
        // Manejar los reportes de seguridad
        console.log('Security Reports:', response);
    })
    .catch(err => console.error(err));
