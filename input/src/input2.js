var encryptedData = CryptoJS.DES.encrypt("data", "key");
console.log(encryptedData);

var userInputHash = md5(userInput);
if (userInputHash == "5f4dcc3b5aa765d61d8327deb882cf99") {
    console.log("Inseguro: comparación de hash insegura");
}

app.get('/xss', (req, res) => {
    const userProvidedInput = req.query.input;

    res.send(`<p>${userProvidedInput}</p>`);
});

const plainTextPassword = "password123";

const username = process.env.DB_USERNAME;
const password = process.env.DB_PASSWORD;

const apiKey = "your_api_key_here";


app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username === 'admin' && password === 'password123') {
        req.session.user = { username: 'admin' };
        res.send('Login successful');
    } else {
        res.status(401).send('Invalid credentials');
    }
});

app.get('/dashboard', (req, res) => {
    if (req.session.user) {
        res.send('Welcome to the dashboard, ' + req.session.user.username);
    } else {
        res.status(401).send('Unauthorized. Please log in.');
    }
});
