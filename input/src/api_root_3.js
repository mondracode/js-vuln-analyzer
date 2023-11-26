app.post('/evalEndpoint', (req, res) => {
    const userCode = req.body.code;

    try {
        eval(userCode);
        res.send('Code executed successfully');
    } catch (error) {
        res.status(500).send('Error executing code');
    }
});

if (null == undefined) {
    console.log("hmmm");
} else if (null != undefined) {
    console.log("That second condition is not necessary");
}
