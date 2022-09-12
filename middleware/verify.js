const jwt = require("jsonwebtoken");

const config = process.env;

const verifyUser = (req, res, next) => {
    const token =
        req.body.token || req.query.token || req.headers["x-access-token"];

    const {id} = req.params;

    if (!token) {
        return res.status(403).send("A token is required for authentication");
    }

    try {
        const decoded = jwt.verify(token, config.TOKEN_KEY);
        req.user = decoded;

        console.log(decoded);
        console.log(id);

        if (decoded.user_id != id) {
            return res.status(403).send("Wrong user credentials");
        }
    } catch (err) {
        return res.status(401).send("Invalid Token");
    }

    return next();
};

module.exports = verifyUser;