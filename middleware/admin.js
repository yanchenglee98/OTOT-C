const jwt = require("jsonwebtoken");

const config = process.env;

const verify = (roles) => {
    return (req, res, next) => {
        const token =
            req.body.token || req.query.token || req.headers["x-access-token"];

        if (!token) {
            return res.status(401).send("A token is required for authentication");
        }

        try {
            const decoded = jwt.verify(token, config.TOKEN_KEY);
            req.user = decoded;
            console.log(decoded);
            if (!roles.includes(decoded.role)) {
                console.log(decoded.role);
                return res.status(403).send("You do not have admin privileges");
            }
        } catch (err) {
            return res.status(401).send("Invalid Token");
        }

        return next();
    };
}

module.exports = verify;