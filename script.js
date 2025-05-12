const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");

const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

async function getDBConnnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "anvandare",
  });
}

function checkToken(req, res) {
  let authHeader = req.headers["authorization"];
  if (authHeader === undefined) {
  }
  let token = authHeader.slice(7);
  let decoded;
  try {
    decoded = jwt.verify(token, "ketchup");
    return decoded;
  } catch (err) {
    console.log(err);
    res.status(401).send("Invalid auth token");
  }
}

app.get("/", (req, res) => {
  res.send(`<h1>Doumentation EXEMPEL</h1>
  <ul><li> GET /users: Listar alla users</li><li>GET /users/:id: Listar usern med det angivna id:t; kräver giltig token</li><li>POST /users: skapar en ny user; kräver giltig token</li><li>PUT /users: uppdaterar namn och lösenord för en user; kräver giltig token</li><li>POST /login - checkar användarnamn och lösenord</li></ul>`);
});

app.get("/users", async (req, res) => {
  let connection = await getDBConnnection();
  decoded = checkToken(req, res);
  if (decoded) {
    let sql = "SELECT * FROM users";

    let [results] = await connection.execute(sql);
    let users = results;
    users.forEach((user) => {
      delete user.password;
    });
    res.json(users);
  }
});

app.get("/users/:id", async (req, res) => {
  decoded = checkToken(req, res);
  if (decoded) {
    let connection = await getDBConnnection();
    let sql = `SELECT * FROM users WHERE id = ?`;
    let [results] = await connection.execute(sql, [req.params.id]);
    res.json(results);
  } else {
    res.status(401).send("Invalid auth token");
  }
});

app.post("/users", async function (req, res) {
  decoded = checkToken(req, res);
  if (decoded) {
    if (
      req.body &&
      typeof req.body.username == "string" &&
      req.body.name &&
      req.body.password
    ) {
      let user = req.body;
      let connection = await getDBConnnection();
      let sql = `INSERT INTO users (username, name, password) VALUES (?,?,?)`;

      const salt = await bcrypt.genSalt(10); // genererar ett salt till hashning
      const hashedPassword = await bcrypt.hash(req.body.password, salt); //hashar lösenordet

      let [results] = await connection.execute(sql, [
        req.body.username,
        req.body.name,
        hashedPassword,
      ]);
      user.id = results.insertId;
      delete user.password;
      res.json(user);
    } else {
      res.sendStatus(422);
    }
  } else {
    res.status(401).send("Invalid auth token");
  }
});

app.put("/users/:id", async (req, res) => {
  decoded = checkToken(req, res);
  if (decoded) {
    let connection = await getDBConnnection();
    if (connection) {
      let sql = `UPDATE users SET name =?, password=? WHERE id=?`;

      const salt = await bcrypt.genSalt(10); // genererar ett salt till hashning
      const hashedPassword = await bcrypt.hash(req.body.password, salt); //hashar lösenordet

      let [results] = await connection.execute(sql, [
        req.body.name,
        hashedPassword,
        req.params.id,
      ]);
      if (results.affectedRows > 0) {
        res.status(200).json(results);
      } else {
        res.status(400).send("Det finns ingenting att hämta");
      }
    } else {
      res.sendStatus(500);
    }
  } else {
    res.status(401).send("Invalid auth token");
  }
});

app.post("/login", async (req, res) => {
  let connection = await getDBConnnection();
  let sql = `SELECT * FROM users WHERE username = ?`;
  let [results] = await connection.execute(sql, [req.body.username]);
  if (results.length > 0) {
    const user = results[0];
    const isPasswordValid = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (isPasswordValid) {
      let payload = {
        sub: user.id,
        name: user.name,
        expiresIn: "2h",
      };
      let token = jwt.sign(payload, "ketchup");
      res.json(token).status(200);
    } else {
      res.status(401).send("Felaktigt användarnamn eller lösenord");
    }
  } else {
    res.status(401).send("Felaktigt användarnamn eller lösenord");
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
